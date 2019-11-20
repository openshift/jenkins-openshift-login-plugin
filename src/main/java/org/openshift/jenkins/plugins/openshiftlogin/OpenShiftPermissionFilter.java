/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2016, Red Hat, Inc., Gabe Montero
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.openshift.jenkins.plugins.openshiftlogin;

import hudson.EnvVars;
import hudson.model.User;
import hudson.security.SecurityRealm;

import static java.util.logging.Level.SEVERE;
import static org.openshift.jenkins.plugins.openshiftlogin.OAuthSession.SESSION_NAME;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.http.HttpResponseException;

import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;

/**
 * This servlet spec filter implementation serves as the hook point to
 * periodically poll OpenShift to see if the user specified by the OAuth session
 * has had a change in the permissions maintained in OpenShift (where those
 * permissions are mapped to the Jenkins permissions maintained in Jenkins'
 * AuthorizationStrategy implementation.
 *
 */
public class OpenShiftPermissionFilter implements Filter {

    private static final String LAST_SELF_SAR_POLL_TIME = "self-sar-time";
    private static final long SELF_SAR_POLL_INTERVAL = 5 * 60 * 1000; // 5
                                                                      // minutes
                                                                      // * 60
                                                                      // seconds
                                                                      // * 1000
                                                                      // milliseconds
    private static final String OPENSHIFT_PERMISSIONS_POLL_INTERVAL = "OPENSHIFT_PERMISSIONS_POLL_INTERVAL"; // doc
                                                                                                             // says
                                                                                                             // this
                                                                                                             // is
                                                                                                             // in
                                                                                                             // seconds
    private static final String OPENSHIFT_ACCESS_VIA_BEARER_TOKEN = "OPENSHIFT_ACCESS_VIA_BEARER_TOKEN";
    private static final int MAX_BEARER_CACHE_ENTRIES = 50;
    private static String NEED_TO_AUTH = "\nYou need to supply credentials that allow you to be authenticated by OpenShift OAuth as a valid user who is assigned either the view, edit, or admin roles in the OpenShift project running this Jenkins instance. \n"
            + "If operating from a browser, provide your user credentials when solicited by the OpenShift login page.  Otherwise, supply as a part of any HTTP requests you generate a HTTP Authorization Bearer header\n"
            + "containing a token that correlates to your user credentials.\n";

    /*
     * the Jenkins crazy use of constructors vs. introspection / field setting means
     * that after initial bringup, but following subsequent Jenkins restarts, we
     * have to re-add our filter to the dynamic filter list Jenkins provides. We use
     * this flag to track that (as init will be called when we add the filter); mark
     * as transient so this is not persisted across restarts
     */
    transient boolean initCalled = false;

    static class BearerCacheEntry {
        long lastCheck;
        UsernamePasswordAuthenticationToken token;
    }

    transient LinkedHashMap<String, BearerCacheEntry> bearerCache = new LinkedHashMap<String, BearerCacheEntry>(
            MAX_BEARER_CACHE_ENTRIES) {

        @Override
        protected boolean removeEldestEntry(
                Entry<String, BearerCacheEntry> eldest) {
            return size() > MAX_BEARER_CACHE_ENTRIES;
        }

    };

    public OpenShiftPermissionFilter() {
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        initCalled = true;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        try {
            boolean updated = OpenShiftSetOAuth.setOauth(false);
            final HttpServletRequest httpRequest = (HttpServletRequest) request;
            long interval = SELF_SAR_POLL_INTERVAL;
            String var = EnvVars.masterEnvVars
                    .get(OPENSHIFT_PERMISSIONS_POLL_INTERVAL);
            if (var != null) {
                try {
                    interval = Long.parseLong(var);
                } catch (Throwable t) {

                }
            }
            HttpSession s = httpRequest.getSession(false);
            if (s != null) {

                OAuthSession oauth = (OAuthSession) s
                        .getAttribute(SESSION_NAME);
                if (oauth != null && oauth.getCredential() != null) {
                    try {
                        Long lastPermissionPoll = (Long) s.getAttribute(SESSION_NAME + LAST_SELF_SAR_POLL_TIME);
                        if (lastPermissionPoll == null) {
                            lastPermissionPoll = System.currentTimeMillis();
                            s.setAttribute(SESSION_NAME + LAST_SELF_SAR_POLL_TIME, System.currentTimeMillis());
                        }

                        if (updated
                                || (System.currentTimeMillis() - lastPermissionPoll.longValue() > (interval * 1000))) {
                            OpenShiftOAuth2SecurityRealm secRealm = (OpenShiftOAuth2SecurityRealm) Jenkins.getInstance().getSecurityRealm();
                            secRealm.updateAuthorizationStrategy(oauth.getCredential());
                            s.setAttribute(SESSION_NAME + LAST_SELF_SAR_POLL_TIME, System.currentTimeMillis());
                        }
                    } catch (Throwable t) {
                        OpenShiftOAuth2SecurityRealm.LOGGER.log(SEVERE, "filter", t);
                    }
                }
            } else if (Jenkins.getInstance().getSecurityRealm() instanceof OpenShiftOAuth2SecurityRealm) {
                // support for non-browser, like curl, access to jenkins with
                // openshift oauth security;
                // by choice, not storing auth in http session (remember, no
                // browser) or anything like that;
                // want the token provided on each access
                try {
                    String enabled = EnvVars.masterEnvVars
                            .get(OPENSHIFT_ACCESS_VIA_BEARER_TOKEN);
                    if (enabled == null || !enabled.equalsIgnoreCase("false")) {
                        String authHdr = httpRequest.getHeader("Authorization");
                        if (authHdr != null && authHdr.length() > 0
                                && authHdr.startsWith("Bearer")) {
                            String[] words = authHdr.split(" ");
                            if (words.length > 1) {
                                String token = words[1];

                                BearerCacheEntry entry = bearerCache.get(token);
                                boolean firstTime = false;
                                if (entry == null) {
                                    entry = new BearerCacheEntry();
                                    bearerCache.put(token, entry);
                                    entry.lastCheck = 0;
                                    // we check for first time in case system time is say reset to 1970
                                    // (perhaps we are in a VM that just spun up and the time has not been set)
                                    // we are not going to bother finding a negative number big enough to ensure 
                                    // we are greater than interval * 100 in this case
                                    firstTime = true;
                                }
                                if (updated || firstTime
                                        || System.currentTimeMillis()
                                                - entry.lastCheck > (interval * 1000)) {
                                    entry.lastCheck =  System.currentTimeMillis();
                                    final Credential credential = new Credential(
                                            BearerToken
                                                    .authorizationHeaderAccessMethod())
                                            .setAccessToken(token);
                                    OpenShiftOAuth2SecurityRealm secRealm = (OpenShiftOAuth2SecurityRealm) Jenkins
                                            .getInstance().getSecurityRealm();
                                    //REMINDER - updateAuthorizationStrategy will call SecurityContextHolder.getContext().setAuthentication
                                    UsernamePasswordAuthenticationToken jenkinsToken = secRealm
                                            .updateAuthorizationStrategy(credential);

                                    // TODO can we assume that once a token is
                                    // invalid, it is always invalid? If so, we
                                    // could put storage of the token
                                    // before the token validity check and
                                    // cached checks to invalid tokens as well;
                                    // note, if token is invalid, an
                                    // exception is thrown and we don't get to
                                    // this line
                                    entry.token = jenkinsToken;
                                } else if (entry.token != null) {
                                    SecurityContextHolder.getContext()
                                            .setAuthentication(entry.token);
                                    SecurityListener.fireAuthenticated(new OpenShiftUserDetails(entry.token.getName(), new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY }));
                                } else {
                                    HttpServletResponse httpResponse = (HttpServletResponse) response;
                                    httpResponse.sendError(401, NEED_TO_AUTH);
                                }
                            }
                        }
                    }
                } catch (HttpResponseException e) {
                    HttpServletResponse httpResponse = (HttpServletResponse) response;
                    httpResponse.sendError(e.getStatusCode(), e.getMessage()
                            + NEED_TO_AUTH);
                } catch (Throwable t) {
                    OpenShiftOAuth2SecurityRealm.LOGGER.log(Level.SEVERE,
                            "filter", t);
                }
            }

        } finally {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }

}
