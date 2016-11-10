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

import java.io.IOException;
import java.util.logging.Level;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import jenkins.model.Jenkins;

/**
 * This servlet spec filter implementation serves as the hook point to periodically
 * poll OpenShift to see if the user specified by the OAuth session has had a change 
 * in the permissions maintained in OpenShift (where those permissions are mapped 
 * to the Jenkins permissions maintained in Jenkins' AuthorizationStrategy implementation.
 *
 */
public class OpenShiftPermissionFilter implements Filter {
	
	private static final String LAST_SELF_SAR_POLL_TIME = "self-sar-time";
	private static final long SELF_SAR_POLL_INTERVAL = 5 * 60 * 1000; // 5 minutes * 60 seconds * 1000 milliseconds
	private static final String OPENSHIFT_PERMISSIONS_POLL_INTERVAL = "OPENSHIFT_PERMISSIONS_POLL_INTERVAL"; // doc says this is in seconds
	
	public OpenShiftPermissionFilter() {
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		try {
		    boolean updated = OpenShiftSetOAuth.setOauth(false);
			final HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpSession s = httpRequest.getSession(false);
			if (s != null) {
				
				OAuthSession oauth = (OAuthSession) s.getAttribute(OAuthSession.SESSION_NAME);
				if (oauth != null && oauth.getCredential() != null) {
					try {
						Long lastPermissionPoll = (Long) s.getAttribute(OAuthSession.SESSION_NAME + LAST_SELF_SAR_POLL_TIME);
						if (lastPermissionPoll == null) {
							lastPermissionPoll = new Long(System.currentTimeMillis());
							s.setAttribute(OAuthSession.SESSION_NAME + LAST_SELF_SAR_POLL_TIME, new Long(System.currentTimeMillis()));
						}
						
						long interval = SELF_SAR_POLL_INTERVAL;
						String var = EnvVars.masterEnvVars.get(OPENSHIFT_PERMISSIONS_POLL_INTERVAL);
						if (var != null) {
							try {
								interval = Long.parseLong(var);
							} catch (Throwable t) {
								
							}
						}
						if (updated || (System.currentTimeMillis() - lastPermissionPoll.longValue() > (interval * 1000))) {
							OpenShiftOAuth2SecurityRealm secRealm = (OpenShiftOAuth2SecurityRealm) Jenkins.getInstance().getSecurityRealm();
							secRealm.updateAuthorizationStrategy(oauth);
							s.setAttribute(OAuthSession.SESSION_NAME + LAST_SELF_SAR_POLL_TIME, new Long(System.currentTimeMillis()));
						}
					} catch (Throwable t) {
						OpenShiftOAuth2SecurityRealm.LOGGER.log(Level.SEVERE, "filter", t);
					}
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
