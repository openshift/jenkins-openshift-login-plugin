/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2016, Red Hat, Inc., Clayton Coleman
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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.openidconnect.IdTokenResponse;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.util.HttpResponses;

public final class BearerTokenOAuthSession extends OAuthSession {
    static final Logger LOGGER = Logger.getLogger(BearerTokenOAuthSession.class.getName());
    private final String redirectOnFinish;
    private final String url;
    @SuppressFBWarnings
    private final AuthorizationCodeFlow flow;
    private final OpenShiftOAuth2SecurityRealm secRealm;

    public BearerTokenOAuthSession(AuthorizationCodeFlow flow, String from, String redirectUrl, String redirectOnFinish,
            String url, AuthorizationCodeFlow flow2, OpenShiftOAuth2SecurityRealm secRealm) {
        super(flow, from, redirectUrl);
        this.redirectOnFinish = redirectOnFinish;
        this.url = url;
        this.flow = flow2;
        this.secRealm = secRealm;
    }

    @Override
    public HttpResponse onSuccess(String authorizationCode) {
        try {
            LOGGER.info("");
            AuthorizationCodeTokenRequest tokenRequest = flow.newTokenRequest(authorizationCode).setRedirectUri(url);
            IdTokenResponse response = IdTokenResponse.execute(tokenRequest);
            final Credential credential = new Credential(BearerToken.authorizationHeaderAccessMethod())
                    .setFromTokenResponse(response);
            this.setCredential(credential);
            secRealm.updateAuthorizationStrategy(credential);
            if (Stapler.getCurrentRequest() != null && Stapler.getCurrentRequest().getSession() != null) {
                Stapler.getCurrentRequest().getSession().setAttribute("oAuthAccessToken", response);
            }
            return new HttpRedirect(redirectOnFinish);

        } catch (Throwable e) {
            if (LOGGER.isLoggable(Level.SEVERE))
                LOGGER.log(Level.SEVERE, "onSuccess", e);
            return HttpResponses.error(500, e);
        }
    }
}