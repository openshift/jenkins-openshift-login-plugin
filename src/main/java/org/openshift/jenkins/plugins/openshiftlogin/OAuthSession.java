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

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.Credential;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.EnvVars;
import hudson.remoting.Base64;
import hudson.util.HttpResponses;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.io.Serializable;
import java.util.UUID;

/**
 * The state of the OAuth request.
 *
 * Verifies the validity of the response by comparing the state.
 */
public abstract class OAuthSession implements Serializable{
    private static final String OPENSHIFT_ENABLE_REDIRECT_PROMPT = "OPENSHIFT_ENABLE_REDIRECT_PROMPT";
    private final AuthorizationCodeFlow flow;
    @SuppressFBWarnings
    private final String uuid = Base64.encode(
            UUID.randomUUID().toString().getBytes()).substring(0, 20);
    /**
     * The url the user was trying to navigate to.
     */
    private final String from;

    /**
     * Where Google will redirect to once the scopes are approved by the user.
     */
    private final String redirectUrl;

    private Credential credential;

    public Credential getCredential() {
        return credential;
    }

    public void setCredential(Credential cred) {
        credential = cred;
    }

    public OAuthSession(AuthorizationCodeFlow flow, String from,
            String redirectUrl) {
        this.flow = flow;
        this.from = from;
        this.redirectUrl = redirectUrl;
    }

    /**
     * Starts the login session.
     */
    public HttpResponse doCommenceLogin() throws IOException {
        // remember this in the session
        Stapler.getCurrentRequest().getSession()
                .setAttribute(SESSION_NAME, this);

        return doRequestAuthorizationCode();
    }

    protected HttpResponse doRequestAuthorizationCode() {
        AuthorizationCodeRequestUrl authorizationCodeRequestUrl = flow
                .newAuthorizationUrl().setState(uuid)
                .setRedirectUri(redirectUrl);
        String redirect = EnvVars.masterEnvVars
                .get(OPENSHIFT_ENABLE_REDIRECT_PROMPT);
        if (redirect != null && !redirect.equalsIgnoreCase("false"))
            return new OpenShiftHttpRedirectWithPrompt(
                    authorizationCodeRequestUrl.toString());
        else
            return new HttpRedirect(authorizationCodeRequestUrl.toString());
    }

    /**
     * When the identity provider is done with its thing, the user comes back
     * here.
     */
    public HttpResponse doFinishLogin(StaplerRequest request)
            throws IOException {
        StringBuffer buf = request.getRequestURL();
        if (request.getQueryString() != null) {
            buf.append('?').append(request.getQueryString());
        }
        AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(
                buf.toString());
        String diagnosticPointer = ", see https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#api-events-oauth-clients"
                + " for possible hints on how to diagnose problems in OpenShift that could cause this.";
        if (!uuid.equals(responseUrl.getState())) {
            return HttpResponses.error(401, "State is invalid; uuid == " + uuid
                    + " resp state == " + responseUrl.getState() + diagnosticPointer);
        }
        String code = responseUrl.getCode();
        if (responseUrl.getError() != null) {
            return HttpResponses.error(401, "Error from provider: " + code + diagnosticPointer);
        } else if (code == null) {
            return HttpResponses.error(404, "Missing authorization code" + diagnosticPointer);
        } else {
            return onSuccess(code);
        }
    }

    /**
     * Where was the user trying to navigate to when they had to login?
     *
     * @return the url the user wants to reach
     */
    protected String getFrom() {
        return from;
    }

    protected abstract HttpResponse onSuccess(String authorizationCode)
            throws IOException;

    /**
     * Gets the {@link OAuthSession} associated with HTTP session in the current
     * extend.
     */
    public static OAuthSession getCurrent() {
        return (OAuthSession) Stapler.getCurrentRequest().getSession()
                .getAttribute(SESSION_NAME);
    }

    static final String SESSION_NAME = OAuthSession.class.getName();
}
