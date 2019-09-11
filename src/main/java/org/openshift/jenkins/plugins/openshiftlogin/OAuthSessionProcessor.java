
package org.openshift.jenkins.plugins.openshiftlogin;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.openidconnect.IdTokenResponse;

import hudson.util.HttpResponses;

public final class OAuthSessionProcessor extends OAuthSession {
    private static final Logger LOGGER = Logger.getLogger(OAuthSessionProcessor.class.getName());

    private final String redirectOnFinish;
    private final AuthorizationCodeFlow flow;
    private final OpenShiftOAuth2SecurityRealm secRealm;
    private final String url;

    public OAuthSessionProcessor(AuthorizationCodeFlow flow, String from, String redirectUrl, String redirectOnFinish,
            AuthorizationCodeFlow flow2, OpenShiftOAuth2SecurityRealm secRealm, String url) {
        super(flow, from, redirectUrl);
        this.redirectOnFinish = redirectOnFinish;
        this.flow = flow2;
        this.secRealm = secRealm;
        this.url = url;
    }

    @Override
    public HttpResponse onSuccess(String authorizationCode) {
        try {
            IdTokenResponse response = IdTokenResponse
                    .execute(flow.newTokenRequest(authorizationCode).setRedirectUri(url));
            final Credential credential = new Credential(BearerToken.authorizationHeaderAccessMethod())
                    .setFromTokenResponse(response);
            this.setCredential(credential);
            secRealm.updateAuthorizationStrategy(credential);

            return new HttpRedirect(redirectOnFinish);

        } catch (Throwable e) {
            if (LOGGER.isLoggable(Level.FINE))
                LOGGER.log(Level.FINE, "onSuccess", e);
            return HttpResponses.error(500, e);
        }
    }
}
