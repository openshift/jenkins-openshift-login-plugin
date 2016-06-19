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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStoreException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.SecurityUtils;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;

/**
 * Login with OpenShift using OpenID Connect / OAuth 2
 *
 */
public class OpenShiftOAuth2SecurityRealm extends SecurityRealm {

    /**
     * OAuth 2 scope. This is enough to call a variety of userinfo api's.
     */
    private static final String SCOPE = "user:info";

    /**
     * Global instance of the JSON factory.
     */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    /**
     * Control the redirection URL for this realm. Exposed for testing.
     */
    static String redirectUrl;
    /**
     * Allow a custom transport to be injected. Exposed for testing.
     */
    static HttpTransport testTransport;

    /**
     * The transport loaded with a service account secret.
     */
    private final HttpTransport transport;
    
    /**
     * The service account directory, if set, instructs the plugin to follow the
     * Kubernetes service account conventions to locate the service account token
     * (client secret) and namespace value (to build the service account). 
     */
    private final String serviceAccountDirectory;
    /**
     * The service account name is used when serviceAccountDirectory is set to
     * create the client ID (system:serviceaccount:NAMESPACE:NAME).
     */
    private final String serviceAccountName;
    /**
     * The base part of the OpenShift URL for making API calls.
     */
    private final String serverPrefix;
    /**
     * The clientID from the OpenShift server.
     */
    private final String clientId;
    /**
     * The client secret from the OpenShift server.
     */
    private final Secret clientSecret;

    @DataBoundConstructor
    public OpenShiftOAuth2SecurityRealm(String serviceAccountDirectory, String serviceAccountName, String serverPrefix, String clientId, String clientSecret) throws IOException, GeneralSecurityException {
        HttpTransport transport = HTTP_TRANSPORT;

        this.serviceAccountDirectory = Util.fixEmpty(serviceAccountDirectory);
    	if (Util.fixEmpty(serviceAccountName) == null)
    		this.serviceAccountName = "jenkins";
    	else
    		this.serviceAccountName = serviceAccountName;
    	// TODO: should this be in a different method?  Will this show up in settings page?
    	if (this.serviceAccountDirectory != null) {
    		if (Util.fixEmpty(clientSecret) == null) {
	            BufferedReader r = new BufferedReader(new FileReader(new File(this.serviceAccountDirectory, "token")));
	            clientSecret = r.readLine();
	            r.close();
    		}
            if (Util.fixEmpty(clientId) == null) {
	            BufferedReader r = new BufferedReader(new FileReader(new File(this.serviceAccountDirectory, "namespace")));
	            String namespace = r.readLine();
	            r.close();
            	clientId = "system:serviceaccount:"+namespace+":"+this.serviceAccountName; 
            }
            if (Util.fixEmpty(serverPrefix) == null)
            	serverPrefix = "https://openshift.default.svc";
            FileInputStream r = null;
            try {
	            r = new FileInputStream(new File(this.serviceAccountDirectory, "ca.crt"));
	            KeyStore keyStore = SecurityUtils.getDefaultKeyStore();
	            try {
	            	keyStore.size();
	            } catch (KeyStoreException e) {
	            	keyStore.load(null);
	            }
	            SecurityUtils.loadKeyStoreFromCertificates(keyStore, SecurityUtils.getX509CertificateFactory(), r);
	            transport = new NetHttpTransport.Builder().trustCertificates(keyStore).build();
            } catch (FileNotFoundException e) {
            } finally {
            	if (r != null)
            		r.close();
            }
    	}
        this.serverPrefix = serverPrefix;
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        
        if (testTransport != null)
        	transport = testTransport;
        this.transport = transport;
    }

    public String getServiceAccountDirectory() {
        return serviceAccountDirectory;
    }

    public String getServiceAccountName() {
        return serviceAccountName;
    }

    public String getServerPrefix() {
        return serverPrefix;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(String,String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /**
     * Acegi has this notion that first an {@link org.acegisecurity.Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link org.acegisecurity.AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link org.acegisecurity.Authentication} only after we verified the user identity,
     * so {@link org.acegisecurity.AuthenticationManager} becomes no-op.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof AnonymousAuthenticationToken)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }

    protected OAuthSession newOAuthSession(String from, final String redirectOnFinish) {
    	final GenericUrl tokenServerURL = new GenericUrl(serverPrefix + "/oauth/token");
        final String authorizationServerURL = serverPrefix +"/oauth/authorize";
        
        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.queryParameterAccessMethod(), transport, JSON_FACTORY, tokenServerURL,
                new ClientParametersAuthentication(clientId, clientSecret.getPlainText()), clientId, authorizationServerURL)
                .setScopes(Arrays.asList(SCOPE))
                .build();
        
        return new OAuthSession(flow, from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    IdTokenResponse response = IdTokenResponse.execute(
                            flow.newTokenRequest(authorizationCode).setRedirectUri(buildOAuthRedirectUrl()));
                    //final Credential credential = flow.createAndStoreCredential(response, null);
                    final Credential credential = new Credential(BearerToken.authorizationHeaderAccessMethod()).setFromTokenResponse(response);
                    HttpRequestFactory requestFactory =
                            transport.createRequestFactory(new HttpRequestInitializer() {
                                public void initialize(HttpRequest request) throws IOException {
                                	credential.initialize(request);
                                    request.setParser(new JsonObjectParser(JSON_FACTORY));
                                }
                            });
                    GenericUrl url = new GenericUrl(serverPrefix + "/oapi/v1/users/~");

                    HttpRequest request = requestFactory.buildGetRequest(url);

                    OpenShiftUserInfo info = request.execute().parseAs(OpenShiftUserInfo.class);
                    GrantedAuthority[] authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
                    // logs this user in.
                    UsernamePasswordAuthenticationToken token =
                            new UsernamePasswordAuthenticationToken(info.getName(), "", authorities);
                    SecurityContextHolder.getContext().setAuthentication(token);
                    // update the user profile.
                    User u = User.get(token.getName());
                    info.updateProfile(u);
                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500,e);
                }
            }
        };
    }
    
    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(@QueryParameter String from,  @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish;
        if (from != null) {
            redirectOnFinish = from;
        } else if (referer != null) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = Jenkins.getInstance().getRootUrl();
        }

        return newOAuthSession(from, redirectOnFinish).doCommenceLogin();
    }

    private String buildOAuthRedirectUrl() {
    	if (redirectUrl != null)
    		return redirectUrl;
        String rootUrl = Jenkins.getInstance().getRootUrl();
        if (rootUrl == null)
            throw new NullPointerException("Jenkins root url should not be null");
        return rootUrl + "securityRealm/finishLogin";
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        return OAuthSession.getCurrent().doFinishLogin(request);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Login with OpenShift";
        }
    }
}
