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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.openshift.jenkins.plugins.openshiftlogin.OpenShiftOAuth2SecurityRealm.SECURITY_REALM_FINISH_LOGIN;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Random;

import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.StaplerResponse;

import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.htmlunit.WebConnection;
import org.htmlunit.WebRequest;
//import org.htmlunit.WebRequestSettings;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.WebConnectionWrapper;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;

import hudson.Util;

public class OpenShiftOAuth2SecurityRealmTest {
    private static final String REDIRECT_URL_FIELD_NAME = "redirectUrl";

    public final class OAuthRedirectedResponse extends WebConnectionWrapper {
        private final WebConnection conn;
        private final OpenShiftOAuth2SecurityRealm realm;

        public OAuthRedirectedResponse(WebConnection webConnection, WebConnection conn,
                OpenShiftOAuth2SecurityRealm realm) throws IllegalArgumentException {
            super(webConnection);
            this.conn = conn;
            this.realm = realm;
        }

        public WebResponse getResponse(final WebRequest settings) throws IOException {
            WebResponse resp = conn.getResponse(settings);
            if (resp.getStatusCode() == 302 && resp.getResponseHeaderValue("Location").startsWith(realm.redirectUrl)) {
                throw new FailingHttpStatusCodeException(resp);
            }
            return resp;
        }
    }

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    static boolean tryIntegration;
    static String server;
    static String id;
    static String secret;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        server = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.server"));
        if (server != null) {
            tryIntegration = true;
        } else {
            server = "https://kubernetes.default:443";
        }
        id = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.clientID"));
        if (id == null)
            id = "jenkins";
        secret = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.clientSecret"));
        if (secret == null)
            secret = "client_secret";
    }

    @Test
    public void testBuildOAuthRedirectUrl() throws Exception {
        String origin = "https://my-redirect-url";
        String port = ":1234";
        String context = "/my-context";
        String redir = origin + port + context;
        OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret, redir);
        String url = realm.buildOAuthRedirectUrl(redir);
        assertThat(url, is(origin + port + SECURITY_REALM_FINISH_LOGIN));
    }

    @Test
    public void testBuildOAuthRedirectUrlDefaultPort() throws Exception {
        String origin = "https://my-redirect-url";
        String port = ":443";
        String context = "/my-context";
        String redir = origin + port + context;
        OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret, redir);
        String url = realm.buildOAuthRedirectUrl(redir);
        assertThat(url, is(origin + SECURITY_REALM_FINISH_LOGIN));
    }

    @Test
    public void testBuildOAuthRedirectUrlHttp() throws Exception {
        String origin = "http://my-redirect-url";
        String port = ":12345";
        String context = "/my-context";
        String redir = origin + port + context;
        OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret, redir);
        String url = realm.buildOAuthRedirectUrl(redir);
        assertThat(url, is(origin + port + SECURITY_REALM_FINISH_LOGIN));
    }

    @Test
    public void testBuildOAuthRedirectUrlDefaultHttpPort() throws Exception {
        String origin = "http://my-redirect-url";
        String port = ":80";
        String context = "/my-context";
        String redir = origin + port + context;
        OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret, redir);
        String url = realm.buildOAuthRedirectUrl(redir);
        assertThat(url, is(origin + SECURITY_REALM_FINISH_LOGIN));
    }

    @Test
    public void testLoginUrl() throws Exception {
        OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret, server);
        assertThat(realm.getLoginUrl(), is("securityRealm/commenceLogin"));
    }

    @Test
    public void testAuthorizeRedirect() throws Exception {
        OpenShiftOAuth2SecurityRealm.testTransport = new NetHttpTransport.Builder().doNotValidateCertificate().build();
        final OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret,
                server);
        realm.redirectUrl = "http://localhost:19191/jenkins" + SECURITY_REALM_FINISH_LOGIN;

        OAuthSession s = realm.newOAuthSession("http://localhost/start", "http://localhost/done");

        // verify an initial redirect is requested
        org.kohsuke.stapler.HttpResponse resp = s.doRequestAuthorizationCode();
        StaplerResponse mockResp = createMock(StaplerResponse.class);
        int m1 = eq(302);
        OAuthURLArgumentMatcher m2 = new OAuthURLArgumentMatcher((new GenericUrl(server)).getHost(), "/oauth/authorize",
                "");
        EasyMock.reportMatcher(m2);
        mockResp.sendRedirect(m1, "");
        replay(mockResp);
        resp.generateResponse(null, mockResp, null);
        verify(mockResp);

        if (!tryIntegration)
            return;

        WebClient client = new WebClient();
        try {
            // client.setUseInsecureSSL(true);
            final WebConnection conn = client.getWebConnection();
            client.setWebConnection(new OAuthRedirectedResponse(conn, conn, realm));

            // go through login
            HtmlPage p = client.getPage(m2.getURL());
            List<HtmlForm> forms = p.getForms();
            assertThat(forms.isEmpty(), is(false));
            HtmlForm form = forms.get(0);
            form.getInputByName("username").setValue("admin" + String.valueOf(new Random().nextInt()));
            form.getInputByName("password").setValue("admin");
            final List<HtmlButton> buttons = form.getElementsByAttribute("button", "type", "submit");

            String code = "";
            try {
                p = buttons.get(0).click();

                // it's possible this user has already been approved
                assertThat(p.getWebResponse().getStatusCode(), is(200));
                assertThat(p.getWebResponse().getContentAsString(),
                        containsString("Do you approve granting an access token to the following"));
                assertThat(p.getWebResponse().getContentAsString(), containsString(id));
                assertThat(p.getWebResponse().getContentAsString(), containsString(SECURITY_REALM_FINISH_LOGIN));
                form = p.getForms().get(0);

                // will redirect
                Page p2 = form.click();
                fail("should have redirected: " + p2.getWebResponse().getContentAsString());
            } catch (FailingHttpStatusCodeException e) {
                if (e.getStatusCode() != 302) {
                    throw e;
                }
                // if we have already approved, we'll be at the end
                String location = e.getResponse().getResponseHeaderValue("Location");
                assertThat(location, startsWith(realm.redirectUrl + "?"));
                GenericUrl url = new GenericUrl(location);
                code = (String) url.getFirst("code");
            }
            resp = s.onSuccess(code);
            assertThat(resp, is(instanceOf(HttpRedirect.class)));
        } finally {
            client.close();
        }
    }

    @Test
    public void testPodDefaults() throws Exception {
        final OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret,
                server);
        assertThat(realm.populateDefaults(), is(false));
        assertThat(realm.getDefaultedServerPrefix(), is(OpenShiftOAuth2SecurityRealm.DEFAULT_SVR_PREFIX));
        assertThat(realm.getDefaultedServiceAccountDirectory(), is(OpenShiftOAuth2SecurityRealm.DEFAULT_SVC_ACCT_DIR));
    }

    @Test
    public void testBuildOAuthRedirectUrlWithoutPrefix() throws Exception {
        final OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret,
                server);
        // Create a new OAuthSession with a redirectUrl with a long path
        OAuthSession session = realm.newOAuthSession("from", "https://example.com/jenkins/extra/path");

        // Find private 'redirectUrl' field using Java Reflection and assert it doesn't
        // include
        // the '/jenkins/extra/path' portion of the redirectUrl passed above.
        Class<?> sessionClass = session.getClass();
        Field fields[] = sessionClass.getDeclaredFields();
        for (Field field : fields) {
            if (field.getName().equals(REDIRECT_URL_FIELD_NAME)) {
                field.setAccessible(true);
                assertThat(field.get(session).toString(), is("https://example.com" + SECURITY_REALM_FINISH_LOGIN));
            }
        }
    }

    @Test
    public void testBuildOAuthRedirectUrlWithPrefixWithPort() throws Exception {
        final OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, server, id, secret,
                server);
        // Create a new OAuthSession with a redirectUrl with a long path
        OAuthSession session = realm.newOAuthSession("from", "https://example.com:1234/jenkins/extra/path");
        // Find private 'redirectUrl' field using Java Reflection and assert it doesn't
        // include
        // the '/jenkins/extra/path' portion of the redirectUrl passed above.
        Class<?> sessionClass = session.getClass();
        Field fields[] = sessionClass.getDeclaredFields();
        for (Field field : fields) {
            if (field.getName().equals(REDIRECT_URL_FIELD_NAME)) {
                field.setAccessible(true);
                assertThat(field.get(session).toString(), is("https://example.com:1234" + SECURITY_REALM_FINISH_LOGIN));
            }
        }
    }

    /*
     * @Test public void testHasConfigPage() throws Exception {
     * JenkinsRule.WebClient webClient = j.createWebClient(); HtmlPage currentPage =
     * webClient.goTo("configureSecurity"); System.out.println(currentPage.asXml());
     * HtmlElement enabled = currentPage.getElementByName("_.enabled"); assertThat(
     * enabled, not(null) );
     *
     * }
     *
     * @Test public void testEnable() throws Exception { JenkinsRule.WebClient
     * webClient = j.createWebClient(); HtmlPage currentPage =
     * webClient.goTo("configureSecurity"); HtmlElement enabled =
     * currentPage.getElementByName("_.enabled"); enabled.fireEvent("click");
     * assertThat( currentPage.getElementByName("_.redirectEnabled"), not(null) ); }
     */
}
