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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.List;
import java.util.Random;

import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.StaplerResponse;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.WebConnectionWrapper;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;

import hudson.Util;

public class OpenShiftOAuth2SecurityRealmTest {
	@ClassRule
	public static JenkinsRule j = new JenkinsRule();

	static boolean tryIntegration;
	static String openshiftServer;
	static String clientID;
	static String clientSecret;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
        openshiftServer = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.server"));
	    if (openshiftServer != null) {
	    	tryIntegration = true;
		} else {
			openshiftServer = "https://openshift.default.svc";
		}
        clientID = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.clientID"));
        if (clientID == null)
        	clientID = "jenkins";
        clientSecret = Util.fixEmpty(System.getProperty("org.openshift.jenkins.plugins.openshiftlogin.clientSecret"));
        if (clientSecret == null)
        	clientSecret = "client_secret";
	}

	@Test
	public void testLoginUrl() throws Exception {
		OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, openshiftServer, clientID, clientSecret);
		assertThat(realm.getLoginUrl(), is("securityRealm/commenceLogin"));
	}

	@Test
	public void testAuthorizeRedirect() throws Exception {
		OpenShiftOAuth2SecurityRealm.redirectUrl = "http://localhost:19191/jenkins/securityRealm/finishLogin";
		OpenShiftOAuth2SecurityRealm.testTransport = new NetHttpTransport.Builder().doNotValidateCertificate().build();

		final OpenShiftOAuth2SecurityRealm realm = new OpenShiftOAuth2SecurityRealm(null, null, openshiftServer, clientID, clientSecret);
		OAuthSession s = realm.newOAuthSession("http://localhost/start", "http://localhost/done");

		// verify an initial redirect is requested
		org.kohsuke.stapler.HttpResponse resp = s.doRequestAuthorizationCode();
		StaplerResponse mockResp = createMock(StaplerResponse.class);
		int m1 = eq(302);
		OAuthURLArgumentMatcher m2 = new OAuthURLArgumentMatcher((new GenericUrl(openshiftServer)).getHost(), "/oauth/authorize", "");
		EasyMock.reportMatcher(m2);
		mockResp.sendRedirect(m1, "");
		replay(mockResp);
		resp.generateResponse(null, mockResp, null);
		verify(mockResp);
		
		if (!tryIntegration)
			return;
		
		WebClient client = new WebClient();
		client.setUseInsecureSSL(true);
		final WebConnection conn = client.getWebConnection();
		client.setWebConnection(new WebConnectionWrapper(conn) {
		    public WebResponse getResponse(final WebRequestSettings settings) throws IOException {
		        WebResponse resp = conn.getResponse(settings);
		        if (resp.getStatusCode() == 302 && resp.getResponseHeaderValue("Location").startsWith(realm.redirectUrl)) {
		        	throw new FailingHttpStatusCodeException(resp);
		        }
		        return resp;
		    }
		});
		
		// go through login
		HtmlPage p = client.getPage(m2.getURL());
		List<HtmlForm> forms = p.getForms();
		assertThat(forms.isEmpty(), is(false));
		HtmlForm form = forms.get(0);
		form.getInputByName("username").setValueAttribute("admin"+String.valueOf(new Random().nextInt()));
		form.getInputByName("password").setValueAttribute("admin");
        final List<HtmlButton> buttons = form.getElementsByAttribute("button", "type", "submit");

        String code = "";
		try {
			p = buttons.get(0).click();

			// it's possible this user has already been approved
			assertThat( p.getWebResponse().getStatusCode(), is(200) );
			assertThat( p.getWebResponse().getContentAsString(), containsString("Do you approve granting an access token to the following") );
			assertThat( p.getWebResponse().getContentAsString(), containsString(clientID) );
			assertThat( p.getWebResponse().getContentAsString(), containsString("securityRealm/finishLogin") );
			form = p.getForms().get(0);
			
			// will redirect
			Page p2 = form.submit();
			fail("should have redirected: "+p2.getWebResponse().getContentAsString());
		} catch (FailingHttpStatusCodeException e) {
			if (e.getStatusCode() != 302) {
				throw e;
			}
			// if we have already approved, we'll be at the end
			String location = e.getResponse().getResponseHeaderValue("Location");
			assertThat( location, startsWith(realm.redirectUrl + "?") );
			GenericUrl url = new GenericUrl(location);
			code = (String)url.getFirst("code");
		}
		resp = s.onSuccess(code);
		assertThat( resp, is(instanceOf(HttpRedirect.class)) );
	}
/*
	@Test
	public void testHasConfigPage() throws Exception {
	    JenkinsRule.WebClient webClient = j.createWebClient();
	    HtmlPage currentPage = webClient.goTo("configureSecurity");
	    System.out.println(currentPage.asXml());
	    HtmlElement enabled = currentPage.getElementByName("_.enabled");
	    assertThat( enabled, not(null) );
	
	}

    @Test
    public void testEnable() throws Exception {
        JenkinsRule.WebClient webClient = j.createWebClient();
        HtmlPage currentPage = webClient.goTo("configureSecurity");
        HtmlElement enabled = currentPage.getElementByName("_.enabled");
        enabled.fireEvent("click");
	    assertThat( currentPage.getElementByName("_.redirectEnabled"), not(null) );
    }*/
 }
