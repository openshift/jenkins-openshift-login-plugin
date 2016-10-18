package org.openshift.jenkins.plugins.openshiftlogin;

import static javax.servlet.http.HttpServletResponse.SC_MOVED_TEMPORARILY;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.logging.Level;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

public class OpenShiftHttpRedirectWithPrompt extends RuntimeException implements
		HttpResponse {

	private final int statusCode;
	private final String url;

	public OpenShiftHttpRedirectWithPrompt(@Nonnull String url) {
		this(SC_MOVED_TEMPORARILY, url);
	}

	public OpenShiftHttpRedirectWithPrompt(int statusCode, @Nonnull String url) {
		this.statusCode = statusCode;
		if (url == null) {
			throw new NullPointerException();
		}
		this.url = url;
	}

	public void generateResponse(StaplerRequest req, StaplerResponse rsp,
			Object node) throws IOException, ServletException {
		PrintWriter w = rsp.getWriter();
		if (w != null && req.getSession().getAttribute(OpenShiftOAuth2SecurityRealm.LOGGING_OUT) == null) {
		    InputStream is = null;
	        InputStreamReader isr = null;
	        BufferedReader br = null;
	        try {
	            is = this.getClass().getResourceAsStream("openshift-jenkins.html");
	            isr = new InputStreamReader(is, Charset.forName("UTF-8"));
	            br = new BufferedReader(isr);
	            rsp.setContentType("text/html");
	            String s = null;
	            while ((s = br.readLine()) != null) {
	                s = s.replace("<a href=\"#", "<a href=\"" + url);
	                w.println(s);
	            }
	        } catch (Throwable t) {
	            if (OpenShiftOAuth2SecurityRealm.LOGGER.isLoggable(Level.FINE))
	                OpenShiftOAuth2SecurityRealm.LOGGER.log(Level.FINE, "generateResponse", t);
	        } finally {
	            if (is != null)
	                is.close();
	            if (isr != null)
	                isr.close();
	            if (br != null)
	                br.close();
	            
	        }
			w.flush();
		} else {
			rsp.sendRedirect(statusCode, url);
		}
	}

	/**
	 * @param relative
	 *            The path relative to the context path. The context path + this
	 *            value is sent to the user.
	 * @deprecated Use {@link HttpResponses#redirectViaContextPath(String)}.
	 */
	public static HttpResponse fromContextPath(final String relative) {
		return HttpResponses.redirectViaContextPath(relative);
	}

	/**
	 * Redirect to "."
	 */
	public static HttpRedirect DOT = new HttpRedirect(".");

	/**
	 * Redirect to the context root
	 */
	public static HttpResponse CONTEXT_ROOT = fromContextPath("");

}
