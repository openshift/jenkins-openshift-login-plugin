package org.openshift.jenkins.plugins.openshiftlogin;

import static javax.servlet.http.HttpServletResponse.SC_MOVED_TEMPORARILY;

import java.io.IOException;
import java.io.PrintWriter;

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
		if (w != null) {
			rsp.setContentType("text/html");
			w.println("<!DOCTYPE html>");
			w.println("<html>");
			w.println("<body onload=\"myFunction()\">");
			w.println("<p id=\"demo\"></p>");
			w.println("<script>");
			w.println("function myFunction() {");
			w.println("var x;");
			w.println("if (confirm(\"Press OK to log into Jenkins via OpenShift. Press Cancel to abort login.\") == true) {");
			w.println("x = \"Redirecting to the OpenShift OAuth server ...\";");
			w.println("window.location.href = \"" + url + "\"");
			w.println("} else {");
			w.println("x = \"You aborted logging into Jenkins via OpenShift OAuth.\";");
			w.println("}");
			w.println("document.getElementById(\"demo\").innerHTML = x;");
			w.println("}");
			w.println("</script>");
			w.println("</body>");
			w.println("</html>");
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
