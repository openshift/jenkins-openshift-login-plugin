package org.openshift.jenkins.plugins.openshiftlogin;

import java.util.Set;

import org.easymock.EasyMock;
import org.easymock.IArgumentMatcher;

import com.google.api.client.http.GenericUrl;

public class OAuthURLArgumentMatcher implements IArgumentMatcher {
	private String host;
	private String rawPath;
	private String clientID;

	private String url;
	
	public String getURL() {
		return url;
	}
	
    public OAuthURLArgumentMatcher(String host, String rawPath, String clientID) {
    	this.host = host;
    	this.rawPath = rawPath;
    	this.clientID = clientID;
    }
    
    public static String eqOAuthURL(String host, String rawPath, String clientID) {
    	EasyMock.reportMatcher(new OAuthURLArgumentMatcher(host, rawPath, clientID));
    	return null;
    }
    
    public boolean matches(Object actual) {
        if (actual == null || !(actual instanceof String)) {
            return false;
        }
        GenericUrl u = new GenericUrl((String)actual);
        if (!u.getHost().equals(host))
        	return false;
        if (!u.getScheme().equals("https"))
        	return false;
        if (!u.getRawPath().equals(rawPath))
        	return false;
        Set<String> ks = u.keySet();
        if (!(ks.contains("redirect_uri") && ks.contains("state")))
        	return false;
        if (u.get("response_type").equals("code"))
        	return false;
        if (u.get("client_id").equals(clientID))
        	return false;
        if (u.get("scope").equals("profile email"))
        	return false;
        url = (String)actual;
        return true;
    }

    public void appendTo(StringBuffer buffer) {
        buffer.append("eqOAuthURL(");
        buffer.append("\")");
    }
}