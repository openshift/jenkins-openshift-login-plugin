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

import com.google.api.client.util.Key;

/**
 * Represents information on the oauth provider.
 *
 * This is from https://SERVER/.well-known/oauth-authorization-server
 */
/*
{
  "issuer": "https://10.13.137.132:8443",
  "authorization_endpoint": "https://10.13.137.132:8443/oauth/authorize",
  "token_endpoint": "https://10.13.137.132:8443/oauth/token",
  "scopes_supported": [
    "user:full",
    "user:info",
    "user:check-access",
    "user:list-scoped-projects",
    "user:list-projects"
  ],
  "response_types_supported": [
    "code",
    "token"
  ],
  "grant_types_supported": [
    "authorization_code"
  ]
}
 */
public class OpenShiftProviderInfo {
	
	public OpenShiftProviderInfo() {
		
	}

	@Key
	public String issuer;
	
	@Key
	public String authorization_endpoint;
	
	@Key
	public String token_endpoint;

    @Override
    public String toString() {
        return "OpenShiftProviderInfo: issuer: " + issuer + " auth ep: " + authorization_endpoint + " token ep: " + token_endpoint;
    }
	
	
	
}