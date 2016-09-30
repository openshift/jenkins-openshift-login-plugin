/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2016, Red Hat, Inc., Gabe Montero
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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;
import hudson.EnvVars;
import hudson.Extension;
import hudson.model.listeners.ItemListener;
import hudson.security.SecurityRealm;

/**
 * This implementaion of the Jenkins listener will get called when startup is completed
 * 
 *
 */
@Extension
public class OpenShiftItemListener extends ItemListener {
	static final Logger LOGGER = Logger.getLogger(OpenShiftItemListener.class.getName());
	private static final String OPENSHIFT_ENABLE_OAUTH = "OPENSHIFT_ENABLE_OAUTH";

	@Override
	public void onLoaded() {
		final Jenkins jenkins = Jenkins.getInstance();
		String enabled = EnvVars.masterEnvVars.get(OPENSHIFT_ENABLE_OAUTH);
		LOGGER.info("OpenShift OAuth: enable oauth set to " + enabled);
		// we override the security realm with openshift oauth if running in an openshift pod
		// and the correct env var is set on the pod during deployment (which our default templates now do)
		if (jenkins != null && enabled != null) {
			SecurityRealm priorSecurityRealm = jenkins.getSecurityRealm();
			LOGGER.info("OpenShift OAuth: configured security realm on startup: " + priorSecurityRealm);
			// if sec realm already openshift ouath, it has been explicitly configured, so leave alone
			if (!(priorSecurityRealm instanceof OpenShiftOAuth2SecurityRealm)) {
				try {
					final OpenShiftOAuth2SecurityRealm osrealm = new OpenShiftOAuth2SecurityRealm(null, null, null, null, null, null);
					boolean inOpenShiftPod = false;
					try {
						inOpenShiftPod = osrealm.populateDefaults();
					} catch (Throwable t) {
						if (LOGGER.isLoggable(Level.FINE))
							LOGGER.log(Level.FINE, "OpenShiftItemListener", t);
					}
					LOGGER.info("OpenShift OAuth: running in OpenShift pod with required OAuth features: " + inOpenShiftPod);
					if (inOpenShiftPod) {
						jenkins.setSecurityRealm(osrealm);
						LOGGER.info("OpenShift OAuth: Jenkins security realm set to OpenShift OAuth");
					}
				} catch (IOException e1) {
				} catch (GeneralSecurityException e1) {
				}
			}
		}
	}

}
