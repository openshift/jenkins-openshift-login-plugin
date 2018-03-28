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

import hudson.EnvVars;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;

public class OpenShiftSetOAuth {

    static final Logger LOGGER = Logger.getLogger(OpenShiftSetOAuth.class
            .getName());
    static final String OPENSHIFT_ENABLE_OAUTH = "OPENSHIFT_ENABLE_OAUTH";
    static long lastCheck = 0;
    static int lastLog = 0;

    static boolean setOauth() {
        return setOauth(true);
    }

    static boolean setOauth(boolean force) {
        final Jenkins jenkins = Jenkins.getInstance();
        String enabled = EnvVars.masterEnvVars.get(OPENSHIFT_ENABLE_OAUTH);
        // we override the security realm with openshift oauth if running in an
        // openshift pod
        // and the correct env var is set on the pod during deployment (which
        // our default templates now do)
        if (jenkins != null && enabled != null
                && !enabled.equalsIgnoreCase("false")) {
            SecurityRealm priorSecurityRealm = jenkins.getSecurityRealm();
            // if sec realm already openshift ouath, it has been explicitly
            // configured, so leave alone
            if (!(priorSecurityRealm instanceof OpenShiftOAuth2SecurityRealm)) {
                synchronized (OpenShiftSetOAuth.class) {
                    if (force
                            || (System.currentTimeMillis() > lastCheck + 1000)) {
                        LOGGER.info("OpenShift OAuth: enable oauth set to "
                                + enabled + " force " + force + " lastCheck "
                                + new Date(lastCheck));
                        LOGGER.info("OpenShift OAuth: configured security realm on startup: "
                                + priorSecurityRealm
                                + " last check "
                                + new Date(lastCheck));
                        lastCheck = System.currentTimeMillis();
                        try {
                            final OpenShiftOAuth2SecurityRealm osrealm = new OpenShiftOAuth2SecurityRealm(
                                    null, null, null, null, null, null);
                            boolean inOpenShiftPod = false;
                            try {
                                inOpenShiftPod = osrealm.populateDefaults();
                            } catch (Throwable t) {
                                if ((lastLog % 100) == 0) {
                                    LOGGER.log(Level.SEVERE, "OpenShiftSetOAuth", t);
                                }
                                lastLog++;
                            }
                            LOGGER.info("OpenShift OAuth: running in OpenShift pod with required OAuth features: "
                                    + inOpenShiftPod);
                            if (inOpenShiftPod) {
                                jenkins.setSecurityRealm(osrealm);
                                LOGGER.info("OpenShift OAuth: Jenkins security realm set to OpenShift OAuth");
                                return true;
                            }
                        } catch (IOException e1) {
                            if ((lastLog % 100) == 0) {
                                LOGGER.log(Level.SEVERE, "OpenShiftSetOAuth", e1);
                            }
                            lastLog++;
                        } catch (GeneralSecurityException e1) {
                            if ((lastLog % 100) == 0) {
                                LOGGER.log(Level.SEVERE, "OpenShiftSetOAuth", e1);
                            }
                            lastLog++;
                        } catch (Throwable t) {
                            if ((lastLog % 100) == 0) {
                                LOGGER.log(Level.SEVERE, "OpenShiftSetOAuth", t);
                            }
                            lastLog++;
                        }
                    }
                }
            } else {
                // make sure filter is in place for restart scenarios
                OpenShiftOAuth2SecurityRealm secRealm = (OpenShiftOAuth2SecurityRealm)priorSecurityRealm;
                secRealm.createFilter();
            }
        }
        return false;
    }
}
