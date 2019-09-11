package org.openshift.jenkins.plugins.openshiftlogin;

import java.io.IOException;

import javax.servlet.ServletException;

import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;

@Extension
public final class DescriptorImpl extends Descriptor<SecurityRealm> {
    private static final String DISPLAY_NAME = "Login with OpenShift";

    public String getDisplayName() {
        return DISPLAY_NAME;
    }

    private FormValidation paramsWithPodDefaults(@QueryParameter String value) {
        if (value == null || value.length() == 0)
            return FormValidation.warning(
                    "Unless you specify a value here, the assumption will be that Jenkins is running inside an OpenShift pod, where the value is available.");
        return FormValidation.ok();
    }

    public FormValidation doCheckServiceAccountDirectory(@QueryParameter String value)
            throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

    public FormValidation doCheckClientId(@QueryParameter String value) throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

    public FormValidation doCheckClientSecret(@QueryParameter String value) throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

    public FormValidation doCheckServerPrefix(@QueryParameter String value) throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

    public FormValidation doCheckRedirectURL(@QueryParameter String value) throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

    public FormValidation doCheckServiceAccountName(@QueryParameter String value) throws IOException, ServletException {
        return paramsWithPodDefaults(value);
    }

}