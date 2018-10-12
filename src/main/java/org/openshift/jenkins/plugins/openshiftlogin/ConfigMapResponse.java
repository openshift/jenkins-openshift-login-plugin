package org.openshift.jenkins.plugins.openshiftlogin;

import java.util.Map;

import com.google.api.client.util.Key;

public class ConfigMapResponse {
    
    public final static String ROLE_LIST = "roleList";
    
    @Key
    public Map<String, String> data;

}
