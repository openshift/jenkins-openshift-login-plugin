package org.openshift.jenkins.plugins.openshiftlogin;

import java.io.IOException;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;

public class OpenShiftRequestInitializer implements HttpRequestInitializer {

    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private final Credential credential;

    public OpenShiftRequestInitializer(Credential credential) {
        this.credential = credential;
    }

    public void initialize(HttpRequest request) throws IOException {
        credential.initialize(request);
        request.setParser(new JsonObjectParser(JSON_FACTORY));
    }
}
