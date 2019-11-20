package org.openshift.jenkins.plugins.openshiftlogin;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.OutputStream;

import com.google.api.client.http.HttpContent;

public final class SARRequestHttpContent implements HttpContent {
    private final String json;

    public SARRequestHttpContent(String json) {
        this.json = json;
    }

    @Override
    public long getLength() throws IOException {
        return (long) (json.getBytes(UTF_8).length);
    }

    @Override
    public String getType() {
        return "application/json";
    }

    @Override
    public boolean retrySupported() {
        return false;
    }

    @Override
    public void writeTo(OutputStream out) throws IOException {
        out.write(json.getBytes(UTF_8));
        out.flush();
    }
}