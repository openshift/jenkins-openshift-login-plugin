package org.openshift.jenkins.plugins.openshiftlogin;

import java.io.IOException;
import java.io.OutputStream;

import com.google.api.client.http.HttpContent;

public final class AdminHttpContent implements HttpContent {
    private final String json;

    public AdminHttpContent(String json) {
        this.json = json;
    }

    @Override
    public long getLength() throws IOException {
        return (long) (json.getBytes().length);
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
        out.write(json.getBytes());
        out.flush();
    }
}