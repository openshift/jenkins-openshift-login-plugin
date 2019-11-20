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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.tasks.Mailer;

import java.io.IOException;

/**
 * Represents an identity information from the oauth provider.
 *
 * This is from https://SERVER/oapi/v1/user/~
 */
public class OpenShiftUserInfo extends UserProperty {

    public static class Metadata extends UserProperty {
        @Key
        public String name;

        @Key
        public String uid;
    }

    @Key
    public Metadata metadata;

    @Key
    public String email;

    public String getEmail() {
        return email;
    }

    public String getName() {
        if (metadata == null)
            return null;
        return metadata.name;
    }

    /**
     * Updates the user information on Jenkins based on the information in this
     * identity.
     */
    public void updateProfile(hudson.model.User u) throws IOException {
        // update the user profile by the externally given information
        if (email != null)
            u.addProperty(new Mailer.UserProperty(email));

        if (getName() != null)
            u.setFullName(getName());

        u.addProperty(this);
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }

        @Override
        @SuppressFBWarnings
        public String getDisplayName() {
            return null;
        }
    }
}