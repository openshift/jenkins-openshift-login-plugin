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

import java.util.ArrayList;
import java.util.List;

import com.google.api.client.util.Key;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@SuppressFBWarnings
public class OpenShiftSubjectAccessReviewRequest {

    public static final String SUBJECT_ACCESS_REVIEW = "SubjectAccessReview";
    public static final String V1 = "authorization.openshift.io/v1";
    public static final String DEFAULT_RESOURCE_API_GROUP = "build.openshift.io";
    public static final String DEFAULT_RESOURCE = "jenkins";

    public OpenShiftSubjectAccessReviewRequest() {
        kind = SUBJECT_ACCESS_REVIEW;
        apiVersion = V1;
        namespace = null;
        verb = null;
        resourceAPIGroup = DEFAULT_RESOURCE_API_GROUP;
        resourceAPIVersion = "";
        resource = DEFAULT_RESOURCE;
        resourceName = "";
        content = null;
        user = "";
        groups = new ArrayList<String>();
        scopes = new ArrayList<String>();
    }

    @Key
    public String kind;

    @Key
    public String apiVersion;

    @Key
    public String namespace;

    @Key
    public String verb;

    @Key
    public String resourceAPIGroup;

    @Key
    public String resourceAPIVersion;

    @Key
    public String resource;

    @Key
    public String resourceName;

    @Key
    public String content;

    @Key
    public String user;

    @Key
    public List<String> groups;

    @Key
    public List<String> scopes;
}
