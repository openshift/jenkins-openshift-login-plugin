/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2019, Red Hat, Inc., Gabe Montero
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
 * Represents openshift server version information.
 *
 * This is from https://SERVER/version
 */
/*
 * {
  "major": "1",
  "minor": "11+",
  "gitVersion": "v1.11.0+d4cacc0",
  "gitCommit": "d4cacc0",
  "gitTreeState": "clean",
  "buildDate": "2019-05-02T11:52:09Z",
  "goVersion": "go1.10.8",
  "compiler": "gc",
  "platform": "linux/amd64"
}
 */
public class OpenShiftVersionInfo {

    public OpenShiftVersionInfo() {

    }

    @Key
    public String major;

    @Key
    public String minor;

    @Key
    public String gitVersion;

    @Override
    public String toString() {
        return "OpenShiftVersionInfo: major: " + major + " minor: "
                + minor + " gitVersion: " + gitVersion;
    }

}