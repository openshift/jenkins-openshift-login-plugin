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

import java.util.logging.Logger;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.listeners.ItemListener;

@Extension
public class OpenShiftItemListener extends ItemListener {

    static final Logger LOGGER = Logger.getLogger(OpenShiftItemListener.class.getName());

    @Override
    public void onLoaded() {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onCreated(Item item) {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onCopied(Item src, Item item) {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onDeleted(Item item) {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onRenamed(Item item, String oldName, String newName) {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onLocationChanged(Item item, String oldFullName, String newFullName) {
        OpenShiftSetOAuth.setOauth();
    }

    @Override
    public void onUpdated(Item item) {
        OpenShiftSetOAuth.setOauth();
    }

}
