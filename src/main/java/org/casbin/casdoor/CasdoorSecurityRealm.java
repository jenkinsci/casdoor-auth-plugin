// Copyright 2022 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.casdoor;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

public class CasdoorSecurityRealm extends SecurityRealm {

    private String clientId = "";
    private String clientSecret = "";
    private String endpoint = "";

    @DataBoundConstructor
    public CasdoorSecurityRealm() {
        super();
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return null;
    }

    public String getClientId() {
        return clientId;
    }

    @DataBoundSetter
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    @DataBoundSetter
    public void setClientSecret() {
        this.clientSecret = clientSecret;
    }

    public String getEndpoint() {
        return endpoint;
    }

    @DataBoundSetter
    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Casdoor Authentication Plugin";
        }
    }
}
