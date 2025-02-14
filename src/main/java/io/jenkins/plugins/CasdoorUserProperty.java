package io.jenkins.plugins;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.List;

public class CasdoorUserProperty extends UserProperty {

    public static class Descriptor extends UserPropertyDescriptor {

        @Override
        public UserProperty newInstance(User user) {
            return new CasdoorUserProperty(user.getId(), new GrantedAuthority[0]);
        }
    }

    private final List<String> authorities = new ArrayList<>();
    private final String username;

    public CasdoorUserProperty(String username, GrantedAuthority[] authorities) {
        this.username = username;
        for (GrantedAuthority authority: authorities) {
            this.authorities.add((authority.getAuthority()));
        }
    }

    public GrantedAuthority[] getAuthoritiesAsGrantedAuthorities() {
        GrantedAuthority[] authorities = new GrantedAuthority[this.authorities.size()];
        for (int i = 0; i < authorities.length; i++) {
            authorities[i] = new SimpleGrantedAuthority(this.authorities.get(i));
        }
        return authorities;
    }


    public String getAllGrantedAuthorities() {
        StringBuilder result = new StringBuilder();
        result.append("Number of GrantedAuthorities in OicUserProperty for ").append(username).append(": ").append(authorities.size());
        for (String authority: authorities) {
            result.append("<br>\nAuthority: ").append(authority);
        }
        return result.toString();
    }

    public String getUsername() {
        return username;
    }

    @Override
    public UserPropertyDescriptor getDescriptor() {
        return new Descriptor();
    }
}
