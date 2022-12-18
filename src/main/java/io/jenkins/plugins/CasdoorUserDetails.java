package io.jenkins.plugins;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.io.Serializable;

public class CasdoorUserDetails implements UserDetails,Serializable{
    private static final long serialVersionUID = 1L;
    private final String username;
    private final GrantedAuthority[] grantedAuthorities;

    public CasdoorUserDetails(String username, GrantedAuthority[] grantedAuthorities) {
        this.username = username;
        this.grantedAuthorities = grantedAuthorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.asList(grantedAuthorities);
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
