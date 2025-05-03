package com.podzilla.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails {

    private String username;

    @JsonIgnore
    private String password;

    @JsonDeserialize(contentAs = CustomGrantedAuthority.class)
    private Set<GrantedAuthority> authorities;

    @Getter
    private final boolean accountNonExpired;
    @Getter
    private final boolean accountNonLocked;
    @Getter
    private final boolean credentialsNonExpired;
    @Getter
    private final boolean enabled;

    public CustomUserDetails() {
        // No-arg constructor required by Jackson
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
    }

    public CustomUserDetails(final String username, final String password,
                             final Set<GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
    }

    public CustomUserDetails(final String username,
                             final String password,
                             final boolean enabled,
                             final boolean accountNonExpired,
                             final boolean accountNonLocked,
                             final boolean credentialsNonExpired,
                             final Set<GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
        this.enabled = enabled;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void eraseCredentials() {
        this.password = null;
    }

    public int hashCode() {
        return this.username.hashCode();
    }

    public boolean equals(final Object obj) {
        if (obj instanceof CustomUserDetails) {
            return this.username
                    .equals(((CustomUserDetails) obj).getUsername());
        } else {
            return false;
        }
    }

    public String toString() {
        return this.getClass().getName() + " ["
                + "Username=" + this.username + ", "
                + "Password=[PROTECTED], "
                + "Enabled=" + this.enabled + ", "
                + "AccountNonExpired=" + this.accountNonExpired + ", "
                + "CredentialsNonExpired=" + this.credentialsNonExpired + ", "
                + "AccountNonLocked=" + this.accountNonLocked + ", "
                + "Granted Authorities=" + this.authorities + "]";
    }
}
