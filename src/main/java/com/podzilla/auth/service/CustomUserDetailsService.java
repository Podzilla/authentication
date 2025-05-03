package com.podzilla.auth.service;

import com.podzilla.auth.dto.CustomGrantedAuthority;
import com.podzilla.auth.dto.CustomUserDetails;
import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(final String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new NotFoundException(
                                email + " not found."));

        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            throw new ValidationException("User has no roles assigned.");
        }

        Set<GrantedAuthority> authorities = user
                .getRoles()
                .stream()
                .map((role) -> new CustomGrantedAuthority(
                        role.getErole().name()))
                .collect(Collectors.toSet());

        return new CustomUserDetails(
                user.getEmail(),
                user.getPassword(),
                user.getEnabled(),
                true,
                true,
                true,
                authorities
        );
    }

    @Cacheable(value = "userDetails", key = "#email")
    public UserDetails loadUserByUsernameCached(final String email) {
        return loadUserByUsername(email);
    }
}
