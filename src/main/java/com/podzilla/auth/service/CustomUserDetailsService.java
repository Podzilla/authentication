package com.podzilla.auth.service;

import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import static com.podzilla.auth.service.AdminService.getUserDetails;

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

        return getUserDetails(user);
    }

    @Cacheable(value = "userDetails", key = "#email")
    public UserDetails loadUserByUsernameCached(final String email) {
        return loadUserByUsername(email);
    }
}
