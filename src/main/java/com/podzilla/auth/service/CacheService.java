package com.podzilla.auth.service;

import com.podzilla.auth.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import static com.podzilla.auth.service.AdminService.getUserDetails;

@Service
public class CacheService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CacheService.class);

    private final CustomUserDetailsService customUserDetailsService;

    public CacheService(
            final CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @CacheEvict(value = "userDetails", key = "#user.email")
    public void evictUserDetailsCache(final User user) {
        LOGGER.debug("Evicting user details cache for userId={}", user.getId());
    }

    @CachePut(value = "userDetails", key = "#user.email")
    public UserDetails updateUserDetailsCache(final User user) {
        LOGGER.debug("Updating user details cache for userId={}", user.getId());

        return getUserDetails(user);
    }

    @Cacheable(value = "userDetails", key = "#email")
    public UserDetails loadUserByUsername(final String email) {
        return customUserDetailsService.loadUserByUsername(email);
    }
}
