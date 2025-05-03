package com.podzilla.auth.service;

import com.podzilla.auth.dto.CustomGrantedAuthority;
import com.podzilla.auth.dto.CustomUserDetails;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AdminService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AdminService.class);

    private final UserRepository userRepository;
    private final UserService userService;

    public AdminService(final UserRepository userRepository,
                        final UserService userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void updateUserActivation(final Long userId,
                                     final boolean isActive) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Updating isActive status for userId={} "
                + "from {} to {}", userId, user.getEnabled(), isActive);
        user.setEnabled(isActive);
        updateUserDetailsCache(user);
        userRepository.save(user);
        LOGGER.debug("User activation status updated "
                + "successfully for userId={}", userId);
    }


    @Transactional
    public void deleteUser(final Long userId) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Deleting user with userId={}", userId);
        evictUserDetailsCache(user);
        userRepository.delete(user);
        LOGGER.debug("User deleted successfully with userId={}", userId);
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

    public static UserDetails getUserDetails(final User user) {
        Set<GrantedAuthority> authorities = user
                .getRoles()
                .stream()
                .map((role) -> new CustomGrantedAuthority(
                        role.getErole().name()))
                .collect(Collectors.toSet());

        return CustomUserDetails.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .enabled(user.getEnabled())
                .authorities(authorities)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
    }
}
