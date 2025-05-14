package com.podzilla.auth.service;

import com.podzilla.auth.dto.AddCourierRequest;
import com.podzilla.auth.dto.CustomGrantedAuthority;
import com.podzilla.auth.dto.CustomUserDetails;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import com.podzilla.mq.EventPublisher;
import com.podzilla.mq.EventsConstants;
import com.podzilla.mq.events.CourierRegisteredEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AdminService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AdminService.class);

    private final UserRepository userRepository;
    private final UserService userService;
    private final CacheService cacheService;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final EventPublisher eventPublisher;

    public AdminService(final UserRepository userRepository,
                        final UserService userService,
                        final CacheService cacheService,
                        final PasswordEncoder passwordEncoder,
                        final RoleRepository roleRepository,
                        final EventPublisher eventPublisher) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.cacheService = cacheService;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.eventPublisher = eventPublisher;
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void updateUserActivation(final UUID userId,
                                     final boolean isActive) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Updating isActive status for userId={} "
                + "from {} to {}", userId, user.getEnabled(), isActive);
        user.setEnabled(isActive);
        cacheService.updateUserDetailsCache(user);
        userRepository.save(user);
        LOGGER.debug("User activation status updated "
                + "successfully for userId={}", userId);
    }


    @Transactional
    public void deleteUser(final UUID userId) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Deleting user with userId={}", userId);
        cacheService.evictUserDetailsCache(user);
        userRepository.delete(user);
        LOGGER.debug("User deleted successfully with userId={}", userId);
    }

    @Transactional
    public void addCourier(final AddCourierRequest request) {
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setMobileNumber(request.getMobileNumber());
        user.setEnabled(true);
        user.setRoles(Set.of(roleRepository.findByErole(ERole.ROLE_COURIER)
                .orElseThrow(() -> new RuntimeException("Role not found"))));

        userRepository.save(user);

        eventPublisher.publishEvent(EventsConstants.COURIER_REGISTERED,
                new CourierRegisteredEvent(user.getId().toString(),
                        user.getName(), user.getMobileNumber()));
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
                .id(user.getId())
                .password(user.getPassword())
                .enabled(user.getEnabled())
                .authorities(authorities)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
    }
}
