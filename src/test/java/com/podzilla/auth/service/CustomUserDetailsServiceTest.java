package com.podzilla.auth.service;

import com.podzilla.auth.dto.CustomUserDetails;
import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.exception.ValidationException; // Added import
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User user;
    private String userEmail;
    private String userPassword;

    @BeforeEach
    void setUp() {
        userEmail = "test@example.com";
        userPassword = "encodedPassword";
        Role userRole = new Role(ERole.ROLE_USER);
        Role adminRole = new Role(ERole.ROLE_ADMIN);

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        roles.add(adminRole);

        user = User.builder()
                .id(1L)
                .name("Test User")
                .email(userEmail)
                .password(userPassword)
                .roles(roles)
                .enabled(true)
                .build();
    }

    @Test
    void loadUserByUsername_shouldReturnUserDetails_whenUserExistsAndHasRoles() {
        // Arrange
        when(userRepository.findByEmail(userEmail)).thenReturn(Optional.of(user));

        // Act
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);

        // Assert
        assertNotNull(userDetails);
        assertEquals(userEmail, userDetails.getUsername());
        assertEquals(userPassword, userDetails.getPassword());
        assertNotNull(userDetails.getAuthorities());
        assertEquals(2, userDetails.getAuthorities().size()); // ROLE_USER and ROLE_ADMIN

        // Check specific authorities
        Set<String> expectedAuthorities = Set.of(ERole.ROLE_USER.name(), ERole.ROLE_ADMIN.name());
        Set<String> actualAuthorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertEquals(expectedAuthorities, actualAuthorities);

        assertInstanceOf(CustomUserDetails.class, userDetails, "Should return an instance of CustomUserDetails");

        verify(userRepository).findByEmail(userEmail);
    }

    @Test
    void loadUserByUsername_shouldThrowNotFoundException_whenUserDoesNotExist() {
        // Arrange
        String nonExistentEmail = "notfound@example.com";
        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(nonExistentEmail);
        });

        assertEquals("Not Found: " + nonExistentEmail + " not found.",
                exception.getMessage());
        verify(userRepository).findByEmail(nonExistentEmail);
    }

    @Test
    void loadUserByUsername_shouldThrowValidationException_whenUserHasEmptyRoles() {
        // Arrange
        String emailWithNoRoles = "norole@example.com";
        User userWithNoRoles = User.builder()
                .id(2L)
                .name("No Role User")
                .email(emailWithNoRoles)
                .password("password123")
                .roles(Collections.emptySet()) // Empty roles set
                .build();
        when(userRepository.findByEmail(emailWithNoRoles)).thenReturn(Optional.of(userWithNoRoles));

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            customUserDetailsService.loadUserByUsername(emailWithNoRoles);
        });

        assertEquals("Validation error: User has no roles assigned.",
                exception.getMessage());
        verify(userRepository).findByEmail(emailWithNoRoles);
    }

    @Test
    void loadUserByUsername_shouldThrowValidationException_whenUserHasNullRoles() {
        // Arrange
        String emailWithNullRoles = "nullrole@example.com";
        User userWithNullRoles = User.builder()
                .id(3L)
                .name("Null Role User")
                .email(emailWithNullRoles)
                .password("password456")
                .roles(null) // Null roles set
                .build();
        when(userRepository.findByEmail(emailWithNullRoles)).thenReturn(Optional.of(userWithNullRoles));

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            customUserDetailsService.loadUserByUsername(emailWithNullRoles);
        });

        assertEquals("Validation error: User has no roles assigned.",
                exception.getMessage());
        verify(userRepository).findByEmail(emailWithNullRoles);
    }
}