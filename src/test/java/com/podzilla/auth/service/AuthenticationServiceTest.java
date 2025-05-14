package com.podzilla.auth.service;

import com.podzilla.auth.dto.CustomGrantedAuthority;
import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest; // Added import
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserRepository userRepository;
    @Mock
    private TokenService tokenService;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock // Added mock for HttpServletRequest
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private AuthenticationService authenticationService;

    private SignupRequest signupRequest;
    private LoginRequest loginRequest;
    private User user;
    private Role userRole;

    @BeforeEach
    void setUp() {
        signupRequest = new SignupRequest();
        signupRequest.setName("Test User");
        signupRequest.setEmail("test@example.com");
        signupRequest.setPassword("password123");

        loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        userRole = new Role(ERole.ROLE_USER);
        user = User.builder()
                .id(UUID.randomUUID())
                .name("Test User")
                .email("test@example.com")
                .password("encodedPassword")
                .roles(Collections.singleton(userRole))
                .build();

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    // --- registerAccount Tests ---

    @Test
    void registerAccount_shouldSaveUser_whenEmailNotExistsAndPasswordNotEmpty() {
        // Arrange
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(signupRequest.getPassword())).thenReturn("encodedPassword");
        when(roleRepository.findByErole(ERole.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(User.class))).thenReturn(user); // Return the saved user

        // Act
        authenticationService.registerAccount(signupRequest);

        // Assert
        verify(userRepository).existsByEmail(signupRequest.getEmail());
        verify(passwordEncoder).encode(signupRequest.getPassword());
        verify(roleRepository).findByErole(ERole.ROLE_USER);

        // Capture the user argument passed to save
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertEquals(signupRequest.getName(), savedUser.getName());
        assertEquals(signupRequest.getEmail(), savedUser.getEmail());
        assertEquals("encodedPassword", savedUser.getPassword());
        assertTrue(savedUser.getRoles().contains(userRole));
    }

    @Test
    void registerAccount_shouldThrowValidationException_whenEmailExists() {
        // Arrange
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(true);

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            authenticationService.registerAccount(signupRequest);
        });

        assertEquals("Validation error: Email already in use.",
                exception.getMessage());
        verify(userRepository).existsByEmail(signupRequest.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(roleRepository, never()).findByErole(any());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void registerAccount_shouldHandleRoleNotFoundGracefully() {
        // Arrange - Simulate role not found in DB
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(signupRequest.getPassword())).thenReturn("encodedPassword");
        when(roleRepository.findByErole(ERole.ROLE_USER)).thenReturn(Optional.empty()); // Role not found

        // Act
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            authenticationService.registerAccount(signupRequest);
        });

        assertEquals("Validation error: Role_USER not found.",
                exception.getMessage());

        // Assert
        verify(userRepository).existsByEmail(signupRequest.getEmail());
        verify(passwordEncoder).encode(signupRequest.getPassword());
        verify(roleRepository).findByErole(ERole.ROLE_USER);
    }


    // --- login Tests ---

    @Test
    void login_shouldReturnUsernameAndSetTokens_whenCredentialsAreValid() {
        // Arrange
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                loginRequest.getEmail(),
                "encodedPassword", // Password doesn't matter much here as AuthenticationManager handles it
                Collections.singletonList(new CustomGrantedAuthority("ROLE_USER"))
        );
        Authentication successfulAuth = new UsernamePasswordAuthenticationToken(
                userDetails, // Principal
                loginRequest.getPassword(), // Credentials
                userDetails.getAuthorities() // Authorities
        );

        // Mock AuthenticationManager behavior
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(successfulAuth);

        // Mocks for token generation (void methods, no 'when' needed unless checking args)
        // doNothing().when(tokenService).generateAccessToken(anyString(), any(HttpServletResponse.class));
        // doNothing().when(tokenService).generateRefreshToken(anyString(), any(HttpServletResponse.class));

        // Act
        String loggedInUsername = authenticationService.login(loginRequest, httpServletResponse);

        // Assert
        assertEquals(loginRequest.getEmail(), loggedInUsername);

        // Verify AuthenticationManager was called with unauthenticated token
        ArgumentCaptor<UsernamePasswordAuthenticationToken> authCaptor =
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        verify(authenticationManager).authenticate(authCaptor.capture());
        UsernamePasswordAuthenticationToken capturedAuthRequest = authCaptor.getValue();
        assertEquals(loginRequest.getEmail(), capturedAuthRequest.getName());
        assertEquals(loginRequest.getPassword(), capturedAuthRequest.getCredentials());
        assertFalse(capturedAuthRequest.isAuthenticated()); // Ensure it was unauthenticated initially

        // Verify token generation methods were called
        verify(tokenService).generateAccessToken(loginRequest.getEmail(), httpServletResponse);
        verify(tokenService).generateRefreshToken(loginRequest.getEmail(), httpServletResponse);
    }

    @Test
    void login_shouldThrowException_whenCredentialsAreInvalid() {
        // Arrange
        // Mock AuthenticationManager to throw an exception for bad credentials
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // Act & Assert
        assertThrows(BadCredentialsException.class, () -> {
            authenticationService.login(loginRequest, httpServletResponse);
        });

        // Verify token generation methods were NOT called
        verify(tokenService, never()).generateAccessToken(anyString(), any(HttpServletResponse.class));
        verify(tokenService, never()).generateRefreshToken(anyString(), any(HttpServletResponse.class));
    }

    // --- logoutUser Tests ---
    @Test
    void logoutUser_shouldCallTokenServiceToRemoveTokens() {
        // Arrange (no specific arrangement needed as methods are void)

        // Act
        authenticationService.logoutUser(httpServletResponse);

        // Assert
        verify(tokenService).removeAccessTokenFromCookie(httpServletResponse);
        verify(tokenService).removeRefreshTokenFromCookieAndExpire(httpServletResponse);
    }

    // --- refreshToken Tests ---
    @Test
    void refreshToken_shouldReturnEmailAndGenerateAccessToken_whenTokenIsValid() {
        // Arrange
        String expectedEmail = "test@example.com";
        String validRefreshToken = "valid-refresh-token";

        when(tokenService.getRefreshTokenFromCookie(httpServletRequest)).thenReturn(validRefreshToken);
        when(tokenService.renewRefreshToken(validRefreshToken, httpServletResponse)).thenReturn(expectedEmail);
        // No need to mock generateAccessToken as it's void, we just verify it

        // Act
        String actualEmail = authenticationService.refreshToken(httpServletRequest, httpServletResponse);

        // Assert
        assertEquals(expectedEmail, actualEmail);
        verify(tokenService).getRefreshTokenFromCookie(httpServletRequest);
        verify(tokenService).renewRefreshToken(validRefreshToken, httpServletResponse);
        verify(tokenService).generateAccessToken(expectedEmail, httpServletResponse);
    }

    @Test
    void refreshToken_shouldThrowAccessDeniedException_whenTokenIsInvalid() {
        // Arrange
        String invalidRefreshToken = "invalid-refresh-token";

        when(tokenService.getRefreshTokenFromCookie(httpServletRequest)).thenReturn(invalidRefreshToken);
        // Mock renewRefreshToken to throw the exception caught in the service method
        when(tokenService.renewRefreshToken(invalidRefreshToken, httpServletResponse))
                .thenThrow(new IllegalArgumentException("Token invalid"));

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            authenticationService.refreshToken(httpServletRequest, httpServletResponse);
        });

        assertEquals("Invalid refresh token.",
                exception.getMessage());
        verify(tokenService).getRefreshTokenFromCookie(httpServletRequest);
        verify(tokenService).renewRefreshToken(invalidRefreshToken, httpServletResponse);
        // Verify generateAccessToken was NOT called in the failure case
        verify(tokenService, never()).generateAccessToken(anyString(), any(HttpServletResponse.class));
    }
}