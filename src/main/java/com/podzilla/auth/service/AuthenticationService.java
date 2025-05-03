package com.podzilla.auth.service;

import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.exception.InvalidActionException;
import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final RoleRepository roleRepository;

    public AuthenticationService(
            final AuthenticationManager authenticationManager,
            final PasswordEncoder passwordEncoder,
            final UserRepository userRepository,
            final TokenService tokenService,
            final RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.roleRepository = roleRepository;
    }

    public String login(final LoginRequest loginRequest,
                        final HttpServletResponse response) {

        if (SecurityContextHolder.getContext().getAuthentication()
                instanceof UsernamePasswordAuthenticationToken) {
            throw new InvalidActionException("User already logged in.");
        }

        Authentication authenticationRequest =
                UsernamePasswordAuthenticationToken.
                        unauthenticated(
                                loginRequest.getEmail(),
                                loginRequest.getPassword());
        Authentication authenticationResponse =
                this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().
                setAuthentication(authenticationResponse);
        tokenService.generateAccessToken(loginRequest.getEmail(), response);
        tokenService.generateRefreshToken(loginRequest.getEmail(), response);
        UserDetails userDetails =
                (UserDetails) authenticationResponse.getPrincipal();

        return userDetails.getUsername();
    }

    public void registerAccount(final SignupRequest signupRequest) {
        checkNotNullValidationException(signupRequest,
                "Signup request cannot be null.");
        checkNotNullValidationException(signupRequest.getEmail(),
                "Email cannot be null.");
        checkNotNullValidationException(signupRequest.getPassword(),
                "Password cannot be null.");
        checkNotNullValidationException(signupRequest.getName(),
                "Name cannot be null.");

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new ValidationException("Email already in use.");
        }

        User account =
                User.builder()
                        .name(signupRequest.getName())
                        .email(signupRequest.getEmail())
                        .password(
                                passwordEncoder.encode(
                                        signupRequest.getPassword()))
                        .build();
        Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(null);

        checkNotNullValidationException(role, "Role_USER not found.");

        account.setRoles(Collections.singleton(role));
        userRepository.save(account);
    }

    public void logoutUser(
            final HttpServletResponse response) {
        tokenService.removeAccessTokenFromCookie(response);
        tokenService.removeRefreshTokenFromCookieAndExpire(response);
    }

    public String refreshToken(final HttpServletRequest request,
                               final HttpServletResponse response) {
        try {
            String refreshToken =
                    tokenService.getRefreshTokenFromCookie(request);
            checkNotNullAccessDeniedException(refreshToken,
                    "Refresh token cannot be found.");
            String email =
                    tokenService.renewRefreshToken(refreshToken, response);
            tokenService.generateAccessToken(email, response);
            return email;
        } catch (IllegalArgumentException e) {
            throw new AccessDeniedException("Invalid refresh token.");
        }
    }

    private void checkNotNullValidationException(final String value,
                                                final String message) {
        if (value == null || value.isEmpty()) {
            throw new ValidationException(message);
        }
    }

    private void checkNotNullValidationException(final Object value,
                                                final String message) {
        if (value == null) {
            throw new ValidationException(message);
        }
    }

    private void checkNotNullAccessDeniedException(final Object value,
                                                  final String message) {
        if (value == null) {
            throw new AccessDeniedException(message);
        }
    }
}
