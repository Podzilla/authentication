package com.podzilla.auth.service;

import com.podzilla.auth.dto.AuthenticationResponse;
import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.RefreshToken;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RefreshTokenRepository;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ValidationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Collections;
import java.util.UUID;


@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private static final TemporalAmount EXPIRES_IN =
            java.time.Duration.ofDays(10);

    public AuthenticationService(
            final AuthenticationManager authenticationManager,
            final PasswordEncoder passwordEncoder,
            final UserRepository userRepository,
            final JWTService jwtService,
            final RoleRepository roleRepository,
            final RefreshTokenRepository refreshTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public AuthenticationResponse login(final LoginRequest loginRequest,
                                        final HttpServletResponse response) {

        Authentication authenticationRequest =
                UsernamePasswordAuthenticationToken.
                        unauthenticated(
                                loginRequest.getEmail(),
                                loginRequest.getPassword());
        Authentication authenticationResponse =
                this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().
                setAuthentication(authenticationResponse);
        jwtService.generateToken(loginRequest.getEmail(), response);
        UserDetails userDetails =
                (UserDetails) authenticationResponse.getPrincipal();

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new EntityExistsException("User not found"));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiresAt(Instant.now().plus(EXPIRES_IN));
        refreshTokenRepository.save(refreshToken);

        return new AuthenticationResponse(userDetails.getUsername(),
                refreshToken.getId());
    }

    public void registerAccount(final SignupRequest signupRequest) {
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new EntityExistsException("Email already used");
        }

        User account = new User(
                signupRequest.getName(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword()));
        Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(null);
        account.setRoles(Collections.singleton(role));
        userRepository.save(account);
    }

    public void logoutUser(final UUID refreshToken,
                           final HttpServletResponse response) {
        jwtService.removeTokenFromCookie(response);
        refreshTokenRepository.deleteById(refreshToken);
    }

    public AuthenticationResponse refreshToken(
            final UUID refreshToken,
            final HttpServletResponse response) {
        final var refreshTokenEntity = refreshTokenRepository
                .findByIdAndExpiresAtAfter(refreshToken, Instant.now())
                .orElseThrow(() ->
                        new ValidationException("Invalid refresh token"));

        refreshTokenEntity.setExpiresAt(Instant.now());
        refreshTokenRepository.save(refreshTokenEntity);

        final RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setUser(refreshTokenEntity.getUser());
        newRefreshToken.setExpiresAt(Instant.now().plus(EXPIRES_IN));
        refreshTokenRepository.save(newRefreshToken);

        jwtService.generateToken(
                refreshTokenEntity.getUser().getEmail(), response);
        return new AuthenticationResponse(
                refreshTokenEntity.getUser().getEmail(),
                newRefreshToken.getId());
    }
}
