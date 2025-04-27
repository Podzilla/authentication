package com.podzilla.auth.service;

import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletResponse;
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
    private final JWTService jwtService;
    private final RoleRepository roleRepository;

    public AuthenticationService(
            final AuthenticationManager authenticationManager,
            final PasswordEncoder passwordEncoder,
            final UserRepository userRepository,
            final JWTService jwtService,
            final RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
    }

    public String login(final LoginRequest loginRequest,
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
        return userDetails.getUsername();
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

    public void logoutUser(final HttpServletResponse response) {
        jwtService.removeTokenFromCookie(response);
    }
}
