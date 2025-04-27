package com.podzilla.auth.controller;

import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final SecurityContextLogoutHandler logoutHandler =
            new SecurityContextLogoutHandler();

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    public AuthenticationController(
            final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody final LoginRequest loginRequest,
            final HttpServletResponse response) {
        try {
            String email = authenticationService.login(loginRequest, response);
            LOGGER.info("User {} logged in", email);
            return new ResponseEntity<>(
                    "User " + email + "logged in successfully",
                    HttpStatus.OK);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(
            @RequestBody final SignupRequest signupRequest,
            final HttpServletRequest request) {
        try {
            authenticationService.registerAccount(signupRequest);
            LOGGER.info("User {} registered", signupRequest.getEmail());
            return new ResponseEntity<>("Account registered.",
                    HttpStatus.CREATED);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(final HttpServletResponse response) {
        authenticationService.logoutUser(response);
        return new ResponseEntity<>("You've been signed out!", HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(
            final HttpServletRequest request,
            final HttpServletResponse response) {
        try {
            String email = authenticationService.refreshToken(
                    request, response);
            LOGGER.info("User {} refreshed token", email);
            return new ResponseEntity<>(
                    "User " + email + "refreshed token successfully",
                    HttpStatus.OK);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }
}
