package com.podzilla.auth.controller;

import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    public AuthenticationController(
            final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    @Operation(
            summary = "Login",
            description = "Logs in a user and generates JWT tokens."
    )
    @ApiResponse(
            responseCode = "200",
            description = "User logged in successfully"
    )
    public ResponseEntity<?> login(
            @RequestBody final LoginRequest loginRequest,
            final HttpServletResponse response) {
        String email = authenticationService.login(loginRequest, response);
        LOGGER.info("User {} logged in", email);
        return new ResponseEntity<>(
                "User " + email + " logged in successfully",
                HttpStatus.OK);
    }

    @PostMapping("/register")
    @Operation(
            summary = "Register",
            description = "Registers a new user."
    )
    @ApiResponse(
            responseCode = "201",
            description = "User registered successfully"
    )
    public ResponseEntity<?> registerUser(
            @RequestBody final SignupRequest signupRequest) {
        authenticationService.registerAccount(signupRequest);
        LOGGER.info("User {} registered", signupRequest.getEmail());
        return new ResponseEntity<>("Account registered.",
                HttpStatus.CREATED);
    }

    @PostMapping("/logout")
    @Operation(
            summary = "Logout",
            description = "Logs out a user and invalidates JWT tokens."
    )
    @ApiResponse(
            responseCode = "200",
            description = "User logged out successfully"
    )
    public ResponseEntity<?> logoutUser(final HttpServletResponse response) {
        authenticationService.logoutUser(response);
        return new ResponseEntity<>("You've been signed out!", HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    @Operation(
            summary = "Refresh Token",
            description = "Refreshes the JWT tokens for a logged-in user."
    )
    @ApiResponse(
            responseCode = "200",
            description = "Token refreshed successfully"
    )
    public ResponseEntity<?> refreshToken(
            final HttpServletRequest request,
            final HttpServletResponse response) {
        String email = authenticationService.refreshToken(
                request, response);
        LOGGER.info("User {} refreshed token", email);
        return new ResponseEntity<>(
                "User " + email + " refreshed tokens successfully",
                HttpStatus.OK);
    }

    @GetMapping("/me")
    @Operation(
            summary = "Get Current User",
            description = "Fetches the details of the currently logged-in user."
    )
    @ApiResponse(
            responseCode = "200",
            description = "User details fetched successfully"
    )
    public UserDetails getCurrentUser() {
        UserDetails userDetails = authenticationService.getCurrentUserDetails();
        LOGGER.info("Fetched details for user {}", userDetails.getUsername());
        return userDetails;
    }
}
