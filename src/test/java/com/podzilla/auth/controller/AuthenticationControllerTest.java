package com.podzilla.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.model.Address;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.AddressRepository;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import com.podzilla.auth.service.TokenService; // Assuming you have a JwtService
import com.podzilla.mq.events.DeliveryAddress;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository; // Inject RoleRepository

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TokenService tokenService;

    private final String testUserEmail = "testuser@example.com";
    private final String testUserPassword = "password123";

    @BeforeEach
    void setUp() {
        roleRepository.deleteAll();
        userRepository.deleteAll(); // Clean slate before each test

        Role adminRole = new Role();
        adminRole.setErole(ERole.ROLE_ADMIN);
        roleRepository.save(adminRole);

        Role userRole = new Role();
        userRole.setErole(ERole.ROLE_USER);
        roleRepository.save(userRole);

        Address address = new Address();
        address.setStreet("123 Test St");
        address.setCity("Test City");
        address.setState("Test State");
        address.setCountry("Test Country");
        address.setPostalCode("12345");

        // Create a pre-existing user for login tests
        User user = new User();
        user.setEmail(testUserEmail);
        user.setPassword(passwordEncoder.encode(testUserPassword));
        user.setName("Test User"); // Assuming name is required or desired
        user.setMobileNumber("1234567890");
        user.setAddress(address);
        address.setUser(user);
        user.getRoles().add(userRole);
        userRepository.save(user);
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll(); // Clean up after each test
        roleRepository.deleteAll();
    }

    @Test
    void registerUser_shouldCreateNewUser_whenEmailIsNotTaken() throws Exception {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("newuser@example.com");
        signupRequest.setPassword("newpassword");
        signupRequest.setName("New User");
        signupRequest.setMobileNumber("1234562137890");
        signupRequest.setAddress(new DeliveryAddress("456 New St", "New City",
                "New State", "New Country", "54321"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated())
                .andExpect(content().string("Account registered."));

        // Verify user exists in the database
        Optional<User> registeredUser = userRepository.findByEmail("newuser@example.com");
        assertTrue(registeredUser.isPresent());
        assertEquals("New User", registeredUser.get().getName());
        assertTrue(passwordEncoder.matches("newpassword", registeredUser.get().getPassword()));
        // Verify role assignment if applicable (assuming default role is USER)
        assertTrue(registeredUser.get().getRoles().stream()
                .anyMatch(role -> role.getErole() == ERole.ROLE_USER));
    }

    @Test
    void registerUser_shouldReturnBadRequest_whenEmailIsTaken() throws Exception {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail(testUserEmail); // Email already exists from setup
        signupRequest.setPassword("anotherpassword");
        signupRequest.setName("Another User");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                // Assuming AuthenticationService throws an exception leading to 4xx
                // Adjust status code based on actual exception handling (e.g., 400 Bad Request or 409 Conflict)
                .andExpect(status().isBadRequest()); // Or Conflict (409) depending on implementation
    }


    @Test
    void login_shouldReturnOkAndSetCookies_whenCredentialsAreValid() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(testUserEmail);
        loginRequest.setPassword(testUserPassword);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User " + testUserEmail + " logged in successfully"))
                .andExpect(cookie().exists("accessToken")) // Check if cookies are set
                .andExpect(cookie().exists("refreshToken"));
        // Add more specific cookie checks if needed (e.g., HttpOnly, Secure, MaxAge)
        // .andExpect(cookie().httpOnly("accessToken", true))
        // .andExpect(cookie().maxAge("accessToken", expectedMaxAge));
    }

    @Test
    void login_shouldReturnUnauthorized_whenCredentialsAreInvalid() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(testUserEmail);
        loginRequest.setPassword("wrongpassword");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized()); // Standard Spring Security behavior
    }

    @Test
    void logoutUser_shouldClearCookiesAndReturnOk() throws Exception {
        // First, log in to get cookies
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(testUserEmail);
        loginRequest.setPassword(testUserPassword);

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie accessTokenCookie = loginResult.getResponse().getCookie("accessToken");
        Cookie refreshTokenCookie = loginResult.getResponse().getCookie("refreshToken");

        assertNotNull(accessTokenCookie);
        assertNotNull(refreshTokenCookie);

        // Perform logout using the obtained cookies
        mockMvc.perform(post("/auth/logout")
                        .cookie(accessTokenCookie) // Send cookies back
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(content().string("You've been signed out!"))
                // Check that cookies are cleared (Max-Age=0)
                .andExpect(cookie().value("accessToken", (String) null))
                .andExpect(cookie().value("refreshToken", (String) null));
    }

    @Test
    void refreshToken_shouldReturnOkAndNewTokens_whenRefreshTokenIsValid() throws Exception {
        // 1. Login to get initial tokens
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(testUserEmail);
        loginRequest.setPassword(testUserPassword);

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie initialAccessToken = loginResult.getResponse().getCookie("accessToken");
        Cookie initialRefreshToken = loginResult.getResponse().getCookie("refreshToken");
        assertNotNull(initialRefreshToken);
        assertNotNull(initialAccessToken);
        assertNotEquals(0, initialRefreshToken.getMaxAge()); // Ensure it's not already expired

        Thread.sleep(3000);

        // 2. Use the refresh token to get new tokens
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh-token")
                        .cookie(initialRefreshToken)) // Send only the refresh token
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("refreshed tokens successfully")))
                .andExpect(cookie().exists("accessToken"))
                .andExpect(cookie().exists("refreshToken"))
                .andReturn();

        // 3. Verify new tokens are different from old ones
        Cookie newAccessToken = refreshResult.getResponse().getCookie("accessToken");
        Cookie newRefreshToken = refreshResult.getResponse().getCookie("refreshToken");

        assertNotNull(newAccessToken);
        assertNotNull(newRefreshToken);
        assertNotEquals(initialAccessToken.getValue(), newAccessToken.getValue());
        // Depending on your implementation, the refresh token might also be rotated
        // assertNotEquals(initialRefreshToken.getValue(), newRefreshToken.getValue());

        // Optional: Verify the expiry/max-age of the new cookies
        assertNotEquals(0, newAccessToken.getMaxAge());
        assertNotEquals(0, newRefreshToken.getMaxAge());
    }

    @Test
    void refreshToken_shouldReturnUnauthorized_whenRefreshTokenIsMissingOrInvalid() throws Exception {
        // Test without sending any cookie
        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isForbidden());
        // Test with an invalid/expired cookie
        Cookie invalidCookie = new Cookie("refreshToken", "invalid-or-expired-token-value");
        invalidCookie.setPath("/"); // Set path and other relevant attributes if needed

        mockMvc.perform(post("/auth/refresh-token")
                        .cookie(invalidCookie))
                .andExpect(status().isForbidden());
    }
}