package com.podzilla.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import io.jsonwebtoken.lang.Collections;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Sql(statements = {
        "INSERT INTO roles (id, erole) VALUES (1, 'ROLE_USER'), (2, 'ROLE_ADMIN')",
}, executionPhase = Sql.ExecutionPhase.BEFORE_TEST_CLASS)
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    private User user1;
    private User user2;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll(); // Clean slate before each test

        Role adminRole = new Role();
        adminRole.setId(2L);
        adminRole.setErole(ERole.ROLE_ADMIN);

        Role userRole = new Role();
        userRole.setId(1L);
        userRole.setErole(ERole.ROLE_USER);

        user1 = new User();
        user1.setEmail("adminUser");
        user1.setPassword(passwordEncoder.encode("password"));
        user1.setRoles(Collections.setOf(adminRole));
        user1.setEmail("admin@example.com");

        user2 = new User();
        user2.setEmail("normalUser");
        user2.setPassword(passwordEncoder.encode("password"));
        user2.setRoles(Collections.setOf(userRole));
        user2.setEmail("user@example.com");

        userRepository.saveAll(Arrays.asList(user1, user2));
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll(); // Clean up after each test
    }

    @Test
    @WithMockUser(authorities = "ROLE_ADMIN")
    void getUsers_shouldReturnListOfUsers_whenUserIsAdmin() throws Exception {
        List<User> expectedUsers = Arrays.asList(user1, user2);

        mockMvc.perform(get("/admin/users")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].name", is(user1.getName())))
                .andExpect(jsonPath("$[0].email", is(user1.getEmail())))
                .andExpect(jsonPath("$[0].password", is(user1.getPassword())))
                .andExpect(jsonPath("$[1].name", is(user2.getName())))
                .andExpect(jsonPath("$[1].email", is(user2.getEmail())))
                .andExpect(jsonPath("$[1].password", is(user2.getPassword())));
    }

    @Test
    @WithMockUser(roles = "USER") // Simulate an authenticated user with USER role
    void getUsers_shouldReturnForbidden_whenUserIsNotAdmin() throws Exception {
        mockMvc.perform(get("/admin/users")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void getUsers_shouldReturnUnauthorized_whenUserIsNotAuthenticated() throws Exception {
        mockMvc.perform(get("/admin/users")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }
}
