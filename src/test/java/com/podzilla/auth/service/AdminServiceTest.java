package com.podzilla.auth.service;

import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AdminService adminService;

    @Test
    void getUsers_shouldReturnListOfUsers() {
        User user1 = User.builder().id(UUID.randomUUID()).email("user1@example.com").name("User One").build();
        User user2 = User.builder().id(UUID.randomUUID()).email("user2@example.com").name("User Two").build();
        List<User> expectedUsers = Arrays.asList(user1, user2);

        when(userRepository.findAll()).thenReturn(expectedUsers);

        List<User> actualUsers = adminService.getUsers();

        assertEquals(expectedUsers.size(), actualUsers.size());
        assertEquals(expectedUsers, actualUsers);

        verify(userRepository).findAll();
    }

    @Test
    void updateUserActivation_shouldActivateUserSuccessfully() {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("user@example.com")
                .name("Test User")
                .enabled(false)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        adminService.updateUserActivation(userId, true);

        verify(userRepository).findById(userId);
        verify(userRepository).save(user);
    }

    @Test
    void updateUserActivation_shouldDeactivateUserSuccessfully() {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("user@example.com")
                .name("Test User")
                .enabled(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        adminService.updateUserActivation(userId, false);

        verify(userRepository).findById(userId);
        verify(userRepository).save(user);
    }


    @Test
    void deleteUser_shouldDeleteUserSuccessfully() {
        UUID userId = UUID.randomUUID();

        when(userRepository.existsById(userId)).thenReturn(true);

        adminService.deleteUser(userId);

        verify(userRepository).existsById(userId);
        verify(userRepository).deleteById(userId);
    }
    
}