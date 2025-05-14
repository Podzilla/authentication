package com.podzilla.auth.service;

import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;


import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    private UUID userId;
    private User existingUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        existingUser = User.builder()
                .id(userId)
                .name("Old Name")
                .email("old@example.com")
                .build();
    }

    @Test
    void updateUserProfile_shouldUpdateName_whenUserExists() {
        // Arrange
        String newName = "New Name";
        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));

        // Act
        userService.updateUserProfile(userId, newName);

        // Assert
        verify(userRepository).findById(userId);


        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertEquals(newName, savedUser.getName());
        assertEquals(userId, savedUser.getId());
    }

    @Test
    void updateUserProfile_shouldThrowNotFoundException_whenUserDoesNotExist() {
        // Arrange
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> {
            userService.updateUserProfile(userId, "New Name");
        });

        assertEquals("Not Found: User with id " + userId + " does not exist.", exception.getMessage());
        verify(userRepository).findById(userId);
        verify(userRepository, never()).save(any(User.class));
    }


}