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
        User user1 = User.builder().id(1L).email("user1@example.com").name("User One").build();
        User user2 = User.builder().id(2L).email("user2@example.com").name("User Two").build();
        List<User> expectedUsers = Arrays.asList(user1, user2);

        when(userRepository.findAll()).thenReturn(expectedUsers);

        List<User> actualUsers = adminService.getUsers();

        assertEquals(expectedUsers.size(), actualUsers.size());
        assertEquals(expectedUsers, actualUsers);

        verify(userRepository).findAll();
    }
}