package com.podzilla.auth.service;

import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AdminService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AdminService.class);

    private final UserRepository userRepository;
    private final UserService userService;

    public AdminService(final UserRepository userRepository,
                        final UserService userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void updateUserActivation(final Long userId,
                                     final boolean isActive) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Updating isActive status for userId={} "
                + "from {} to {}", userId, user.getEnabled(), isActive);
        user.setEnabled(isActive);
        userRepository.save(user);
        LOGGER.debug("User activation status updated "
                + "successfully for userId={}", userId);
    }


    @Transactional
    public void deleteUser(final Long userId) {
        User user = userService.getUserOrThrow(userId);
        LOGGER.debug("Deleting user with userId={}", userId);
        userRepository.delete(user);
        LOGGER.debug("User deleted successfully with userId={}", userId);
    }
}
