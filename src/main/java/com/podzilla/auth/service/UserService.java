package com.podzilla.auth.service;

import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Transactional
    public void updateUserProfile(final UUID userId, final String name) {
        User user = getUserOrThrow(userId);
        LOGGER.debug("Updating name for userId={}", userId);
        user.setName(name);
        userRepository.save(user);
        LOGGER.debug("User profile updated successfully for userId={}", userId);
    }


    public User getUserOrThrow(final UUID userId) {
        LOGGER.debug("Fetching user with id={}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> {
                    LOGGER.warn("User not found with id={}", userId);
                    return new NotFoundException("User with id "
                            + userId + " does not exist.");
                });
    }
}
