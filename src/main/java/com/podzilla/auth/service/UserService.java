package com.podzilla.auth.service;

import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    public User getUserOrThrow(final Long userId) {
        logger.debug("Fetching user with id={}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> {
                    logger.warn("User not found with id={}", userId);
                    return new NotFoundException("User with id " + userId + " does not exist.");
                });
    }
}
