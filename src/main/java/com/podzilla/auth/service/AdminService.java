package com.podzilla.auth.service;

import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminService.class);

    private final UserRepository userRepository;

    public AdminService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void updateUserActivation(final Long userId, final boolean isActive) {
        logger.debug("Fetching user with id={}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    logger.warn("User not found with id={}", userId);
                    return new NotFoundException("User with id " + userId + " does not exist.");
                });

        logger.debug("Updating isActive status for userId={} from {} to {}", userId, user.getIsActive(), isActive);
        user.setIsActive(isActive);
        userRepository.save(user);
        logger.debug("User activation status updated successfully for userId={}", userId);
    }
}
