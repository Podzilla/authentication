package com.podzilla.auth.controller;

import com.podzilla.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PutMapping("/update/{userId}")
    @Operation(summary = "Update user name",
            description = "Allows user to update their name.")
    @ApiResponse(responseCode = "200",
            description = "User profile updated successfully")
    public void updateProfile(@PathVariable final Long userId,
                              @Valid @RequestBody final String name) {
        logger.debug("Received updateProfile request for userId={}", userId);
        userService.updateUserProfile(userId, name);
    }
}
