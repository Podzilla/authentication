package com.podzilla.auth.controller;

import com.podzilla.auth.dto.UpdateRequest;
import com.podzilla.auth.dto.UserDetailsRequest;
import com.podzilla.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/user")
public class UserController {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    public UserController(final UserService userService) {
        this.userService = userService;
    }

    @PutMapping("/update")
    @Operation(summary = "Update user name",
            description = "Allows user to update their name.")
    @ApiResponse(responseCode = "200",
            description = "User profile updated successfully")
    public void updateProfile(@Valid @RequestBody final UpdateRequest
                                      updateRequest) {
        LOGGER.debug("Received updateProfile request");
        userService.updateUserProfile(updateRequest);
    }

    @GetMapping("/details")
    @Operation(summary = "Get user details",
            description = "Fetches the details of the current user.")
    @ApiResponse(responseCode = "200",
            description = "User details fetched successfully")
    public UserDetailsRequest getUserDetails() {
        LOGGER.debug("Received getUserDetails request");
        return userService.getUserDetails();
    }
}
