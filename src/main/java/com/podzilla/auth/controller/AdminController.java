package com.podzilla.auth.controller;

import com.podzilla.auth.model.User;
import com.podzilla.auth.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AdminService adminService;
    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    public AdminController(final AdminService adminService) {
        this.adminService = adminService;
    }

    @GetMapping("/users")
    @Operation(summary = "Get all users",
            description = "Fetches all users in the system.")
    @ApiResponse(responseCode = "200",
            description = "Users fetched successfully")
    public List<User> getUsers() {
        return adminService.getUsers();
    }

    @PatchMapping("/users/{userId}/activate")
    @Operation(summary = "Activate or deactivate a user",
            description = "Allows an admin to activate or deactivate a specific user.")
    @ApiResponse(responseCode = "200",
            description = "User activation status updated successfully")
    public void updateUserActivation(
            @Parameter(description = "ID of the user to activate/deactivate")
            @PathVariable Long userId,

            @Parameter(description = "Set to true to activate, false to deactivate the user")
            @RequestParam boolean isActive) {

        logger.debug("Admin requested to update activation status for userId={} to isActive={}", userId, isActive);
        adminService.updateUserActivation(userId, isActive);
    }
}
