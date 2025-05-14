package com.podzilla.auth.controller;

import com.podzilla.auth.dto.AddCourierRequest;
import com.podzilla.auth.model.User;
import com.podzilla.auth.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AdminService adminService;
    private static final Logger LOGGER =
            LoggerFactory.getLogger(AdminController.class);

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
            description = "Allows an admin to activate"
                    + " or deactivate a specific user.")
    @ApiResponse(responseCode = "200",
            description = "User activation status updated successfully")
    public void updateUserActivation(
            @Parameter(description = "ID of the user to activate/deactivate")
            @PathVariable final UUID userId,

            @Parameter(description = "Set to true to activate,"
                    + " false to deactivate the user")
            @RequestParam final boolean isActive) {

        LOGGER.debug("Admin requested to update activation status for "
                + "userId={}"
                + " to isActive={}", userId, isActive);
        adminService.updateUserActivation(userId, isActive);
    }


    @DeleteMapping("/users/{userId}")
    @Operation(summary = "Delete a user",
            description = "Allows an admin to delete a specific user account.")
    @ApiResponse(responseCode = "200",
            description = "User deleted successfully")
    public void deleteUser(
            @Parameter(description = "ID of the user to delete")
            @PathVariable final UUID userId) {

        LOGGER.debug("Admin requested to delete user with userId={}", userId);
        adminService.deleteUser(userId);
    }

    @PostMapping("/courier")
    @Operation(summary = "Add a new courier",
            description = "Allows an admin to add a new courier to the system.")
    @ApiResponse(responseCode = "200",
            description = "Courier added successfully")
    public void addCourier(
            @Parameter(description = "Courier details")
            @RequestBody final AddCourierRequest addCourierRequest) {

        LOGGER.debug("Admin requested to add a new courier with details={}",
                addCourierRequest);
        adminService.addCourier(addCourierRequest);
    }
}
