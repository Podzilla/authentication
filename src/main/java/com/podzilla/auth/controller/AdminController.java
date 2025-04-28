package com.podzilla.auth.controller;

import com.podzilla.auth.model.User;
import com.podzilla.auth.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;

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

}
