package com.podzilla.auth.dto;

import java.util.UUID;

public record AuthenticationResponse(String email, UUID refreshToken) {
}
