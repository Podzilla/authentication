package com.podzilla.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserDetailsRequest {
    private String email;
    private String name;
    private String mobileNumber;
    private DeliveryAddress address;
}
