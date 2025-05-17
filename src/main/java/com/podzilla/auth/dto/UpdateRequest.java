package com.podzilla.auth.dto;

import lombok.Data;

@Data
public class UpdateRequest {
    private String name;
    private DeliveryAddress address;
    private String mobileNumber;
}
