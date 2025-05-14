package com.podzilla.auth.dto;

import com.podzilla.mq.events.DeliveryAddress;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateRequest {

    @NotBlank(message = "Name is required")
    private String name;

    @Valid
    private DeliveryAddress address;

    @NotBlank(message = "Mobile Number is required")
    private String mobileNumber;
}
