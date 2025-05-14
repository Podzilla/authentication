package com.podzilla.auth.dto;

import com.podzilla.mq.events.DeliveryAddress;
import lombok.Builder;

@Builder
public class UserDetailsRequest {
    private String email;
    private String name;
    private String mobileNumber;
    private DeliveryAddress address;
}
