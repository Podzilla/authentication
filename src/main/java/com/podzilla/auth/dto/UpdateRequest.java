package com.podzilla.auth.dto;

import com.podzilla.mq.events.DeliveryAddress;
import lombok.Data;

@Data
public class UpdateRequest {
    private String name;
    private DeliveryAddress address;
    private String mobileNumber;
}
