package com.podzilla.auth.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeliveryAddress implements Serializable {

    private static final long serialVersionUID = 1L;

    private String street;
    private String city;
    private String state;
    private String country;
    private String postalCode;
}