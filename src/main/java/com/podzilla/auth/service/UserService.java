package com.podzilla.auth.service;

import com.podzilla.auth.dto.CustomUserDetails;
import com.podzilla.auth.dto.UpdateRequest;
import com.podzilla.auth.dto.UserDetailsRequest;
import com.podzilla.auth.exception.NotFoundException;
import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.Address;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.AddressRepository;
import com.podzilla.auth.repository.UserRepository;
import com.podzilla.mq.events.DeliveryAddress;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final AddressRepository addressRepository;

    public UserService(final UserRepository userRepository,
                       final AddressRepository addressRepository) {
        this.userRepository = userRepository;
        this.addressRepository = addressRepository;
    }


    @Transactional
    public void updateUserProfile(final UpdateRequest updateRequest) {
        LOGGER.debug("Updating user profile");
        CustomUserDetails customUserDetails =
                AuthenticationService.getCurrentUserDetails();
        if (updateRequest.getName() != null
                && !updateRequest.getName().isBlank()) {
            User user = getUserOrThrow(customUserDetails.getId());
            LOGGER.debug("Updating user with id={}", user.getId());
            user.setName(updateRequest.getName());
            userRepository.save(user);
        }
        if (updateRequest.getMobileNumber() != null
                && !updateRequest.getMobileNumber().isBlank()
                && mobileNumberIsUnique(updateRequest.getMobileNumber())) {
            User user = getUserOrThrow(customUserDetails.getId());
            LOGGER.debug("Updating mobile number for user with id={}",
                    user.getId());
            user.setMobileNumber(updateRequest.getMobileNumber());
            userRepository.save(user);
        }
        if (updateRequest.getAddress() != null
                && isValidAddress(updateRequest.getAddress())) {
            Address address = getAddressOrThrow(
                    customUserDetails.getId());
            LOGGER.debug("Updating address for user with id={}",
                    address.getUser().getId());
            address.setStreet(updateRequest.getAddress().getStreet());
            address.setCity(updateRequest.getAddress().getCity());
            address.setState(updateRequest.getAddress().getState());
            address.setCountry(updateRequest.getAddress().getCountry());
            address.setPostalCode(updateRequest.getAddress()
                    .getPostalCode());
            addressRepository.save(address);
        }
    }

    public UserDetailsRequest getUserDetails() {
        CustomUserDetails customUserDetails =
                AuthenticationService.getCurrentUserDetails();
        LOGGER.debug("Fetching user details for user with id={}",
                customUserDetails.getId());
        User user = getUserOrThrow(customUserDetails.getId());
        DeliveryAddress address = new DeliveryAddress();
        address.setStreet(user.getAddress().getStreet());
        address.setCity(user.getAddress().getCity());
        address.setState(user.getAddress().getState());
        address.setCountry(user.getAddress().getCountry());
        address.setPostalCode(user.getAddress().getPostalCode());
        return UserDetailsRequest.builder()
                .name(user.getName())
                .email(user.getEmail())
                .mobileNumber(user.getMobileNumber())
                .address(address)
                .build();
    }

    private boolean isValidAddress(final DeliveryAddress address) {
        if (address.getStreet() == null || address.getStreet().isBlank()) {
            throw new ValidationException("Street is required");
        }
        if (address.getCity() == null || address.getCity().isBlank()) {
            throw new ValidationException("City is required");
        }
        if (address.getState() == null || address.getState().isBlank()) {
            throw new ValidationException("State is required");
        }
        if (address.getCountry() == null || address.getCountry().isBlank()) {
            throw new ValidationException("Country is required");
        }
        if (address.getPostalCode() == null
                || address.getPostalCode().isBlank()) {
            throw new ValidationException("Postal code is required");
        }
        return true;
    }

    private boolean mobileNumberIsUnique(final String mobileNumber) {
        if (userRepository.existsByMobileNumber(mobileNumber)) {
            throw new ValidationException("Mobile number already exists");
        }
        return true;
    }

    public User getUserOrThrow(final UUID userId) {
        LOGGER.debug("Fetching user with id={}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> {
                    LOGGER.warn("User not found with id={}", userId);
                    return new NotFoundException("User with id "
                            + userId + " does not exist.");
                });
    }

    public Address getAddressOrThrow(final UUID userId) {
        LOGGER.debug("Fetching address for user with id={}", userId);
        return addressRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    LOGGER.warn("Address not found for user with id={}",
                            userId);
                    return new NotFoundException("Address for user with id "
                            + userId + " does not exist.");
                });
    }
}
