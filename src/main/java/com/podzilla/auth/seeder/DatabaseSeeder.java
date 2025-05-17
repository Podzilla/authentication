package com.podzilla.auth.seeder;

import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.repository.AddressRepository;
import com.podzilla.auth.repository.RefreshTokenRepository;
import com.podzilla.auth.repository.RoleRepository;
import com.podzilla.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DatabaseSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final AddressRepository addressRepository;

    public DatabaseSeeder(final RoleRepository roleRepository,
                          final RefreshTokenRepository refreshTokenRepository,
                          final UserRepository userRepository,
                          final AddressRepository addressRepository) {
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.addressRepository = addressRepository;
    }

    @Override
    public void run(final String... args) throws Exception {
        userRepository.findAll().forEach(user -> {
            user.getRoles().clear();
            userRepository.save(user);
        });
        userRepository.deleteAll();
        roleRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        addressRepository.deleteAll();
        roleRepository.save(new Role(ERole.ROLE_USER));
        roleRepository.save(new Role(ERole.ROLE_ADMIN));
        roleRepository.save(new Role(ERole.ROLE_COURIER));
    }
}
