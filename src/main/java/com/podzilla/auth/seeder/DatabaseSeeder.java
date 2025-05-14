package com.podzilla.auth.seeder;

import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import com.podzilla.auth.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;


public class DatabaseSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;

    public DatabaseSeeder(final RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(final String... args) throws Exception {
        roleRepository.save(new Role(ERole.ROLE_USER));
        roleRepository.save(new Role(ERole.ROLE_ADMIN));
    }
}
