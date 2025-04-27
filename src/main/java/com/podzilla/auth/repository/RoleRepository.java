package com.podzilla.auth.repository;

import com.podzilla.auth.model.ERole;
import com.podzilla.auth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByErole(ERole eRole);
}
