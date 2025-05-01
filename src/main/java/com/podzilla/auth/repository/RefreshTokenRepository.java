package com.podzilla.auth.repository;

import com.podzilla.auth.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends
                                    JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByIdAndExpiresAtAfter(UUID id, Instant date);
    Optional<RefreshToken> findByUserIdAndExpiresAtAfter(Long userId,
                                                         Instant date);
}
