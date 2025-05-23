package com.podzilla.auth.model;

import jakarta.persistence.Id;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Column;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.JoinTable;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.CascadeType;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


@Entity
@Table(name = "users")
@Data
@Getter
@NoArgsConstructor
@AllArgsConstructor
public final class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String name;

    @Email
    @Column(unique = true)
    private String email;

    private String password;

    @Column(unique = true)
    private String mobileNumber;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL,
            orphanRemoval = true)
    private Address address;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL,
            orphanRemoval = true)
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    @Column(columnDefinition = "BOOLEAN DEFAULT TRUE")
    private Boolean enabled = true;

    private User(final Builder builder) {
        this.id = builder.id;
        this.name = builder.name;
        this.email = builder.email;
        this.password = builder.password;
        this.roles = builder.roles;
        this.refreshTokens = builder.refreshTokens;
        this.enabled = builder.enabled;
        this.mobileNumber = builder.mobileNumber;
        this.address = builder.address;
    }

    public static class Builder {
        private UUID id;
        private String name;
        private String email;
        private String password;
        private Set<Role> roles = new HashSet<>();
        private Set<RefreshToken> refreshTokens = new HashSet<>();
        private Boolean enabled = true;
        private String mobileNumber;
        private Address address;

        public Builder id(final UUID id) {
            this.id = id;
            return this;
        }

        public Builder name(final String name) {
            this.name = name;
            return this;
        }

        public Builder email(final String email) {
            this.email = email;
            return this;
        }

        public Builder password(final String password) {
            this.password = password;
            return this;
        }

        public Builder roles(final Set<Role> roles) {
            this.roles = roles;
            return this;
        }

        public Builder enabled(final Boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder address(final Address address) {
            this.address = address;
            return this;
        }

        public Builder mobileNumber(final String mobileNumber) {
            this.mobileNumber = mobileNumber;
            return this;
        }

        public User build() {
            return new User(this);
        }
    }
}
