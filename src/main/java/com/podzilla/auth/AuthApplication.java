package com.podzilla.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@EnableCaching
@ComponentScan(basePackages = { "com.podzilla" })
public class AuthApplication {

    public static void main(final String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

}
