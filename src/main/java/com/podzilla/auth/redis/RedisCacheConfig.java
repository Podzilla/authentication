package com.podzilla.auth.redis;

import com.podzilla.auth.dto.CustomUserDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

import java.time.Duration;

@Configuration
public class RedisCacheConfig {

    private static final int CACHE_TTL = 60 * 60;

    @Bean
    public CacheManager cacheManager(
            final RedisConnectionFactory redisConnectionFactory,
            @Value("${appconfig.cache.enabled}") final String cacheEnabled) {
        if (!Boolean.parseBoolean(cacheEnabled)) {
            return new NoOpCacheManager();
        }

        RedisCacheConfiguration defaultConfig = RedisCacheConfiguration
                .defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(CACHE_TTL))
                .disableCachingNullValues()
                .serializeValuesWith(
                        RedisSerializationContext.
                                SerializationPair.
                                fromSerializer(
                                        new Jackson2JsonRedisSerializer<>(
                                                CustomUserDetails.class)));

        return RedisCacheManager.builder(redisConnectionFactory)
                .cacheDefaults(defaultConfig)
                .build();
    }
}
