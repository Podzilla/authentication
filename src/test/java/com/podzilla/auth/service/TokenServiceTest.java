package com.podzilla.auth.service;

import com.podzilla.auth.exception.ValidationException;
import com.podzilla.auth.model.RefreshToken;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RefreshTokenRepository;
import com.podzilla.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.util.WebUtils;


import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpServletRequest request;

    // Use InjectMocks to automatically inject the mocked dependencies
    @InjectMocks
    private TokenService tokenService;

    // Test data
    private final String testEmail = "test@example.com";
    private final String testSecret = "testSecretKeyForJwtTokenGenerationWhichIsVeryLongAndSecure"; // Use a valid Base64 encoded key if possible
    private final Long testUserId = 115642L;
    private final UUID testRefreshTokenId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        // Use ReflectionTestUtils to set the private @Value fields
        ReflectionTestUtils.setField(tokenService, "secret", testSecret);
        Long testJwtExpiresMinutes = 30L;
        ReflectionTestUtils.setField(tokenService, "jwtExpiresMinutes", testJwtExpiresMinutes);
        // Reset claims if needed between tests (though it's mostly set during validation)
        ReflectionTestUtils.setField(tokenService, "claims", null);
    }

    @Test
    @DisplayName("Should generate access token and add cookie")
    void generateAccessToken_ShouldAddCookie() {
        // Arrange
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        tokenService.generateAccessToken(testEmail, response);

        // Assert
        verify(response).addCookie(cookieCaptor.capture());
        Cookie addedCookie = cookieCaptor.getValue();

        assertNotNull(addedCookie);
        assertEquals("accessToken", addedCookie.getName());
        assertTrue(addedCookie.isHttpOnly());
        assertTrue(addedCookie.getSecure());
        assertEquals("/", addedCookie.getPath()); // Check path
        assertEquals(60 * 30, addedCookie.getMaxAge()); // Check expiration

        // Optionally, validate the JWT content (requires parsing logic similar to validateAccessToken)
        assertNotNull(addedCookie.getValue());
        // You could add more detailed JWT validation if needed
    }

    @Test
    @DisplayName("Should generate new refresh token if none exists")
    void generateRefreshToken_WhenNoneExists_ShouldCreateNewAndAddCookie() {
        // Arrange
        User user = User.builder().id(testUserId).email(testEmail).build();
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUserIdAndExpiresAtAfter(eq(testUserId), any(Instant.class)))
                .thenReturn(Optional.empty()); // No existing valid token
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> {
                    RefreshToken token = invocation.getArgument(0);
                    token.setId(testRefreshTokenId);
                    return token;
                }); // Mock save to return the
        // token itself

        ArgumentCaptor<RefreshToken> refreshTokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        tokenService.generateRefreshToken(testEmail, response);

        // Assert
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
        RefreshToken savedToken = refreshTokenCaptor.getValue();
        assertNotNull(savedToken);
        assertEquals(user, savedToken.getUser());
        assertNotNull(savedToken.getCreatedAt());
        assertNotNull(savedToken.getExpiresAt());
        assertTrue(savedToken.getExpiresAt().isAfter(Instant.now()));

        verify(response).addCookie(cookieCaptor.capture());
        Cookie addedCookie = cookieCaptor.getValue();
        assertNotNull(addedCookie);
        assertEquals("refreshToken", addedCookie.getName());
        assertEquals(savedToken.getId().toString(), addedCookie.getValue()); // Verify token value in cookie
        assertTrue(addedCookie.isHttpOnly());
        assertTrue(addedCookie.getSecure());
        assertEquals("/api/auth/refresh-token", addedCookie.getPath()); // Check specific path
        assertTrue(addedCookie.getMaxAge() > 0); // Check expiration
    }

    @Test
    @DisplayName("Should use existing refresh token if valid one exists")
    void generateRefreshToken_WhenValidExists_ShouldUseExistingAndAddCookie() {
        // Arrange
        User user = User.builder().id(testUserId).email(testEmail).build();
        RefreshToken existingToken = RefreshToken.builder()
                .id(testRefreshTokenId)
                .user(user)
                .createdAt(Instant.now().minus(1, ChronoUnit.DAYS))
                .expiresAt(Instant.now().plus(50, ChronoUnit.DAYS)) // Still
                // valid
                .build();

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUserIdAndExpiresAtAfter(eq(testUserId), any(Instant.class)))
                .thenReturn(Optional.of(existingToken));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        tokenService.generateRefreshToken(testEmail, response);

        // Assert
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class)); // Should not save a new one

        verify(response).addCookie(cookieCaptor.capture());
        Cookie addedCookie = cookieCaptor.getValue();
        assertNotNull(addedCookie);
        assertEquals("refreshToken", addedCookie.getName());
        assertEquals(existingToken.getId().toString(), addedCookie.getValue()); // Uses existing token ID
        assertTrue(addedCookie.isHttpOnly());
        assertTrue(addedCookie.getSecure());
        assertEquals("/api/auth/refresh-token", addedCookie.getPath());
    }


    @Test
    @DisplayName("Should throw ValidationException if user not found during refresh token generation")
    void generateRefreshToken_WhenUserNotFound_ShouldThrowValidationException() {
        // Arrange
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.empty());

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            tokenService.generateRefreshToken(testEmail, response);
        });
        assertEquals("Validation error: User not found",
                exception.getMessage());
        verify(refreshTokenRepository, never()).save(any());
        verify(response, never()).addCookie(any());
    }


    @Test
    @DisplayName("Should renew refresh token successfully")
    void renewRefreshToken_ValidToken_ShouldExpireOldCreateNewAddCookieAndReturnEmail() {
        // Arrange
        User user = User.builder().id(testUserId).email(testEmail).build();
        RefreshToken oldToken = RefreshToken.builder()
                .id(testRefreshTokenId)
                .user(user)
                .createdAt(Instant.now().minus(10, ChronoUnit.DAYS))
                .expiresAt(Instant.now().plus(5, ChronoUnit.DAYS))
                .build();
        String oldTokenString = oldToken.getId().toString();

        when(refreshTokenRepository.findByIdAndExpiresAtAfter(eq(testRefreshTokenId), any(Instant.class)))
                .thenReturn(Optional.of(oldToken));
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> {
                    RefreshToken token = invocation.getArgument(0);
                    token.setId(UUID.randomUUID());
                    return token;
                }); // Mock save to return the token itself

        ArgumentCaptor<RefreshToken> refreshTokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        String resultEmail = tokenService.renewRefreshToken(oldTokenString, response);

        // Assert
        assertEquals(testEmail, resultEmail);

        verify(refreshTokenRepository, times(2)).save(refreshTokenCaptor.capture());
        RefreshToken expiredToken = refreshTokenCaptor.getAllValues().get(0);
        RefreshToken newToken = refreshTokenCaptor.getAllValues().get(1);

        // Verify old token was expired (or set to expire immediately)
        assertTrue(expiredToken.getExpiresAt().isBefore(Instant.now().plusSeconds(1))); // Check if expiration is set to now or very close

        // Verify new token details
        assertNotEquals(oldToken.getId(), newToken.getId());
        assertEquals(user, newToken.getUser());
        assertTrue(newToken.getExpiresAt().isAfter(Instant.now()));

        // Verify cookie for the new token
        verify(response).addCookie(cookieCaptor.capture());
        Cookie addedCookie = cookieCaptor.getValue();
        assertEquals("refreshToken", addedCookie.getName());
        assertEquals(newToken.getId().toString(), addedCookie.getValue());
        assertTrue(addedCookie.isHttpOnly());
        assertTrue(addedCookie.getSecure());
        assertEquals("/api/auth/refresh-token", addedCookie.getPath());
    }

    @Test
    @DisplayName("Should throw ValidationException when renewing invalid refresh token")
    void renewRefreshToken_InvalidToken_ShouldThrowValidationException() {
        // Arrange
        String invalidTokenString = UUID.randomUUID().toString();
        when(refreshTokenRepository.findByIdAndExpiresAtAfter(eq(UUID.fromString(invalidTokenString)), any(Instant.class)))
                .thenReturn(Optional.empty());

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            tokenService.renewRefreshToken(invalidTokenString, response);
        });
        assertEquals("Validation error: Invalid refresh token",
                exception.getMessage());
        verify(refreshTokenRepository, never()).save(any());
        verify(response, never()).addCookie(any());
    }

    @Test
    @DisplayName("Should return access token from cookie")
    void getAccessTokenFromCookie_WhenCookieExists_ShouldReturnTokenValue() {
        // Arrange
        String tokenValue = "dummyAccessToken";
        Cookie accessTokenCookie = new Cookie("accessToken", tokenValue);
        // Static mocking for WebUtils (alternative: inject a mock WebUtils if preferred)
        // Use a try-with-resources block for mocking static methods if using mockito-inline
        try (var mockedStatic = mockStatic(WebUtils.class)) {
            mockedStatic.when(() -> WebUtils.getCookie(request, "accessToken")).thenReturn(accessTokenCookie);

            // Act
            String retrievedToken = tokenService.getAccessTokenFromCookie(request);

            // Assert
            assertEquals(tokenValue, retrievedToken);
        }
    }

    @Test
    @DisplayName("Should return null if access token cookie does not exist")
    void getAccessTokenFromCookie_WhenCookieMissing_ShouldReturnNull() {
        // Arrange
        try (var mockedStatic = mockStatic(WebUtils.class)) {
            mockedStatic.when(() -> WebUtils.getCookie(request, "accessToken")).thenReturn(null);
            // Act
            String retrievedToken = tokenService.getAccessTokenFromCookie(request);

            // Assert
            assertNull(retrievedToken);
        }
    }

    // Similar tests for getRefreshTokenFromCookie...

    @Test
    @DisplayName("Should validate a valid access token")
    void validateAccessToken_ValidToken_ShouldNotThrow() {
        // Arrange: Generate a valid token first
        // Note: This relies on the internal generation logic using the test secret.
        byte[] keyBytes = Decoders.BASE64.decode(testSecret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);
        String validToken = Jwts.builder()
                .subject(testEmail)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5)) // Expires in 5 mins
                .signWith(key)
                .compact();

        // Act & Assert: Should not throw any exception
        assertDoesNotThrow(() -> tokenService.validateAccessToken(validToken));

        // Also assert that claims are set
        Claims claims = (Claims) ReflectionTestUtils.getField(tokenService, "claims");
        assertNotNull(claims);
        assertEquals(testEmail, claims.getSubject());
    }

    @Test
    @DisplayName("Should throw ValidationException for invalid access token (expired)")
    void validateAccessToken_ExpiredToken_ShouldThrowValidationException() {
        // Arrange: Generate an expired token
        SecretKey key = Keys.hmacShaKeyFor(testSecret.getBytes());
        String expiredToken = Jwts.builder()
                .subject(testEmail)
                .issuedAt(new Date(System.currentTimeMillis() - 1000 * 60 * 10)) // Issued 10 mins ago
                .expiration(new Date(System.currentTimeMillis() - 1000 * 60 * 5)) // Expired 5 mins ago
                .signWith(key)
                .compact();

        // Act & Assert
        assertThrows(ValidationException.class, () -> {
            tokenService.validateAccessToken(expiredToken);
        });
    }

    @Test
    @DisplayName("Should throw ValidationException for malformed access token")
    void validateAccessToken_MalformedToken_ShouldThrowValidationException() {
        // Arrange
        String malformedToken = "this.is.not.a.valid.jwt";

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            tokenService.validateAccessToken(malformedToken);
        });
        // Check if the message indicates a JWT format issue
        assertTrue(exception.getMessage().toLowerCase().contains("jwt"));
    }

    @Test
    @DisplayName("Should remove access token cookie")
    void removeAccessTokenFromCookie_ShouldAddNullCookie() {
        // Arrange
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        tokenService.removeAccessTokenFromCookie(response);

        // Assert
        verify(response).addCookie(cookieCaptor.capture());
        Cookie addedCookie = cookieCaptor.getValue();

        assertEquals("accessToken", addedCookie.getName());
        assertNull(addedCookie.getValue()); // Value should be null to remove
        assertEquals("/", addedCookie.getPath());
        // MaxAge might be 0 or not set depending on exact removal strategy, check path mainly
    }


    // --- Tests for removeRefreshTokenFromCookieAndExpire ---
    // This requires setting the 'claims' field first, as extractEmail depends on it.

    private void setupClaimsForEmailExtraction() {
        // Helper to simulate that validateAccessToken was called successfully before
        SecretKey key = Keys.hmacShaKeyFor(testSecret.getBytes());
        Claims claims = Jwts.claims().subject(testEmail).build();
        ReflectionTestUtils.setField(tokenService, "claims", claims);
    }

    @Test
    @DisplayName("Should remove refresh token cookie and expire token in DB")
    void removeRefreshTokenFromCookieAndExpire_ValidState_ShouldPerformActions() {
        // Arrange
        setupClaimsForEmailExtraction(); // Simulate prior successful access token validation

        User user = User.builder().id(testUserId).email(testEmail).build();
        RefreshToken refreshToken = RefreshToken.builder()
                .id(testRefreshTokenId)
                .user(user)
                .createdAt(Instant.now().minus(7, ChronoUnit.DAYS))
                .expiresAt(Instant.now().plus(21, ChronoUnit.DAYS))
                .build();

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUserIdAndExpiresAtAfter(eq(testUserId), any(Instant.class)))
                .thenReturn(Optional.of(refreshToken));

        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // Act
        tokenService.removeRefreshTokenFromCookieAndExpire(response);

        // Assert
        // 1. Verify token was expired
        verify(refreshTokenRepository).save(tokenCaptor.capture());
        RefreshToken expiredToken = tokenCaptor.getValue();
        assertEquals(refreshToken.getId(), expiredToken.getId());
        assertTrue(expiredToken.getExpiresAt().isBefore(Instant.now().plusSeconds(1))); // Expired now

        // 2. Verify cookie was removed
        verify(response).addCookie(cookieCaptor.capture());
        Cookie removedCookie = cookieCaptor.getValue();
        assertEquals("refreshToken", removedCookie.getName());
        assertNull(removedCookie.getValue());
        assertEquals("/api/auth/refresh-token", removedCookie.getPath());
    }

    @Test
    @DisplayName("removeRefreshTokenFromCookieAndExpire should throw if user not found")
    void removeRefreshTokenFromCookieAndExpire_UserNotFound_ShouldThrowValidationException() {
        // Arrange
        setupClaimsForEmailExtraction();
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.empty());

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            tokenService.removeRefreshTokenFromCookieAndExpire(response);
        });
        assertEquals("Validation error: User not found",
                exception.getMessage());
        verify(refreshTokenRepository, never()).findByUserIdAndExpiresAtAfter(any(), any());
        verify(refreshTokenRepository, never()).save(any());
        verify(response, never()).addCookie(any());
    }

    @Test
    @DisplayName("removeRefreshTokenFromCookieAndExpire should throw if refresh token not found")
    void removeRefreshTokenFromCookieAndExpire_TokenNotFound_ShouldThrowValidationException() {
        // Arrange
        setupClaimsForEmailExtraction();
        User user = User.builder().id(testUserId).email(testEmail).build();

        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUserIdAndExpiresAtAfter(eq(testUserId), any(Instant.class)))
                .thenReturn(Optional.empty()); // Token not found

        // Act & Assert
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            tokenService.removeRefreshTokenFromCookieAndExpire(response);
        });
        assertEquals("Validation error: Refresh token not found",
                exception.getMessage());
        verify(refreshTokenRepository, never()).save(any());
        verify(response, never()).addCookie(any());
    }


    @Test
    @DisplayName("Should extract email from claims")
    void extractEmail_WhenClaimsSet_ShouldReturnSubject() {
        // Arrange
        setupClaimsForEmailExtraction(); // Sets claims with testEmail as subject

        // Act
        String extractedEmail = tokenService.extractEmail();

        // Assert
        assertEquals(testEmail, extractedEmail);
    }

    @Test
    @DisplayName("extractEmail should throw NullPointerException if claims not set")
    void extractEmail_WhenClaimsNull_ShouldThrowNullPointerException() {
        // Arrange: claims field is null by default or after reset

        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            tokenService.extractEmail();
        }, "Expected NullPointerException because claims object is null");
    }
}