# Session Handling with Refresh Token (DB-Based) - Implementation Guide

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Features](#security-features)
4. [Implementation Steps](#implementation-steps)
5. [Configuration](#configuration)
6. [API Contract](#api-contract)
7. [Testing](#testing)
8. [Monitoring](#monitoring)
9. [Rollback Plan](#rollback-plan)
10. [Summary](#summary)

---

## Overview

### Current State
- B2B2C token → One Time Token → JWT Token (stateless)
- No refresh token mechanism
- No session extension capability
- User must re-authenticate when JWT expires

### Target State
- B2B2C token → One Time Token → JWT Token + Refresh Token
- JWT access token (stateless, 7 min)
- Stateful refresh token (DB-persisted, 20 min)
- RT rotation on every refresh
- Instant revoke capability
- Reuse detection with automatic security response

### Why DB Instead of Redis?
- **No additional infrastructure**: Menggunakan DB yang sudah ada
- **Zero additional cost**: Tidak perlu lisensi/instance Redis
- **Persistent**: Data tidak hilang saat restart
- **Familiar tooling**: Tim sudah familiar dengan DB ops
- **Tradeoff**: Sedikit lebih lambat dari Redis untuk lookup, namun acceptable untuk token operation (bukan hot path per-request)

---

## Architecture

### Token Flow (Sequence Diagram)

```
BPI App → BPI BE: Send CIF/RM2No
  ↓
BPI BE → BPI BE: Create signature with privateKey
  ↓
BPI BE → Avantrade BE: B2B Request
  ↓
Avantrade BE → BPI BE: B2B Token Response
  ↓
BPI BE → BPI BE: Create signature with B2B Token
  ↓
BPI BE → Avantrade BE: Authcode Request with B2B Signature
  ↓
Avantrade BE → BPI BE: Authcode Response
  ↓
BPI BE → Avantrade BE: B2B2C Request (Using Authcode)
  ↓
Avantrade BE → BPI BE: B2B2C Token Response
  ↓
BPI BE → Avantrade BE: One Time Token Request (Using B2B2C Token)
  ↓
Avantrade BE → BPI BE: One Time Token Response
  ↓
BPI BE → BPI App: One Time Token Response
  ↓
BPI App → Avantrade SDK: - One Time Token
                         - Host Expiry Timestamp
  ↓
Avantrade SDK → Avantrade SDK: Create timer based on host expiry timestamp
  ↓
Avantrade SDK → Avantrade BE: Request Token Using One Time Token
  ↓
Avantrade BE → Avantrade BE: Generate JWT Token + Refresh Token
  ↓
Avantrade BE → Avantrade BE: Revoke One Time Token (DB: is_used = true)
  ↓
Avantrade BE → Avantrade SDK: - JWT Token
                              - JWT Token Expiry
                              - Refresh Token
                              - Refresh Token Expiry
  ↓
Avantrade SDK → Avantrade SS: Launch
                              (Parameter: JWT Token, JWT Token Expiry,
                               Refresh Token, Refresh Token Expiry)
  ↓
[JWT expiry <= 2 minutes → trigger refresh, max retry 3x, logout if last retry fail]
  ↓
Avantrade SS → Avantrade BE: Refresh JWT Token Using Refresh Token
  ↓
Avantrade BE → Avantrade BE: Validate RT from DB, Generate new JWT + new RT,
                             Revoke old RT (is_revoked = true)
  ↓
Avantrade BE → Avantrade SS: New JWT Token + New Refresh Token
  ↓
[Timer <= 1 minute before host expiry timestamp]
  ↓
Avantrade SDK → BPI App: Send callback
  ↓
BPI App → BPI BE: Refresh session
  ↓
BPI BE → BPI App: Session Refreshed
  ↓
BPI App → Avantrade SDK: Reset expired token timestamp
  ↓
Avantrade SDK → Avantrade SDK: Reset timer
```

---

### DB Table Structure

Ada **2 tabel baru** yang dibuat. OTT menggunakan tabel terpisah (bukan tabel user existing) karena OTT punya lifecycle sendiri — dibuat saat B2B2C selesai, dipakai sekali oleh SDK, lalu expired. Menyatukannya dengan master data user berisiko delete record user secara tidak sengaja dan menyulitkan audit/cleanup.

#### 1. `one_time_token` — menyimpan OTT yang di-generate saat B2B2C flow

```sql
CREATE TABLE one_time_token (
    id          BIGINT          PRIMARY KEY AUTO_INCREMENT,
    token       VARCHAR(255)    NOT NULL UNIQUE,
    username    VARCHAR(100)    NOT NULL,
    is_used     BOOLEAN         NOT NULL DEFAULT FALSE,
    client_code VARCHAR(50)     NOT NULL,
    branch_id   VARCHAR(36)     NOT NULL,
    user_id     VARCHAR(36)     NOT NULL;
    expired_at  DATETIME        NOT NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ott_token      ON one_time_token(token);
CREATE INDEX idx_ott_expired_at ON one_time_token(expired_at);
```

#### 2. `refresh_token` — menyimpan RT untuk RT rotation

```sql
CREATE TABLE refresh_token (
    id          BIGINT          PRIMARY KEY AUTO_INCREMENT,
    rt_id       VARCHAR(36)     NOT NULL UNIQUE,
    username    VARCHAR(100)    NOT NULL,
    session_id  VARCHAR(36)     NOT NULL,
    is_revoked  BOOLEAN         NOT NULL DEFAULT FALSE,
    expired_at  DATETIME        NOT NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rt_id         ON refresh_token(rt_id);
CREATE INDEX idx_rt_username   ON refresh_token(username);
CREATE INDEX idx_rt_expired_at ON refresh_token(expired_at);
```

**Pertimbangan indexing:**
- `idx_ott_token` → Primary lookup saat SDK tukar OTT ke JWT (single row, harus cepat)
- `idx_rt_id` → Primary lookup saat validasi refresh token
- `idx_rt_username` → Untuk revoke-all saat reuse detection
- `expired_at` (kedua tabel) → Untuk scheduled cleanup job agar tabel tidak membengkak

---

## Security Features

### 1. RT Rotation
- Setiap refresh menghasilkan RT baru
- RT lama langsung di-revoke (`is_revoked = true`)
- Mencegah token replay attack

### 2. Reuse Detection dengan Atomic Update
```java
int updated = refreshTokenRepository.revokeIfNotRevoked(rtId, LocalDateTime.now());
if (updated == 0) {
    // RT tidak ditemukan, sudah expired, atau sudah dipakai thread lain
    refreshTokenDbService.revokeAllUserTokens(username);
    throw new JwtException("Refresh token reuse detected");
}
```
- Menggunakan atomic conditional UPDATE (`AND is_revoked = false AND expired_at > now`)
- Aman dari race condition concurrent refresh — hanya satu thread yang dapat `updated = 1`
- Otomatis revoke semua session user jika reuse terdeteksi

### 3. One-Time Token
- OTT disimpan di tabel `one_time_token` terpisah dari data user
- Di-flag `is_used = true` secara atomic setelah dipakai SDK
- Tidak bisa di-reuse, short-lived (expired_at based on B2B2C token expiry)
- Tidak di-delete setelah dipakai agar bisa diaudit

### 4. Instant Revoke
- Logout set `is_revoked = true` di DB
- Force logout semua device bisa dilakukan via `revokeAllByUsername`
- Tidak perlu menunggu token expiry

### 5. Proactive Refresh
- SDK refresh 2 menit sebelum JWT expiry
- Max retry 3x dengan interval 30 detik
- Logout jika semua retry gagal

### 6. Auto Cleanup (Scheduled Job)
- Tidak ada TTL otomatis seperti Redis, perlu scheduled job
- Hapus row `expired_at < NOW()` dari kedua tabel secara berkala
- Mencegah tabel membengkak

---

## Implementation Steps

### Step 1: Create DB Tables (Migration)

**File:** `src/main/resources/db/migration/V{n}__create_token_tables.sql`

```sql
-- Tabel One Time Token
CREATE TABLE one_time_token (
    id          BIGINT          PRIMARY KEY AUTO_INCREMENT,
    token       VARCHAR(255)    NOT NULL UNIQUE,
    username    VARCHAR(100)    NOT NULL,
    is_used     BOOLEAN         NOT NULL DEFAULT FALSE,
    client_code VARCHAR(50)     NOT NULL,
    branch_id   VARCHAR(36)     NOT NULL,
    user_id     VARCHAR(36)     NOT NULL;
    expired_at  DATETIME        NOT NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ott_token      ON one_time_token(token);
CREATE INDEX idx_ott_expired_at ON one_time_token(expired_at);

-- Tabel Refresh Token
CREATE TABLE refresh_token (
    id          BIGINT          PRIMARY KEY AUTO_INCREMENT,
    rt_id       VARCHAR(36)     NOT NULL UNIQUE,
    username    VARCHAR(100)    NOT NULL,
    session_id  VARCHAR(36)     NOT NULL,
    is_revoked  BOOLEAN         NOT NULL DEFAULT FALSE,
    expired_at  DATETIME        NOT NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rt_id         ON refresh_token(rt_id);
CREATE INDEX idx_rt_username   ON refresh_token(username);
CREATE INDEX idx_rt_expired_at ON refresh_token(expired_at);
```

---

### Step 2: Create OneTimeToken Entity + Repository

**File:** `src/main/java/com/issm/avantrade/auth/entity/OneTimeTokenEntity.java`

```java
package com.issm.avantrade.auth.entity;

import lombok.*;
import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "one_time_token")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OneTimeTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String token;

    @Column(name = "username", nullable = false, length = 100)
    private String username;

    @Column(name = "client_code", nullable = false)
    private String clientCode;

    @Column(name = "branch_id", nullable = false)
    private String branchId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "is_used", nullable = false)
    private boolean used;

    @Column(name = "expired_at", nullable = false)
    private LocalDateTime expiredAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
```

**File:** `src/main/java/com/issm/avantrade/auth/repository/OneTimeTokenRepository.java`

```java
package com.issm.avantrade.auth.repository;

import com.issm.avantrade.auth.entity.OneTimeTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface OneTimeTokenRepository extends JpaRepository<OneTimeTokenEntity, Long> {

    Optional<OneTimeTokenEntity> findByToken(String token);

    // Atomic conditional UPDATE — hanya mark as used jika belum dipakai dan belum expired.
    // Return 0 jika token tidak ditemukan, sudah dipakai, atau sudah expired.
    @Modifying
    @Query("UPDATE OneTimeTokenEntity o SET o.used = true " +
           "WHERE o.token = :token AND o.used = false AND o.expiredAt > :now")
    int markAsUsedIfValid(@Param("token") String token, @Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM OneTimeTokenEntity o WHERE o.expiredAt < :now")
    int deleteExpired(@Param("now") LocalDateTime now);
}
```

---

### Step 3: Create RefreshToken Entity + Repository

**File:** `src/main/java/com/issm/avantrade/auth/entity/RefreshTokenEntity.java`

```java
package com.issm.avantrade.auth.entity;

import lombok.*;
import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_token")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rt_id", nullable = false, unique = true, length = 36)
    private String rtId;

    @Column(name = "username", nullable = false, length = 100)
    private String username;

    @Column(name = "session_id", nullable = false, length = 36)
    private String sessionId;

    @Column(name = "is_revoked", nullable = false)
    private boolean revoked;

    @Column(name = "expired_at", nullable = false)
    private LocalDateTime expiredAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
```

**File:** `src/main/java/com/issm/avantrade/auth/repository/RefreshTokenRepository.java`

```java
package com.issm.avantrade.auth.repository;

import com.issm.avantrade.auth.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

    // Atomic conditional UPDATE — fix race condition concurrent refresh.
    // Hanya revoke jika belum direvoke DAN belum expired.
    // Return 0 jika RT tidak ditemukan, sudah direvoke thread lain, atau sudah expired.
    @Modifying
    @Query("UPDATE RefreshTokenEntity r SET r.revoked = true " +
           "WHERE r.rtId = :rtId AND r.revoked = false AND r.expiredAt > :now")
    int revokeIfNotRevoked(@Param("rtId") String rtId, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE RefreshTokenEntity r SET r.revoked = true " +
           "WHERE r.username = :username AND r.revoked = false")
    int revokeAllByUsername(@Param("username") String username);

    @Modifying
    @Query("DELETE FROM RefreshTokenEntity r WHERE r.expiredAt < :now")
    int deleteExpired(@Param("now") LocalDateTime now);
}
```

---

### Step 4: Create RefreshTokenDbService

**File:** `src/main/java/com/issm/avantrade/auth/service/RefreshTokenDbService.java`

```java
package com.issm.avantrade.auth.service;

import com.issm.avantrade.auth.entity.RefreshTokenEntity;
import com.issm.avantrade.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenDbService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public void storeRefreshToken(String rtId, String username, String sessionId, int ttlMinutes) {
        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .rtId(rtId)
                .username(username)
                .sessionId(sessionId)
                .revoked(false)
                .expiredAt(LocalDateTime.now().plusMinutes(ttlMinutes))
                .build();
        refreshTokenRepository.save(entity);
        log.debug("[RT_STORE] Stored RT {} for user {}, TTL {} min", rtId, username, ttlMinutes);
    }

    /**
     * Atomic validate + revoke menggunakan conditional UPDATE.
     *
     * Tidak pakai findByRtId() lalu update terpisah karena ada window race condition
     * di antara dua operasi tersebut — dua thread concurrent bisa sama-sama lolos
     * cek is_revoked dan sama-sama generate token baru (melanggar prinsip reuse detection).
     *
     * Solusi: satu atomic UPDATE dengan kondisi AND is_revoked = false AND expired_at > now.
     * Hanya satu thread yang akan dapat updated = 1, thread lain dapat 0.
     *
     * @Transactional tetap diperlukan agar storeRefreshToken (setelah ini dipanggil)
     * berada dalam satu unit kerja yang konsisten.
     */
    @Transactional
    public boolean validateAndRevoke(String rtId) {
        int updated = refreshTokenRepository.revokeIfNotRevoked(rtId, LocalDateTime.now());
        if (updated == 0) {
            log.warn("[RT_INVALID] RT {} not found, already revoked, or expired", rtId);
            return false;
        }
        log.debug("[RT_REVOKE] Successfully revoked RT {}", rtId);
        return true;
    }

    @Transactional
    public void revokeAllUserTokens(String username) {
        int count = refreshTokenRepository.revokeAllByUsername(username);
        log.info("[RT_REVOKE_ALL] Revoked {} RTs for user {}", count, username);
    }
}
```

---

### Step 5: Create Cleanup Scheduled Job

**File:** `src/main/java/com/issm/avantrade/auth/scheduler/TokenCleanupJob.java`

```java
package com.issm.avantrade.auth.scheduler;

import com.issm.avantrade.auth.repository.OneTimeTokenRepository;
import com.issm.avantrade.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupJob {

    private final RefreshTokenRepository refreshTokenRepository;
    private final OneTimeTokenRepository oneTimeTokenRepository;

    /**
     * Hapus expired RT dan OTT setiap 30 menit.
     * Pastikan @EnableScheduling aktif di main class atau config.
     */
    @Scheduled(fixedDelay = 1800000)
    @Transactional
    public void cleanupExpiredTokens() {
        int deletedRt  = refreshTokenRepository.deleteExpired(LocalDateTime.now());
        int deletedOtt = oneTimeTokenRepository.deleteExpired(LocalDateTime.now());
        log.info("[RT_CLEANUP]  Deleted {} expired refresh tokens", deletedRt);
        log.info("[OTT_CLEANUP] Deleted {} expired one time tokens", deletedOtt);
    }
}
```

> **Note:** Pastikan `@EnableScheduling` sudah ada di salah satu `@Configuration` class atau di main application class.

---

### Step 6: Modify JwtTokenUtil

**File:** `src/main/java/com/issm/avantrade/auth/util/JwtTokenUtil.java`

**Ganti dependency (dari Redis ke DB):**
```java
// SEBELUM:
// @Autowired
// private RefreshTokenRedisService refreshTokenRedisService;

// SESUDAH:
@Autowired
private RefreshTokenDbService refreshTokenDbService;
```

**Tambah / update methods:**
```java
public String generateRefreshToken(String username, UUID sessionId, int sessionTimeoutMinutes) {
    String rtId = UUID.randomUUID().toString();
    Date iat = new Date();
    Date exp = DateUtils.addMinutes(iat, sessionTimeoutMinutes);

    log.debug("[REFRESH_TOKEN_EXPIRATION] RT will expire at {}",
        DateUtil.toFormat(exp, "dd MMM yyyy, HH:mm:ss.SSS"));

    return Jwts.builder()
        .setId(rtId)
        .setSubject(username)
        .claim("sessionId", sessionId.toString())
        .setIssuedAt(iat)
        .setExpiration(exp)
        .signWith(generateRefreshTokenSecretKey())
        .compact();
}

public JwtTokenDtls refreshToken(String refreshToken, String oldJwtToken, int rtTtlMinutes) {
    Claims rtClaims = this.refreshTokenParser.parseClaimsJws(refreshToken).getBody();
    String rtId      = rtClaims.getId();
    String username  = rtClaims.getSubject();
    String sessionId = rtClaims.get("sessionId", String.class);

    // Atomic validate + revoke — aman dari concurrent refresh
    if (!refreshTokenDbService.validateAndRevoke(rtId)) {
        log.error("[RT_REUSE] RT reuse detected for user {}", username);
        refreshTokenDbService.revokeAllUserTokens(username);
        throw new JwtException("Refresh token reuse detected");
    }

    // Ambil ClaimDTO dari old JWT — tidak perlu query DB / hardcode
    // ClaimDTO (clientCode, branchId, userId) sudah tersimpan sebagai claim "user" di JWT lama
    Claims oldClaims = this.jwtParser.parseClaimsJws(oldJwtToken).getBody();
    ClaimDTO userInfo = oldClaims.get("user", ClaimDTO.class);

    this.sessService.updateSession(UUID.fromString(sessionId), LocalDateTime.now());

    JwtTokenDtls newTokens = generateToken(username, userInfo, sessionId);

    String newRT = generateRefreshToken(username, UUID.fromString(sessionId), rtTtlMinutes);
    Claims newRtClaims = this.refreshTokenParser.parseClaimsJws(newRT).getBody();

    refreshTokenDbService.storeRefreshToken(
        newRtClaims.getId(), username, sessionId, rtTtlMinutes
    );

    return new JwtTokenDtls(newTokens.getToken(), newRT, newTokens.getIssuedAt(), newTokens.getExpiration());
}

public JwtParser getRefreshTokenParser() {
    return this.refreshTokenParser;
}
```

---

### Step 7: Update JwtTokenDtls DTO

**File:** `src/main/java/com/issm/avantrade/auth/dto/JwtTokenDtls.java`

```java
package com.issm.avantrade.auth.dto;

import java.util.Date;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenDtls {
    private String token;
    private String refreshToken;
    private Date issuedAt;
    private Date expiration;

    public JwtTokenDtls(String token, Date issuedAt, Date expiration) {
        this.token = token;
        this.issuedAt = issuedAt;
        this.expiration = expiration;
    }
}
```

---

### Step 8: Update AuthenticationTokenByB2b2cResponse

**File:** `src/main/java/com/issm/avantrade/auth/newarchitecture/features/function/authentication/tokenbyb2b2c/AuthenticationTokenByB2b2cResponse.java`

```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.tokenbyb2b2c;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationTokenByB2b2cResponse {
    String successCode;
    String successMessage;
    String oneTimeToken;
    String oneTimeTokenExpiry;
    String webviewUrl;
}
```

---

### Step 9: Update AuthenticationTokenByB2b2cServiceImpl

**File:** `src/main/java/com/issm/avantrade/auth/newarchitecture/features/function/authentication/tokenbyb2b2c/AuthenticationTokenByB2b2cServiceImpl.java`

```java
@Override
public AuthenticationTokenByB2b2cResponse serve(HttpServletRequest httpServletRequest) {
    // ... existing code ...

    ClientUsers clientUsers =  clientUsersRepository.findByTokenValue(accessTokenB2B.replace(AccessTokenType.BEARER.getValue()+" ", "")).orElseThrow(() -> new CustomException("UNAUTHORIZED"));
    validator.validateExpiredTokenB2b2c(clientUsers);

    ClientDetail clientDetail = clientDetailRepository.findByClientId(clientUsers.getClientId()).orElseThrow(() -> new CustomException("UNAUTHORIZED"));  

    JwtTokenDtls token = jwtTokenUtil.generateAuthCustomer(loginId,
        new ClaimDTO(clientDetail.getClientCode(), "NONE", clientUsers.getUserId(), UUID.fromString(branchId)),
        sessId.toString());

    String loginId = clientUsers.getLoginId();
    String branchId = clientUsers.getBranchId().toString();
    String clientCode = clientDetail.getClientCode();
    String userId = clientUsers.getUserId();

    // Simpan OTT ke tabel one_time_token (tabel terpisah dari data user)
    oneTimeTokenRepository.save(
        OneTimeTokenEntity.builder()
            .token(token.getToken())
            .username(loginId)
            .clientCode(clientCode)
            .branchId(branchId)
            .userId(userId)
            .used(false)
            .expiredAt(...)
            .build()
    );

    AuthenticationTokenByB2b2cResponse response = new AuthenticationTokenByB2b2cResponse();
    response.setSuccessCode("43");
    response.setSuccessMessage("Success");
    response.setOneTimeToken(token.getToken());
    response.setOneTimeTokenExpiry(token.getExpiration().toInstant().toString());
    response.setWebviewUrl(getWebViewUrl(environement));
    return response;
}
```

---

### Step 10: Create One Time Token to JWT Endpoint

**Package:** `authentication/onetimetoken/`

**Request:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.onetimetoken;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationTokenByOneTimeTokenRequest {
    private String oneTimeToken;
}
```

**Response:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.onetimetoken;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationTokenByOneTimeTokenResponse {
    String successCode;
    String successMessage;
    String jwtToken;
    String jwtTokenExpiry;
    String refreshToken;
    String refreshTokenExpiry;
}
```

**Service Interface:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.onetimetoken;

public interface AuthenticationTokenByOneTimeTokenService {
    AuthenticationTokenByOneTimeTokenResponse serve(AuthenticationTokenByOneTimeTokenRequest request);
}
```

**Service Implementation:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.onetimetoken;

import java.time.LocalDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.issm.avantrade.auth.constant.SysParamCode;
import com.issm.avantrade.auth.dto.ClaimDTO;
import com.issm.avantrade.auth.dto.JwtTokenDtls;
import com.issm.avantrade.auth.entity.OneTimeTokenEntity;
import com.issm.avantrade.auth.exception.CustomException;
import com.issm.avantrade.auth.gateways.system.parameter.SystemParameterGateway;
import com.issm.avantrade.auth.objects.SystemParameterObj;
import com.issm.avantrade.auth.repository.OneTimeTokenRepository;
import com.issm.avantrade.auth.service.RefreshTokenDbService;
import com.issm.avantrade.auth.service.UserSessionService;
import com.issm.avantrade.auth.util.JwtTokenUtil;
import com.issm.avantrade.auth.util.StringUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Service
@Slf4j
public class AuthenticationTokenByOneTimeTokenServiceImpl implements AuthenticationTokenByOneTimeTokenService {

    private final OneTimeTokenRepository oneTimeTokenRepository;
    private final SystemParameterGateway systemParameterGateway;
    private final UserSessionService sessService;
    private final JwtTokenUtil jwtTokenUtil;
    private final RefreshTokenDbService refreshTokenDbService;

    @Override
    @Transactional
    public AuthenticationTokenByOneTimeTokenResponse serve(AuthenticationTokenByOneTimeTokenRequest request) {
        // Atomic validate + mark as used — aman dari concurrent reuse
        int updated = oneTimeTokenRepository.markAsUsedIfValid(
            request.getOneTimeToken(), LocalDateTime.now()
        );

        if (updated == 0) {
            log.warn("[OTT_INVALID] OTT invalid, already used, or expired");
            throw new CustomException("Invalid or expired one time token");
        }

        OneTimeTokenEntity ottEntity = oneTimeTokenRepository
            .findByToken(request.getOneTimeToken())
            .orElseThrow(() -> new CustomException("One time token not found"));

        int sessionTimeOut = systemParameterGateway.findByEnum(SysParamCode.SESSION_TIMEOUT)
                .map(SystemParameterObj::getValue)
                .map(StringUtil::toBoxInt)
                .orElse(20);

        UUID sessId = sessService.createUserSession(
            ottEntity.getUsername(),
            ottEntity.getUsername(),
            LocalDateTime.now(),
            sessionTimeOut
        );

        // TODO: ClaimDTO perlu disesuaikan dengan data real user
        // clientCode dan branchId perlu diambil dari user/client table
        ClaimDTO claims = new ClaimDTO(
            ottEntity.getClientCode(),
            "NONE",
            ottEntity.getUserId(),
            UUID.fromString(ottEntity.getBranchId())
        );
        JwtTokenDtls jwtToken = jwtTokenUtil.generateToken(ottEntity.getUsername(), claims, sessId.toString());

        String refreshToken = jwtTokenUtil.generateRefreshToken(ottEntity.getUsername(), sessId, sessionTimeOut);
        Claims rtClaims = jwtTokenUtil.getRefreshTokenParser().parseClaimsJws(refreshToken).getBody();

        refreshTokenDbService.storeRefreshToken(
            rtClaims.getId(), ottEntity.getUsername(), sessId.toString(), sessionTimeOut
        );

        AuthenticationTokenByOneTimeTokenResponse response = new AuthenticationTokenByOneTimeTokenResponse();
        response.setSuccessCode("43");
        response.setSuccessMessage("Success");
        response.setJwtToken(jwtToken.getToken());
        response.setJwtTokenExpiry(jwtToken.getExpiration().toInstant().toString());
        response.setRefreshToken(refreshToken);
        response.setRefreshTokenExpiry(rtClaims.getExpiration().toInstant().toString());

        return response;
    }
}
```

---

### Step 11: Create Refresh Token Endpoint

**Package:** `authentication/refresh/`

**Request:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.refresh;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {
    private String jwtToken;       // untuk extract ClaimDTO (clientCode, branchId, userId)
    private String refreshToken;   // untuk validasi + rotasi RT
}
```

**Response:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.refresh;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenResponse {
    String successCode;
    String successMessage;
    String jwtToken;
    String jwtTokenExpiry;
    String refreshToken;
    String refreshTokenExpiry;
}
```

**Service Interface:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.refresh;

public interface RefreshTokenService {
    RefreshTokenResponse serve(RefreshTokenRequest request);
}
```

**Service Implementation:**
```java
package com.issm.avantrade.auth.newarchitecture.features.function.authentication.refresh;

import org.springframework.stereotype.Service;
import com.issm.avantrade.auth.constant.SysParamCode;
import com.issm.avantrade.auth.dto.JwtTokenDtls;
import com.issm.avantrade.auth.exception.CustomException;
import com.issm.avantrade.auth.gateways.system.parameter.SystemParameterGateway;
import com.issm.avantrade.auth.objects.SystemParameterObj;
import com.issm.avantrade.auth.util.JwtTokenUtil;
import com.issm.avantrade.auth.util.StringUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final JwtTokenUtil jwtTokenUtil;
    private final SystemParameterGateway systemParameterGateway;

    @Override
    public RefreshTokenResponse serve(RefreshTokenRequest request) {
        try {
            int sessionTimeOut = systemParameterGateway.findByEnum(SysParamCode.SESSION_TIMEOUT)
                    .map(SystemParameterObj::getValue)
                    .map(StringUtil::toBoxInt)
                    .orElse(20);

            JwtTokenDtls tokens = jwtTokenUtil.refreshToken(
                request.getRefreshToken(), request.getJwtToken(), sessionTimeOut
            );

            Claims rtClaims = jwtTokenUtil.getRefreshTokenParser()
                .parseClaimsJws(tokens.getRefreshToken())
                .getBody();

            RefreshTokenResponse response = new RefreshTokenResponse();
            response.setSuccessCode("43");
            response.setSuccessMessage("Success");
            response.setJwtToken(tokens.getToken());
            response.setJwtTokenExpiry(tokens.getExpiration().toInstant().toString());
            response.setRefreshToken(tokens.getRefreshToken());
            response.setRefreshTokenExpiry(rtClaims.getExpiration().toInstant().toString());

            return response;

        } catch (JwtException e) {
            throw new CustomException("Invalid or expired refresh token");
        }
    }
}
```

---

### Step 12: Update Controller

**File:** `src/main/java/com/issm/avantrade/auth/newarchitecture/features/function/authentication/AuthenticationControllerV2.java`

```java
@RestController
@AllArgsConstructor
@RequestMapping(value = "/authentication/v2")
public class AuthenticationControllerV2 {

    private final AuthenticationTokenByB2b2cService authenticationTokenByB2b2cService;
    private final AuthenticationB2b2cService authenticationB2b2cService;
    private final AuthenticationB2bService authenticationB2bService;
    private final AuthenticationCodeService authenticationCodeService;
    private final AuthenticationAppInAppService appInAppService;
    private final AuthenticationTokenByOneTimeTokenService authenticationTokenByOneTimeTokenService;
    private final RefreshTokenService refreshTokenService;

    // ... existing endpoints ...

    @PostMapping("/token/by-one-time-token")
    public ResponseEntity<AuthenticationTokenByOneTimeTokenResponse> getTokenByOneTimeToken(
        @Valid @RequestBody AuthenticationTokenByOneTimeTokenRequest request
    ) {
        AuthenticationTokenByOneTimeTokenResponse body = authenticationTokenByOneTimeTokenService.serve(request);
        return new ResponseEntity<>(body, HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<RefreshTokenResponse> refreshToken(
        @Valid @RequestBody RefreshTokenRequest request
    ) {
        RefreshTokenResponse body = refreshTokenService.serve(request);
        return new ResponseEntity<>(body, HttpStatus.OK);
    }
}
```

---

## Configuration

### application.yml

```yaml
avantrade:
  app:
    jwt:
      secret: ${JWT_SECRET}
      expiration:
        ms: 420000  # 7 minutes
      refresh:
        secret: ${JWT_REFRESH_SECRET}
        expiration:
          minutes: 20
  feature:
    refresh-token:
      enabled: true

# Tidak ada konfigurasi Redis — menggunakan datasource yang sudah ada
```

---

## API Contract

### POST /authentication/v2/token/by-one-time-token

**Request:**
```json
{ "oneTimeToken": "eyJhbGciOiJIUzI1NiJ9..." }
```

**Response (Success):**
```json
{
  "successCode": "43",
  "successMessage": "Success",
  "jwtToken": "eyJhbGciOiJIUzI1NiJ9...",
  "jwtTokenExpiry": "2024-01-01T10:07:00Z",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshTokenExpiry": "2024-01-01T10:20:00Z"
}
```

**Response (Error):**
```json
{ "errorCode": "...", "errorMessage": "Invalid or expired one time token" }
```

---

### POST /authentication/v2/refresh-token

**Request:**
```json
{
  "jwtToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Response (Success):**
```json
{
  "successCode": "43",
  "successMessage": "Success",
  "jwtToken": "eyJhbGciOiJIUzI1NiJ9...",
  "jwtTokenExpiry": "2024-01-01T10:14:00Z",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshTokenExpiry": "2024-01-01T10:27:00Z"
}
```

**Response (Error):**
```json
{ "errorCode": "...", "errorMessage": "Invalid or expired refresh token" }
```

---

## Testing

### Test Checklist

- [ ] Get B2B2C token successfully
- [ ] OTT tersimpan di tabel `one_time_token` setelah B2B2C flow selesai (`is_used = false`)
- [ ] SDK tukar OTT → JWT + RT: OTT di-flag `is_used = true`, RT tersimpan di DB
- [ ] OTT tidak bisa dipakai dua kali
- [ ] OTT yang sudah expired tidak bisa dipakai
- [ ] Concurrent request dengan OTT yang sama → hanya satu yang berhasil
- [ ] Refresh JWT using RT successfully → RT lama `is_revoked = true`, RT baru tersimpan
- [ ] Concurrent refresh dengan RT yang sama → hanya satu berhasil, satu trigger reuse detection
- [ ] Reuse old RT → semua RT user di-revoke, error thrown
- [ ] RT expired tidak bisa dipakai
- [ ] JWT expires after 7 minutes
- [ ] Cleanup job hapus expired RT dan OTT dari DB
- [ ] Feature flag `enabled=false` menghentikan fitur tanpa down

### Test Scenarios

#### 1. Normal Flow
```
1. Get B2B2C token
2. Cek: OTT ada di one_time_token, is_used = false
3. SDK tukar OTT → JWT + RT
4. Cek: OTT is_used = true, RT ada di refresh_token
5. Gunakan JWT untuk API calls
6. Tunggu 5 menit (JWT hampir expired)
7. Refresh JWT menggunakan RT → dapat JWT + RT baru
8. Cek: RT lama is_revoked = true, RT baru valid di DB
```

#### 2. Concurrent OTT Reuse
```
1. Get OTT
2. Kirim 2 request concurrent dengan OTT yang sama
3. Expected: Satu berhasil (updated=1), satu gagal (updated=0)
4. Cek: Hanya satu pasang JWT+RT yang di-generate
```

#### 3. Concurrent RT Refresh (Race Condition)
```
1. Get JWT + RT
2. Kirim 2 request refresh concurrent dengan RT yang sama
3. Expected: Satu berhasil (updated=1), satu trigger reuse detection → semua RT user di-revoke
```

#### 4. RT Reuse Detection
```
1. Get JWT + RT
2. Refresh → dapat JWT + RT baru (RT lama revoked)
3. Coba pakai RT lama lagi
4. Expected: Semua RT user di-revoke, error thrown
```

#### 5. Cleanup Job
```
1. Insert RT/OTT dengan expired_at = 1 menit lalu
2. Trigger cleanup job
3. Expected: Rows dihapus dari kedua tabel
```

---

## Monitoring

### Application Metrics

Monitor hal-hal berikut:
- Refresh success/failure rate
- RT reuse detection count (indikasi potensial token theft)
- OTT reuse attempt count
- Row count aktif di tabel `refresh_token` dan `one_time_token`
- Query latency untuk `revokeIfNotRevoked` dan `markAsUsedIfValid`
- Cleanup job execution rate dan deleted count
- DB connection pool status

### Alerts

Set up alerts untuk:
- DB connection pool exhausted
- Query latency token tables > 500ms
- RT reuse detection spike (> N per jam)
- Refresh failure rate > 5%
- Row count `refresh_token` > threshold (indikasi cleanup job tidak jalan)
- Cleanup job tidak jalan > 1 jam

---

## Rollback Plan

### Phase 1: Feature Flag
```java
@Value("${avantrade.feature.refresh-token.enabled:false}")
private boolean refreshTokenEnabled;
```

### Phase 2: Gradual Rollout
1. Deploy ke staging → test thoroughly (termasuk concurrent test)
2. Deploy ke 10% production → monitor metrics 24 jam
3. Deploy ke 50% production → monitor metrics 24 jam
4. Deploy ke 100% production

### Rollback jika ada masalah:
1. Set `avantrade.feature.refresh-token.enabled=false` via config
2. Truncate tabel `refresh_token` dan `one_time_token` jika diperlukan
3. Tidak ada infra tambahan yang perlu di-teardown (tidak seperti Redis)

---

## Summary

### Open Items (Perlu Dikonfirmasi Sebelum Go-Live)

| Item | Status | Keterangan |
|---|---|---|
| `getUserInfoFromSession()` | ✅ Resolved | ClaimDTO diambil dari claim `"user"` di old JWT yang dikirim client saat refresh |
| `ClaimDTO` di OTT service | ⚠️ TODO | `clientCode` dan `branchId` perlu diambil dari data real user |
| `sessionId` origin | ✅ Confirmed | Di-generate via `createUserSession` saat OTT ditukar ke JWT, di-carry via RT claim |

### Perbedaan vs Versi Redis

| Aspek | Redis | DB |
|---|---|---|
| Infrastructure | Redis instance tambahan | Pakai DB existing |
| Cost | Tambahan (instance + lisensi) | Tidak ada |
| Latency lookup | ~1ms | ~5-20ms |
| Auto cleanup | TTL otomatis | Butuh scheduled job |
| Persistent | Opsional (RDB/AOF) | Ya |
| Revoke-all | O(M) via SET index | Satu query UPDATE |
| Race condition protection | Atomic Redis ops | Atomic conditional UPDATE |

### Files Created
- `V{n}__create_token_tables.sql`
- `OneTimeTokenEntity.java`
- `OneTimeTokenRepository.java`
- `RefreshTokenEntity.java`
- `RefreshTokenRepository.java`
- `RefreshTokenDbService.java`
- `TokenCleanupJob.java`
- `onetimetoken/` package (4 files)
- `refresh/` package (4 files)

### Files Modified
- `JwtTokenUtil.java`
- `JwtTokenDtls.java`
- `AuthenticationTokenByB2b2cResponse.java`
- `AuthenticationTokenByB2b2cServiceImpl.java`
- `AuthenticationControllerV2.java`

### Timeline
- Implementation: 8-10 hours
- Testing (termasuk concurrent test): 3-4 hours
- Deployment (include DB migration): 1 hour
- **Total: ~13 hours**