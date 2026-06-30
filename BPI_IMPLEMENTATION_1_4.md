<style>
  pre { font-size: 8px !important; line-height: 1.2 !important; }
  code { font-size: 8px !important; }
</style>

# BPI Implementation

## 1. Session Handling Flow
<img src="https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_flow.png" style="width: 600px; max-width: 100%; height: 750px;" alt="Session Handling Flow">

<div style="page-break-after: always;"></div>

## 2. B2B Request Signature

Ensures non-repudiation & integrity checking using asymmetric signature **SHA256withRSA** (`Private_Key`, `stringToSign`).
- `Private_Key` is provided during the partner registration process
- `stringToSign = X-CLIENT-KEY + "|" + X-TIMESTAMP`

### 2.1 Function
```java
public String generateAuthSignature(
        String clientId,
        String timestamp,
        String privateKeyPem) throws Exception {

    String cleaned = privateKeyPem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s", "");

    byte[] keyBytes = Base64.getDecoder().decode(cleaned);
    PrivateKey privateKey = KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

    String payload = clientId + "|" + timestamp;

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(payload.getBytes(StandardCharsets.UTF_8));

    return Base64.getEncoder().encodeToString(signature.sign());
}
```

### 2.1.1 Function Parameter
---
| Key | Type | Length | Mandatory | Description | Sample Value |
|-------------|--------|--------|-----------|--------------------------------------|----------------------------------------|
| clientId | String | N.A | Y | Client UUID from Registration Process | 53e75332-b619-4688-ad45-37d279110a16 |
| timestamp | String | N.A | Y | TimeStamp when initiating process | 2026-05-20T13:45:12.123+07:00 |
| privateKeyPem | String | N.A | Y | Private Key from Registration Process | -----BEGIN PRIVATE KEY----- |
|  | |  |  | | asdasgdjhg2jg21hj3g1jg3jh1g23hj12g|
|  | |  |  | | -----END PRIVATE KEY----- |

### 2.2 Usage
```java
ZonedDateTime now = ZonedDateTime.now(TimeZone.getTimeZone("Asia/Jakarta").toZoneId());
String timeStamp = now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX"));
String privateKeySignature;
try {
    privateKeySignature = helper.generateAuthSignature(
            constants.getClientId2(),
            timeStamp,
            constants.getPrivateKeyPem2());
} catch (Exception e) {
    throw new CustomException(e.toString());
}
```


<div style="page-break-after: always;"></div>

## 3. B2B2C Request Signature

Represents the signature of a request using symmetric signature **HMAC_SHA512** (`secretKey`, `stringToSign`).
```
stringToSign = HTTPMethod + ":" + EndpointURL + ":" + access_token + ":" + Lowercase(HexEncode(SHA-256(requestBody))) + ":" + X-TIMESTAMP
```

> If there is no request body, use an empty string `""`.

### 3.1 Function
```java
public static String generateTransactionSignature(
        String httpMethod,
        String endPoint,
        String token,
        String timestamp,
        String body,
        String clientSecret) throws NoSuchAlgorithmException, InvalidKeyException {

    String hexEncodeBody = sha256Hex(body);
    String stringToSign = String.join(":", httpMethod, endPoint, token, hexEncodeBody, timestamp);

    SecretKeySpec secretKey = new SecretKeySpec(clientSecret.getBytes(), "HmacSHA512");
    Mac hmac = Mac.getInstance("HmacSHA512");
    hmac.init(secretKey);

    return Base64.getEncoder().encodeToString(
            hmac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
}
```

### 3.1.1 Function Parameter
---
| Key | Type | Length | Mandatory | Description | Sample Value |
|-------------|--------|--------|-----------|--------------------------------------|----------------------------------------|
| httpMethod | String | N.A | Y | endpoint method | POST |
| endPoint | String | N.A | Y | url endpoint | /auth-service/authentication/v2/access-token/b2b |
| token | String | N.A | Y | B2B Token | asdasgdjhg2jg21hj3g1jg3jh1g23hj12g |
| timestamp | String | N.A | Y | TimeStamp when initiating process | 2026-05-20T13:45:12.123+07:00 |
| body | String | N.A | Y | Empty String by default |  |
| clientSecret | String | N.A | Y | channel id from B2B Token Response |  53e75332-b619-4688-ad45-37d279110a16 |

### 3.2 Usage
```java
public String generateTransactionSignature(String timeStamp, UUID channelId, String b2bToken) {
    try {
        return SignatureUtil.generateTransactionSignature(
                "POST",
                "/auth-service/authentication/v2/access-token/b2b",
                b2bToken,
                timeStamp,
                "",
                channelId.toString());
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```

<div style="page-break-after: always;"></div>

## 4. API Detail

### 4.1 B2B

#### 4.1.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_b2b.png)

#### 4.1.2 URL
---
POST api-gateway/auth-service/authentication/v2/access-token/b2b

#### 4.1.3 Header Parameter
---
| Key                  | Type   | Length | Mandatory | Description                                         | Sample Value                              |
|----------------------|--------|--------|-----------|-----------------------------------------------------|--------------------------------------------|
| X-CLIENT-KEY         | String | N.A    | Y         | clientId from registration process                                            | c04ee779-1a81-4453-83ea-fd370e9f4cc9      |
| X-TIMESTAMP          | String | N.A    | Y         | Timestamp when create secretKey and privateKey signature | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...           |
| X-SIGNATURE          | String | N.A    | Y         | privateKey Signature                                | SIGNATURE                                  |

#### 4.1.4 Body Parameter
---
| Key            | Type   | Length | Mandatory | Description                          | Sample Value     |
|----------------|--------|--------|-----------|--------------------------------------|-------------------|
| grantType      | String | N A    | Y         | -                                    | client_credentials         |


#### 4.1.5 Response
---
| Property       | Type Data | Sample Value                              |
|---------------|----------|--------------------------------------------|
| accessToken   | String   | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA                 |
| tokenType     | String   | Bearer                                     |
| expiresIn     | String   | 900 (Seconds)                                        |
| sessionId     | UUID     | d568e0f0-740e-42fc-a65e-c8860a50cd3d         |
| channelId     | UUID     | d568e0f0-740e-42fc-a65e-c8860a50cd3d         |
| successCode   | String   | 43                                         |
| successMessage| String   | Success                                    |

#### 4.1.6 Data Relations
---
| Property     | Mapping                          | Relations                    |
|-------------|----------------------------------|------------------------------|
| accessToken | OAuth2Token.getTokenValue        |                              |
| tokenType   | OAuth2AccessToken.getTokenType   |                              |
| sessionId   | MST_USER_SESSIONS.SESSION_ID     |                              |

#### 4.1.7 Curl Example
---
```powershell
curl --location '<host>/api-gateway/auth-service/authentication/v2/access-token/b2b' \
--header 'X-CLIENT-KEY: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'X-TIMESTAMP: 2025-07-11T14:21:23.456+08:00' \
--header 'X-SIGNATURE: cX5cBkPQwaXaV8qbRcwc/EmqI9spIEKrBQDCllsHgDD/AgqjS9Y9DQxkJX1UMHdy5z9L4YgrqSLvlmD2HxwPfV2wAxOHBd+HENsx6TgX/YCzFex0jqUk12FML4B8wK13Eqp9ARbkrGAkhnlcUW+Q3IcTFM+miq+SUqOQ8j3vQjbBSKDpWgS2Qn0bPAu0BCXqmQaYkKZ7AP03bA/VKmkXiOixq2H7/U8Y0qeX0K3hznYZnPZCMIkhJfamLXBHqDdLHUtiYoL3WaYTj+q+wv4Uah4Hj3I1zEUrkphR3lhl0o3pF7EJUVqGYBrEyqJRKgBlT15T9z5UvEMbonGyCDK8Hw==' \
--header 'Content-Type: application/json' \
--data '{
    "grantType":"client_credentials"
}'
```

#### 4.1.8 Response Example
---
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.dummy.payload.signature",
  "tokenType": "Bearer",
  "expiresIn": "900",
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "channelId": "WEB",
  "additionalInfo": {}
}
```

#### 4.1.9 Error List
---
| Messages | Message Code | HTTP Code |
|---|---|---|
| Token generation failed for client: $clientKey | TOKEN_GENERATION_FAILED | 401 |
| Invalid Mandatory Field X-SIGNATURE | MISSING_SIGNATURE | 401 |
| Invalid Signature | INVALID_SIGNATURE | 401 |
| Invalid Mandatory Field X-TIMESTAMP | MISSING_TIMESTAMP | 401 |
| Invalid Format Field X-TIMESTAMP | INVALID_TIMESTAMP | 401 |
| Invalid X-CLIENT-KEY Not Match | INVALID_CLIENT_KEY | 401 |
| Invalid or missing X-Client-Key header. | MISSING_CLIENT_KEY | 401 |
| Generic Exception | GENERIC_EXCEPTION | 500 |

#### 4.1.10 Error Response Example
---
```json
{
  "success": false,
  "errorCodes": ["TOKEN_GENERATION_FAILED"],
  "errors": ["Token generation failed for client: c04ee779-1a81-4453-83ea-fd370e9f4cc9"],
  "data": null,
  "messageCodes": null,
  "messages": null,
  "errorUid": "67de40be-08ef-4950-bbcd-83348c633c5f"
}
```

<div style="page-break-after: always;"></div>

#### 4.2 Auth Code

#### 4.2.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/auth_code_flow.png)

#### 4.2.2 URL
---
POST api-gateway/auth-service/authentication/v2/generate-auth-code/b2b2c

#### 4.2.3 Header Parameter
---
| Key            | Type   | Length | Mandatory | Description                                  | Sample Value                              |
|---------------|--------|--------|-----------|------------------------------------------------|--------------------------------------------|
| X-PARTNER-ID  | String | N.A    | Y         | clientId                                     | c04ee779-1a81-4453-83ea-fd370e9f4cc9         |
| X-TIMESTAMP   | String | N.A    | Y         | Timestamp when create secretKey signature    | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...               |
| X-SIGNATURE   | String | N.A    | Y         | secretKey Signature                          | SIGNATURE                                  |
| X-BRANCH-ID   | String | N.A    | Y         | clientId                                     | c04ee779-1a81-4453-83ea-fd370e9f4cc9         |
| Authorization | String | N.A    | Y         | B2B token                                    | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...               |

#### 4.2.4 Body Parameter
---
| Key            | Type   | Length | Mandatory | Description                                 | Sample Value    |
|---------------|--------|--------|-----------|---------------------------------------------|-----------------|
| paramType     | String | N.A    | Y         | param type used                             | CIF_BANK        |
| paramValue    | String | N.A    | Y         | param value used for get customer data      | CIF2501045138   |
| partnerChannel| String | N.A    | Y         | registered partner channel                  | CH_BPI          |

#### 4.2.5 Response
---
| Property       | Type Data | Sample Value                              |
|---------------|-----------|---------------------------------------------|
| authCode      | String    | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA             |
| successCode   | String    | 43                                        |
| successMessage| String    | Success                                   |

#### 4.2.6 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| authCode  | MST_CLIENT_USER_AUTH_CODE.AUTH_CODE  |           |

#### 4.2.7 Curl Example
---
```powershell
curl --location '<host>/api-gateway/auth-service/authentication/v2/generate-auth-code/b2b2c' \
--header 'Authorization: ato3DmdyHOnnnCKLB9jInGDmzMfPreV6BwUs8-6bYMBGg81Wx2ayEqHI1DRD7BRghPAhvS1OeYnRW7bXL2O_U4BCEr7yZSRb0blq5iTMuxOXKIZ-1u8rI1IX9uYUEZEH' \
--header 'X-PARTNER-ID: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'X-BRANCH-ID: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'X-TIMESTAMP: 2025-07-11T14:21:23.456+08:00' \
--header 'X-SIGNATURE: Ymk6zVbOCjlhd9Jd7MdVYyD3DgZPn1pssFr8KgXB/d0z9Tmue6ul5UmpvBDqBKdKDOJk9mKhOsmBV4LiraJYvQ==' \
--header 'Content-Type: application/json' \
--data '{
    "paramType":"CIF_BANK",
    "paramValue":"00000001102859",
    "partnerChannel":"CH_BPI"
}'
```

#### 4.2.8 Response Example
---
```json
{
  "successCode": "43",
  "successMessage": "Success",
  "authCode": "AUTH-7F3A9C8D5B2E1F4A"
}
```

#### 4.2.9 Error List
---
| Messages | Message Code | HTTP Code |
|---|---|---|
| Token Not Found | TOKEN_INVALID | 401 |
| Token Expired | TOKEN_EXPIRED | 401 |
| Invalid Mandatory Field X-SIGNATURE | MISSING_SIGNATURE | 401 |
| Unauthorized. Invalid Client ID or Signature | INVALID_SIGNATURE | 401 |
| Invalid Mandatory Field X-TIMESTAMP | MISSING_TIMESTAMP | 401 |
| Invalid Format Field X-TIMESTAMP | INVALID_TIMESTAMP | 401 |
| Generic Exception | GENERIC_EXCEPTION | 500 |

#### 4.2.10 Error Response Example
---
```json
{
  "success": false,
  "errorCodes": ["TOKEN_EXPIRED"],
  "errors": ["Token Expired"],
  "data": null,
  "messageCodes": null,
  "messages": null,
  "errorUid": "67de40be-08ef-4950-bbcd-83348c633c5f"
}
```

<div style="page-break-after: always;"></div>

### 4.3 B2B2C

#### 4.3.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_b2b2c.png)

#### 4.3.2 URL
---
POST api-gateway/auth-service/authentication/v2/access-token/b2b2c

#### 4.3.3 Header Parameter
---
| Key                  | Type   | Length | Mandatory | Description                                         | Sample Value                              |
|----------------------|--------|--------|-----------|-----------------------------------------------------|--------------------------------------------|
| X-CLIENT-KEY         | String | N.A    | Y         | clientId                                            | c04ee779-1a81-4453-83ea-fd370e9f4cc9      |
| X-TIMESTAMP          | String | N.A    | Y         | Timestamp when create secretKey and privateKey signature | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...           |
| X-SIGNATURE          | String | N.A    | Y         | privateKey Signature                                | SIGNATURE                                  |
| X-BRANCH-ID          | String | N.A    | Y         | clientId                                            | c04ee779-1a81-4453-83ea-fd370e9f4cc9      |
| AUTHORIZATION-CUSTOMER | String | N.A  | Y         | token from B2B Response                             | 5207d4a3-5666-4d6d-8f1f-7732ca8fa85e      |

#### 4.3.4 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                  | Sample Value          |
|-------------|--------|--------|-----------|------------------------------|----------------------|
| grantType    | String | N.A    | Y         | grant type                   | AUTHORIZATION_CODE    |
| authCode     | String | N.A    | Y         | auth code from response      | eyJhbGciOiJIUzUxMiJ9 |
| refreshToken | String | N.A    | Y         | empty by default             | -                     |

#### 4.3.5 Response
---
| Property                | Type Data | Sample Value                              |
|-------------------------|-----------|---------------------------------------------|
| accessToken             | String    | B2B2C Token             |
| tokenType               | String    | Bearer                                     |
| accessTokenExpiryTime   | String    | 1296000 (In Seconds - 15 Days)                                        |
| refreshToken            | String    | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA             |
| refreshTokenExpiryTime  | String    | 900                                        |
| responseCode             | String    | 43                                         |
| responseMessage          | String    | Success                                    |

#### 4.3.6 Data Relations
---
| Property               | Mapping                        | Relations |
|------------------------|---------------------------------|-----------|
| accessToken            | OAuth2Token.getTokenValue      |           |
| tokenType              | OAuth2AccessToken.getTokenType |           |
| accessTokenExpiryTime  |                                |           |
| refreshToken           |                                |           |
| refreshTokenExpiryTime |                                |           |

#### 4.3.7 Curl Example
---
```powershell
curl --location '<host>/api-gateway/auth-service/authentication/v2/access-token/b2b2c' \
--header 'X-BRANCH-ID: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'X-CLIENT-KEY: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'X-TIMESTAMP: 2025-07-11T14:21:23.456+08:00' \
--header 'X-SIGNATURE: cX5cBkPQwaXaV8qbRcwc/EmqI9spIEKrBQDCllsHgDD/AgqjS9Y9DQxkJX1UMHdy5z9L4YgrqSLvlmD2HxwPfV2wAxOHBd+HENsx6TgX/YCzFex0jqUk12FML4B8wK13Eqp9ARbkrGAkhnlcUW+Q3IcTFM+miq+SUqOQ8j3vQjbBSKDpWgS2Qn0bPAu0BCXqmQaYkKZ7AP03bA/VKmkXiOixq2H7/U8Y0qeX0K3hznYZnPZCMIkhJfamLXBHqDdLHUtiYoL3WaYTj+q+wv4Uah4Hj3I1zEUrkphR3lhl0o3pF7EJUVqGYBrEyqJRKgBlT15T9z5UvEMbonGyCDK8Hw==' \
--header 'AUTHORIZATION-CUSTOMER: ato3DmdyHOnnnCKLB9jInGDmzMfPreV6BwUs8-6bYMBGg81Wx2ayEqHI1DRD7BRghPAhvS1OeYnRW7bXL2O_U4BCEr7yZSRb0blq5iTMuxOXKIZ-1u8rI1IX9uYUEZEH' \
--header 'X-PARTNER-ID: 47c5963a-4836-d939-e063-e30a1aac30ba' \
--header 'Content-Type: application/json' \
--data '{
    "grantType":"AUTHORIZATION_CODE",
    "authCode":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJDSUZfQkFOSyIsInVzZXIiOiIwMDAwMDAwMTEwMjg1OSIsImNoYW5uZWwiOiJDSF9CUEkiLCJpYXQiOjE3ODA5ODg5NTYsImV4cCI6MTc4MTM0ODk1Nn0.JEy7RqtyYvhZsRmtz_oIszRGda1iHic27v1g1qy2uqGgyV9-uQlagXQXTTP6QiQskOcPp1G83J8D6DqtgV_wBg",
    "refreshToken":""
}'
```

#### 4.3.8 Response Example
---
```json
{
  "responseCode": "2007300",
  "responseMessage": "Successful",
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.dummy.access.token",
  "tokenType": "Bearer",
  "accessTokenExpiryTime": "1296000",
  "refreshToken": "",
  "refreshTokenExpiryTime": "",
  "additionalInfo": {}
}
```

#### 4.3.9 Error List
---
| Messages | Message Code | HTTP Code |
|---|---|---|
| Invalid Authentication Code | INVALID_AUTH_CODE | 401 |
| Missing Authentication Code | MISSING_AUTH_CODE | 401 |
| Invalid Mandatory Field X-SIGNATURE | MISSING_SIGNATURE | 401 |
| Invalid Signature | INVALID_SIGNATURE | 401 |
| Invalid Mandatory Field X-TIMESTAMP | MISSING_TIMESTAMP | 401 |
| Invalid Format Field X-TIMESTAMP | INVALID_TIMESTAMP | 401 |
| User Not Found | USER_NOT_FOUND | 401 |
| Invalid X-CLIENT-KEY Not Match | INVALID_CLIENT_KEY | 401 |
| Invalid or missing X-Client-Key header. | MISSING_CLIENT_KEY | 401 |
| Generic Exception | GENERIC_EXCEPTION | 500 |

#### 4.3.10 Error Response Example
---
```json
{
  "success": false,
  "errorCodes": ["INVALID_AUTH_CODE"],
  "errors": ["Invalid Authentication Code"],
  "data": null,
  "messageCodes": null,
  "messages": null,
  "errorUid": "67de40be-08ef-4950-bbcd-83348c633c5f"
}
```

<div style="page-break-after: always;"></div>

### 4.4 One Time Token By B2B2C

#### 4.4.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_ott.png)

#### 4.4.2 URL
---
POST api-gateway/auth-service/authentication/v2/token/by-b2bc-token

#### 4.4.3 Header Parameter
---
| Key                    | Type   | Length | Mandatory | Description              | Sample Value                                                                                       |
|------------------------|--------|--------|-----------|---------------------------|---------------------------------------------------------------------------------------------------|
| authorization-customer  | String | N.A    | Y         | B2B2C Token  | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |
| Authorization          | String | N.A    | Y         | B2B2C Token   | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |

#### 4.4.4 Response
---
| Property            | Type Data | Sample Value      |
|---------------------|-----------|--------------------|
| successCode         | String    | 43               |
| successMessage      | String    | Success          |
| oneTimeToken        | String    | eyJhbGciOiJIUz... |
| oneTimeTokenExpiry  | String    | 900              |

#### 4.4.5 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| oneTimeToken  | MST_ONE_TIME_TOKEN.TOKEN  |           |
| oneTimeTokenExpiry  | MST_ONE_TIME_TOKEN.EXPIRED_AT  |           |

#### 4.4.6 Curl Example
---
```bash
curl -X POST <host>/api-gateway/auth-service/authentication/v2/token/by-b2bc-token \
  -H "authorization-customer: <B2B2C_ACCESS_TOKEN>" \
  -H "Authorization: <B2B2C_ACCESS_TOKEN>" \
  -H "ENV: SIT"
```

#### 4.4.7 Response Example
---
```json
{
  "successCode": "43",
  "successMessage": "Success",
  "oneTimeToken": "eyJhbGciOiJSUzI1NiJ9...",
  "oneTimeTokenExpiry": "2026-06-04T09:35:49+07:00"
}
```

#### 4.4.8 Error List
---
| Messages | Message Code | HTTP Code |
|---|---|---|
| Missing B2BC Token | MISSING_TOKEN | 401 |
| Token Expired | EXPIRED_TOKEN | 401 |
| User Not Found | USER_NOT_FOUND | 401 |
| Generic Exception | GENERIC_EXCEPTION | 500 |

#### 4.4.9 Error Response Example
---
```json
{
  "success": false,
  "errorCodes": ["MISSING_TOKEN"],
  "errors": ["Missing B2BC Token"],
  "data": null,
  "messageCodes": null,
  "messages": null,
  "errorUid": "67de40be-08ef-4950-bbcd-83348c633c5f"
}
```


### 4.5 Access Token By One Time Token 
---
> **Note:** This API should only be hit by the **Avantrade side**. Host side should not generate JWT token — JWT token currently can only be generated by the **SDK**.

#### 4.5.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handle_ott_to_at.png)

#### 4.5.2 URL
---
POST api-gateway/auth-service/authentication/v2/token/by-one-time-token

#### 4.5.3 Header Parameter
---
| Key                  | Type   | Length | Mandatory | Description                                         | Sample Value                              |
|----------------------|--------|--------|-----------|-----------------------------------------------------|--------------------------------------------|
| ENV       | String | N.A    | Y         | Selected Environement (DEV/GAD/SIT/UAT)                                            | DEV     |

#### 4.5.4 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                   | Sample Value              |
|-------------|--------|--------|-----------|--------------------------------|--------------------------|
| oneTimeToken | String | N.A    | Y         | One Time Token | eyJhbGciOiJIUzUxMiJ9... |

#### 4.5.5 Response
---
| Property             | Type Data | Sample Value              |
|----------------------|-----------|---------------------------|
| successCode          | String    | 43                       |
| successMessage       | String    | Success                  |
| jwtToken             | String    | eyJhbGciOiJIUzUxMiJ9...   |
| jwtTokenExpiry       | String    | 900                      |
| refreshToken         | String    | eyJhbGciOiJIUzUxMiJ9...   |
| refreshTokenExpiry   | String    | TimeStamp                     |
| refreshTokenExpiry   | String    | TimeStamp                     |
| webviewUrl   | String    | dynamic Webview URL                     |

#### 4.5.6 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| refreshTokenExpiry  | MST_REFRESH_TOKEN.EXPIRED_AT  |           |

#### 4.5.7 Error List
---
| Messages | Message Code | HTTP Code |
|---|---|---|
| Missing B2BC Token | MISSING_TOKEN | 401 |
| Token Expired | EXPIRED_TOKEN | 401 |
| User Not Found | USER_NOT_FOUND | 401 |
| Generic Exception | GENERIC_EXCEPTION | 500 |

#### 4.5.8 Error Response Example
---
```json
{
  "success": false,
  "errorCodes": ["EXPIRED_TOKEN"],
  "errors": ["Token Expired"],
  "data": null,
  "messageCodes": null,
  "messages": null,
  "errorUid": "67de40be-08ef-4950-bbcd-83348c633c5f"
}
```