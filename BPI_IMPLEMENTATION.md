
<style>
  pre { font-size: 8px !important; line-height: 1.2 !important; }
  code { font-size: 8px !important; }
</style>

# BPI Implementation

## Table of Contents
1. [Session Handling Flow](#1-session-handling-flow)
2. [B2B Request Signature](#2-b2b-request-signature)
   - [Function](#21-function)
   - [Usage](#22-usage)
3. [B2B2C Request Signature](#3-b2b2c-request-signature)
   - [Function](#31-function)
   - [Usage](#32-usage)
4. [Investment Allocation By B2B2C](#4-investment-allocation-by-b2b2c)
   - [URL](#41-url)
   - [Path Parameter](#42-path-parameter)
   - [Header Parameter](#43-header-parameter)
   - [Response](#44-response)
   - [Error List](#45-error-list)
   - [Sample Response](#46-sample-response)
5. [API Detail](#5-api-detail)
   - [B2B](#51-b2b)
     - [Flowchart](#511-flowchart)
     - [URL](#512-url)
     - [Body Parameter](#513-body-parameter)
     - [Response](#514-response)
     - [Data Relations](#515-data-relations)
     - [Error List](#516-error-list)
   - [Auth Code](#52-auth-code)
     - [Flowchart](#521-flowchart)
     - [URL](#522-url)
     - [Header Parameter](#523-header-parameter)
     - [Body Parameter](#524-body-parameter)
     - [Response](#525-response)
     - [Data Relations](#526-data-relations)
     - [Error List](#527-error-list)
   - [B2B2C](#53-b2b2c)
     - [Flowchart](#531-flowchart)
     - [URL](#532-url)
     - [Header Parameter](#533-header-parameter)
     - [Body Parameter](#534-body-parameter)
     - [Response](#535-response)
     - [Data Relations](#536-data-relations)
     - [Error List](#537-error-list)
   - [One Time Token By B2B2C](#54-one-time-token-by-b2b2c)
     - [Flowchart](#541-flowchart)
     - [URL](#542-url)
     - [Header Parameter](#543-header-parameter)
     - [Body Parameter](#544-body-parameter)
     - [Response](#545-response)
     - [Data Relations](#546-data-relations)
     - [Error List](#547-error-list)
   - [Access Token By One Time Token](#55-access-token-by-one-time-token)
     - [Flowchart](#551-flowchart)
     - [URL](#552-url)
     - [Body Parameter](#553-body-parameter)
     - [Response](#554-response)
     - [Data Relations](#555-data-relations)
     - [Error List](#556-error-list)
   - [Refresh Token](#56-refresh-token)
     - [Flowchart](#561-flowchart)
     - [URL](#562-url)
     - [Body Parameter](#563-body-parameter)
     - [Response](#564-response)
     - [Data Relations](#565-data-relations)
     - [Error List](#566-error-list)

<div style="page-break-after: always;"></div>

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


## 4. Investment Allocation By B2B2C

### 4.1 URL
---
GET portfolio-service/v1/portfolio/allocation-investment/{customerId}

### 4.2 Path Parameter
---
| Key | Type | Length | Mandatory | Description | Sample Value |
|-------------|--------|--------|-----------|--------------------------------------|----------------------------------------|
| customerId | String | N.A | Y | Customer UUID from B2B2C Request | 53e75332-b619-4688-ad45-37d279110a16 |

### 4.3 Header Parameter
---
| Key | Type | Length | Mandatory | Description | Sample Value |
|------------------------|--------|--------|-----------|--------------------------|---------------------------------------------------------------------------------------------------|
| Authorization | String | N.A | Y | JWT Token / B2B2C Token | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |
| authorization-customer | String | N.A | Y | JWT Token / B2B2C Token | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |

### 4.4 Response
---
| Property | Type | Sample Value |
|-------------|-----------|-------------------------------------------|
| success | Boolean | true |
| errorCodes | Array | [] |
| errors | Array | [] |
| data | Array | [ { ... } ] |
| messageCodes| Array | [] |
| messages | Array | [] |

### 4.5 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|----------|
| AUTH_00 | Internal Server Error  | 500      |
| AUTH_01 | Invalid Login User!    | 400      |

### 4.6 Sample Response

Sample Response
---
```json
{
    "success": true,
    "errorCodes": [],
    "errors": [],
    "data": [
        {
            "entityNo": "S202601220125885",
            "customerName": "customer dev tiga",
            "detailList": [
                {
                    "invAccountTypeId": "5a9758d2-9601-47ad-bc97-3e6099fb8636",
                    "invAccountTypeName": "Other",
                    "currency": "IDR",
                    "amount": 1010000000,
                    "totalProduct": 1,
                    "productIds": [
                        "5c48d358-8992-40f4-9110-e62426816bea"
                    ]
                },
                {
                    "invAccountTypeId": "62aff3b3-cc53-446e-af79-bc116ea55f81",
                    "invAccountTypeName": "Other",
                    "currency": "IDR",
                    "amount": 105000000,
                    "totalProduct": 1,
                    "productIds": [
                        "211b2eca-be96-4bbf-bbd8-cb81a8e2ea4a"
                    ]
                }
            ]
        },
        {
            "entityNo": "ALL",
            "customerName": "All",
            "detailList": [
                {
                    "invAccountTypeId": "5a9758d2-9601-47ad-bc97-3e6099fb8636",
                    "invAccountTypeName": "Other",
                    "currency": "IDR",
                    "amount": 1115000000,
                    "totalProduct": 2,
                    "productIds": [
                        "211b2eca-be96-4bbf-bbd8-cb81a8e2ea4a",
                        "5c48d358-8992-40f4-9110-e62426816bea"
                    ]
                }
            ]
        }
    ],
    "messageCodes": [],
    "messages": []
}
```

<div style="page-break-after: always;"></div>

## 5. API Detail

### 5.1 B2B

#### 5.1.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_b2b.png)

#### 5.1.2 URL
---
POST auth-service/authentication/v2/access-token/b2b

#### 5.1.3 Body Parameter
---
| Key            | Type   | Length | Mandatory | Description                          | Sample Value     |
|----------------|--------|--------|-----------|--------------------------------------|-------------------|
| grantType      | String | N A    | Y         | -                                    | client_credentials         |

#### 5.1.4 Response
---
| Property       | Type Data | Sample Value                              |
|---------------|----------|--------------------------------------------|
| accessToken   | String   | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA                 |
| tokenType     | String   | Bearer                                     |
| expiresIn     | String   | 900                                        |
| sessionId     | UUID     | d568e0f0-740e-42fc-a65e-c8860a50cd3d         |
| successCode   | String   | 43                                         |
| successMessage| String   | Success                                    |

#### 5.1.5 Data Relations
---
| Property     | Mapping                          | Relations                    |
|-------------|----------------------------------|------------------------------|
| accessToken | OAuth2Token.getTokenValue        |                              |
| tokenType   | OAuth2AccessToken.getTokenType   |                              |
| sessionId   | MST_USER_SESSIONS.SESSION_ID     |                              |

#### 5.1.6 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|----------|
| AUTH_00 | Internal Server Error  | 500      |
| AUTH_01 | Invalid Login User!    | 400      |

<div style="page-break-after: always;"></div>

#### 5.2 Auth Code

#### 5.2.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/auth_code_flow.png)

#### 5.2.2 URL
---
POST auth-service/authentication/v2/generate-auth-code/b2b2c

#### 5.2.3 Header Parameter
---
| Key            | Type   | Length | Mandatory | Description                                  | Sample Value                              |
|---------------|--------|--------|-----------|----------------------------------------------|--------------------------------------------|
| X-PARTNER-ID  | String | N.A    | Y         | clientId                                     | c04ee779-1a81-4453-83ea-fd370e9f4cc9         |
| X-TIMESTAMP   | String | N.A    | Y         | Timestamp when create secretKey signature    | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...               |
| X-SIGNATURE   | String | N.A    | Y         | secretKey Signature                          | SIGNATURE                                  |
| X-BRANCH-ID   | String | N.A    | Y         | clientId                                     | c04ee779-1a81-4453-83ea-fd370e9f4cc9         |
| X-SESSION-ID  | String | N.A    | Y         | Session id from B2B response                 | 5207d4a3-5666-4d6d-8f1f-7732ca8fa85e         |
| Authorization | String | N.A    | Y         | B2B token                                    | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...               |

#### 5.2.4 Body Parameter
---
| Key            | Type   | Length | Mandatory | Description                                 | Sample Value    |
|---------------|--------|--------|-----------|---------------------------------------------|-----------------|
| paramType     | String | N.A    | Y         | param type used                             | CIF_BANK        |
| paramValue    | String | N.A    | Y         | param value used for get customer data      | CIF2501045138   |
| partnerChannel| String | N.A    | Y         | registered partner channel                  | CH_BPI          |

#### 5.2.5 Response
---
| Property       | Type Data | Sample Value                              |
|---------------|-----------|-------------------------------------------|
| authCode      | String    | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA             |
| successCode   | String    | 43                                        |
| successMessage| String    | Success                                   |

#### 5.2.6 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| authCode  | MST_CLIENT_USER_AUTH_CODE.AUTH_CODE  |           |

#### 5.2.7 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|-----------|
| AUTH_00 | Internal Server Error  | 500       |
| AUTH_01 | Invalid Login User!    | 400       |

<div style="page-break-after: always;"></div>

### 5.3 B2B2C

#### 5.3.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_b2b2c.png)

#### 5.3.2 URL
---
POST auth-service/authentication/v2/access-token/b2b2c

#### 5.3.3 Header Parameter
---
| Key                  | Type   | Length | Mandatory | Description                                         | Sample Value                              |
|----------------------|--------|--------|-----------|-----------------------------------------------------|--------------------------------------------|
| X-CLIENT-KEY         | String | N.A    | Y         | clientId                                            | c04ee779-1a81-4453-83ea-fd370e9f4cc9      |
| X-TIMESTAMP          | String | N.A    | Y         | Timestamp when create secretKey and privateKey signature | 7xDTUTKUlUF1e5XC9OsBxNJEN4C...           |
| X-SIGNATURE          | String | N.A    | Y         | privateKey Signature                                | SIGNATURE                                  |
| X-BRANCH-ID          | String | N.A    | Y         | clientId                                            | c04ee779-1a81-4453-83ea-fd370e9f4cc9      |
| X-SESSION-ID         | String | N.A    | Y         | Session id from B2B response                        | 5207d4a3-5666-4d6d-8f1f-7732ca8fa85e      |
| AUTHORIZATION-CUSTOMER | String | N.A  | Y         | token from B2B Response                             | 5207d4a3-5666-4d6d-8f1f-7732ca8fa85e      |

#### 5.3.4 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                  | Sample Value          |
|-------------|--------|--------|-----------|------------------------------|----------------------|
| grantType    | String | N.A    | Y         | grant type                   | AUTHORIZATION_CODE    |
| authCode     | String | N.A    | Y         | auth code from response      | eyJhbGciOiJIUzUxMiJ9 |
| refreshToken | String | N.A    | Y         | empty by default             | -                     |

#### 5.3.5 Response
---
| Property                | Type Data | Sample Value                              |
|-------------------------|-----------|-------------------------------------------|
| customerId          | String    | UUID                                    |
| accessToken             | String    | B2B2C Token             |
| tokenType               | String    | Bearer                                     |
| accessTokenExpiryTime   | String    | 900                                        |
| refreshToken            | String    | 8S1NjMEMF3IqQr2Q1PgPAN26j1aA             |
| refreshTokenExpiryTime  | String    | 900                                        |
| successCode             | String    | 43                                         |
| successMessage          | String    | Success                                    |

#### 5.3.6 Data Relations
---
| Property               | Mapping                        | Relations |
|------------------------|--------------------------------|-----------|
| accessToken            | OAuth2Token.getTokenValue      |           |
| tokenType              | OAuth2AccessToken.getTokenType |           |
| accessTokenExpiryTime  |                                |           |
| refreshToken           |                                |           |
| refreshTokenExpiryTime |                                |           |

#### 5.3.7 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|-----------|
| AUTH_00 | Internal Server Error  | 500       |
| AUTH_01 | Invalid Login User!    | 400       |

<div style="page-break-after: always;"></div>

### 5.4 One Time Token By B2B2C

#### 5.4.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_ott.png)

#### 5.4.2 URL
---
POST auth-service/authentication/v2/token/by-b2bc-token

#### 5.4.3 Header Parameter
---
| Key                    | Type   | Length | Mandatory | Description              | Sample Value                                                                                       |
|------------------------|--------|--------|-----------|--------------------------|---------------------------------------------------------------------------------------------------|
| authorization-customer  | String | N.A    | Y         | B2B2C Token  | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |
| Authorization          | String | N.A    | Y         | B2B2C Token   | 7SZjVjOzWfm_VuPqilbieMAG8sh7UxhicaCz46h-GqmgTTlW5NXpxCS5dBCjuFw_AODJGoBg9XgFHY_IG5FkLzbYaePcdXRJzUOIUFNw1m3AP3TjtVs2ylfjqmx_MSOy |
| Content-Type           | String | N.A    | Y         | Media type of request body | application/json                                                                                  |

#### 5.4.4 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                  | Sample Value                                                                                       |
|-------------|--------|--------|-----------|------------------------------|---------------------------------------------------------------------------------------------------|
| grantType    | String | N.A    | Y         | grant type                   | AUTHORIZATION_CODE                                                                                 |
| authCode     | String | N.A    | Y         | B2B2C Token      | -YZt6NG9qG-mfnVlaGz9m_4FD8E6KiWphxrv5W8_4500CdoBryhc02j5dQJCr6CaZ-3Em0Vx25YCusNgPb-FalN-N8nDBAA7fdENR4VdQPyK8bWyJ7QzF87veIV_fKTl |
| refreshToken | String | N.A    | Y         | empty by default             | ""                                                                                                |

#### 5.4.5 Response
---
| Property            | Type Data | Sample Value      |
|---------------------|-----------|------------------|
| successCode         | String    | 43               |
| successMessage      | String    | Success          |
| oneTimeToken        | String    | eyJhbGciOiJIUz... |
| oneTimeTokenExpiry  | String    | 900              |

#### 5.4.6 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| oneTimeToken  | MST_ONE_TIME_TOKEN.TOKEN  |           |
| oneTimeTokenExpiry  | MST_ONE_TIME_TOKEN.EXPIRED_AT  |           |

#### 5.4.7 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|-----------|
| AUTH_00 | Internal Server Error  | 500       |
| AUTH_01 | Invalid Login User!    | 400       |


### 5.5 Access Token By One Time Token 
---

#### 5.5.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handle_ott_to_at.png)

#### 5.5.2 URL
---
POST auth-service/authentication/v2/token/by-one-time-token

#### 5.5.3 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                   | Sample Value              |
|-------------|--------|--------|-----------|-------------------------------|--------------------------|
| oneTimeToken | String | N.A    | Y         | One Time Token | eyJhbGciOiJIUzUxMiJ9... |

#### 5.5.4 Response
---
| Property             | Type Data | Sample Value              |
|----------------------|-----------|--------------------------|
| successCode          | String    | 43                       |
| successMessage       | String    | Success                  |
| jwtToken             | String    | eyJhbGciOiJIUzUxMiJ9...   |
| jwtTokenExpiry       | String    | 900                      |
| refreshToken         | String    | eyJhbGciOiJIUzUxMiJ9...   |
| refreshTokenExpiry   | String    | TimeStamp                     |

#### 5.5.5 Data Relations
---
| Property  | Mapping                              | Relations |
|-----------|--------------------------------------|-----------|
| refreshTokenExpiry  | MST_REFRESH_TOKEN.EXPIRED_AT  |           |

#### 5.5.6 Error List
---
| Code    | Message Error           | HTTP Code |
|---------|------------------------|-----------|
| AUTH_00 | Internal Server Error  | 500       |
| AUTH_01 | Invalid Login User!    | 400       |


#### 5.6 Refresh Token
---

#### 5.6.1 Flowchart
---
![Flowchart](https://raw.githubusercontent.com/triandresono/andre-images/main/session_handling_refresh_token.png)

#### 5.6.2 URL
---
POST auth-service/authentication/v2/refresh-token

#### 5.6.3 Body Parameter
---
| Key          | Type   | Length | Mandatory | Description                   | Sample Value              |
|-------------|--------|--------|-----------|-------------------------------|--------------------------|
| jwtToken     | String | N.A    | Y         | Old JWT Token | eyJhbGciOiJIUzUxMiJ9... |
| refreshToken | String | N.A    | Y         | Current Refresh Token | eyJhbGciOiJIUzUxMiJ9... |

#### 5.6.4 Response
---
| Property             | Type Data | Sample Value              |
|----------------------|-----------|--------------------------|
| successCode          | String    | 43                       |
| successMessage       | String    | Success                  |
| jwtToken             | String    | eyJhbGciOiJIUzUxMiJ9...   |
| jwtTokenExpiry       | String    | 900                      |
| refreshToken         | String    | eyJhbGciOiJIUzUxMiJ9...   |
| refreshTokenExpiry   | String    | TimeStamp                     |

#### 5.6.5 Data Relations
---
| Property             | Mapping                         | Relations |
|----------------------|---------------------------------|-----------|
| refreshTokenExpiry   | MST_REFRESH_TOKEN.EXPIRED_AT    |           |

#### 5.6.6 Error List
---
| Code        | Message Error                    | HTTP Code |
|------------|----------------------------------|-----------|
| AUTH_04    | Invalid or expired refresh token | 400       |
| AUTH_00    | Internal Server Error            | 500       |

