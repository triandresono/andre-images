# Avantrade Self Service SDK – Android Integration (Steps 1–6)

---

## 1. Integration Flow

1. Prepare SDK configuration
2. Register SDK listeners
3. Launch the SDK with a target page
4. SDK validates configuration and initializes session

All subsequent operations are handled internally by the SDK.

---

## 2. SDK Configuration

Create a valid `SelfServiceConfiguration` instance before proceeding.

```java
SelfServiceConfiguration config = new SelfServiceConfiguration(
    AvantradeEnvironment.SIT,          // DEV | UAT | PROD | SIT
    expiryAtEpochMillis                // long (epoch millis)
);
```

---

## 3. Listener Registration

Listeners **must** be registered **before** calling `AvantradeSDK.launch(...)`.

### 3.1 State Listener

Observes SDK lifecycle: configuration validation, session init, WebView preload, and error handling. Use it to show loading states or catch errors.

```java
AvantradeSDK.setStateListener((state, message) -> {
    switch (state) {
        case LOADING:  // Initializing or background work
            break;
        case SUCCESS:  // A step completed successfully
            break;
        case ERROR:    // SDK stopped due to an error
            break;
    }
});
```

### 3.2 Session Listener

Fires **1 minute before session expiry** based on the `expiryAt` value passed in config. When triggered, the host app should request a new One Time Token from its backend and call `updateSession()` with the refreshed expiry timestamp.

```java
AvantradeSDK.setSessionListener(expiryAtEpochMillis -> {
    // Current session expiry time in epoch millis
    // Request a new One Time Token from your backend and update the session
});
```

### 3.3 Update Session

Updates session expiry **without** restarting the SDK. Replaces the old expiry, cancels the previous callback, and reschedules a new one.

```java
AvantradeSDK.updateSession(newExpiryAtEpochMillis);
```

---

## 4. Launch SDK

After configuration and listeners are set, launch the SDK with a One Time Token and a target `Page`. The SDK will exchange the One Time Token with Avantrade's backend to obtain a JWT and Refresh Token — after which the token is immediately revoked. This triggers: config validation → token exchange → session init → WebView preload → UI launch.

```java
AvantradeSDK.launch(context, configuration, oneTimeToken, page);
```

---

| Parameter | Type | Description |
|-----------|------|-------------|
| `context` | `Context` | Android context |
| `configuration` | `SelfServiceConfiguration` | SDK config (environment + expiry) |
| `oneTimeToken` | `String` | Short-lived token obtained from your backend. Used once to retrieve JWT — immediately revoked after exchange. |
| `page` | `Page` | Target screen to launch (see Section 6) |

See **Section 6** for the full list of supported pages and their usage.

---

## 5. Disposing the SDK

Call this method when the user logs out or when the SDK is no longer needed. This will release all internal resources, including the preloaded WebView and session state.

After calling `dispose()`, the SDK cannot be used until `launch()` is called again.

> ⚠️ Do not call `dispose()` during normal navigation or app backgrounding, as this will force a full reload on the next launch.

```java
AvantradeSDK.dispose();
```

---

## 6. Supported Pages

The SDK uses a `Page` abstraction to determine which screen is loaded on launch. Pass a `Page` instance as the **fourth** argument to `AvantradeSDK.launch(...)`.

### 6.1 DashboardPage

Launches the main dashboard screen. No additional parameters required.

```java
AvantradeSDK.launch(context, config, oneTimeToken, new DashboardPage());
```

---

### 6.2 OrderFormPage

Launches the order/buy form screen. No additional parameters required.

```java
AvantradeSDK.launch(context, config, oneTimeToken, new OrderFormPage());
```

---

### 6.3 InvestmentFundPage

Launches the product holding screen for a specific investment fund type. Requires a `typeId` corresponding to the fund's unique identifier.

| Parameter | Type | Description |
|-----------|------|-------------|
| `typeId` | `String` | Unique identifier (UUID) of the investment fund type |

```java
AvantradeSDK.launch(context, config, oneTimeToken, new InvestmentFundPage("your-fund-uuid"));
```

---

### 6.4 Page Summary

| Page Class | Target Screen | Parameters |
|---|---|---|
| `DashboardPage` | Main dashboard | None |
| `OrderFormPage` | Buy/order form | None |
| `InvestmentFundPage` | Product holding | `typeId` (String, UUID) |