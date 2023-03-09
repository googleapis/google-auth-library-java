package com.google.auth.oauth2;


import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Map;

/**
 * Encapsulates the service account impersonation options portion of the configuration for
 * ExternalAccountCredentials.
 *
 * <p>If token_lifetime_seconds is not specified, the library will default to a 1-hour lifetime.
 *
 * <pre>
 * Sample configuration:
 * {
 *   ...
 *   "service_account_impersonation": {
 *     "token_lifetime_seconds": 2800
 *    }
 * }
 * </pre>
 */
public class ServiceAccountImpersonationOptions implements Serializable {

  private static final long serialVersionUID = 4250771921886280953L;
  private static final int DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;
  private static final int MAXIMUM_TOKEN_LIFETIME_SECONDS = 43200;
  private static final int MINIMUM_TOKEN_LIFETIME_SECONDS = 600;
  private static final String TOKEN_LIFETIME_SECONDS_KEY = "token_lifetime_seconds";

  final int lifetime;

  ServiceAccountImpersonationOptions(Map<String, Object> optionsMap) {
    if (!optionsMap.containsKey(TOKEN_LIFETIME_SECONDS_KEY)) {
      lifetime = DEFAULT_TOKEN_LIFETIME_SECONDS;
      return;
    }

    try {
      Object lifetimeValue = optionsMap.get(TOKEN_LIFETIME_SECONDS_KEY);
      if (lifetimeValue instanceof BigDecimal) {
        lifetime = ((BigDecimal) lifetimeValue).intValue();
      } else if (optionsMap.get(TOKEN_LIFETIME_SECONDS_KEY) instanceof Integer) {
        lifetime = (int) lifetimeValue;
      } else {
        lifetime = Integer.parseInt((String) lifetimeValue);
      }
    } catch (NumberFormatException | ArithmeticException e) {
      throw new IllegalArgumentException(
          "Value of \"token_lifetime_seconds\" field could not be parsed into an integer.", e);
    }

    if (lifetime < MINIMUM_TOKEN_LIFETIME_SECONDS || lifetime > MAXIMUM_TOKEN_LIFETIME_SECONDS) {
      throw new IllegalArgumentException(
          String.format(
              "The \"token_lifetime_seconds\" field must be between %s and %s seconds.",
              MINIMUM_TOKEN_LIFETIME_SECONDS, MAXIMUM_TOKEN_LIFETIME_SECONDS));
    }
  }

  int getLifetime() {
    return lifetime;
  }
}
