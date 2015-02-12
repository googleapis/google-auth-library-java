package com.google.auth.oauth2;

import java.util.Date;

/**
 * Represents a temporary OAuth2 access token and its expiration information.
 */
public class AccessToken {

  private final String tokenValue;
  private final Long expirationTimeMillis;

  /**
   * @param tokenValue String representation of the access token.
   * @param expirationTime Time when access token will expire.
   */
  public AccessToken(String tokenValue, Date expirationTime) {
    this.tokenValue = tokenValue;
    this.expirationTimeMillis = (expirationTime == null) ? null : expirationTime.getTime();
  }

  /**
   * String representation of the access token.
   */
  public String getTokenValue() {
    return tokenValue;
  }

  /**
   * Time when access token will expire.
   */
  public Date getExpirationTime() {
    if (expirationTimeMillis == null) {
      return null;
    }
    return new Date(expirationTimeMillis);
  }

  Long getExpirationTimeMillis() {
    return expirationTimeMillis;
  }
}
