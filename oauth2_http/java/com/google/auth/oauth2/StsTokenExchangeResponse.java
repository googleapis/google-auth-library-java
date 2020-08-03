package com.google.auth.oauth2;


import static com.google.api.client.util.Preconditions.checkNotNull;

import com.google.api.client.util.Clock;
import java.util.Date;
import java.util.List;
import javax.annotation.Nullable;

/**
 * Defines an OAuth 2.0 token exchange successful response. Based on
 * https://tools.ietf.org/html/rfc8693#section-2.2.1.
 */
public class StsTokenExchangeResponse {
  private AccessToken accessToken;
  private String issuedTokenType;
  private String tokenType;
  private Long expiresIn;

  @Nullable private String refreshToken;
  @Nullable private List<String> scopes;

  private StsTokenExchangeResponse(
      String accessToken,
      String issuedTokenType,
      String tokenType,
      Long expiresIn,
      @Nullable String refreshToken,
      @Nullable List<String> scopes) {
    checkNotNull(accessToken);
    this.expiresIn = checkNotNull(expiresIn);
    long expiresAtMilliseconds = Clock.SYSTEM.currentTimeMillis() + expiresIn * 1000L;
    this.accessToken = new AccessToken(accessToken, new Date(expiresAtMilliseconds));
    this.issuedTokenType = checkNotNull(issuedTokenType);
    this.tokenType = checkNotNull(tokenType);
    this.refreshToken = refreshToken;
    this.scopes = scopes;
  }

  public static Builder newBuilder(String accessToken,
      String issuedTokenType,
      String tokenType,
      Long expiresIn) {
    return new Builder(accessToken, issuedTokenType, tokenType, expiresIn);
  }

  public AccessToken getAccessToken() {
    return accessToken;
  }

  public String getIssuedTokenType() {
    return issuedTokenType;
  }

  public String getTokenType() {
    return tokenType;
  }

  public Long getExpiresIn() {
    return expiresIn;
  }

  @Nullable
  public String getRefreshToken() {
    return refreshToken;
  }

  @Nullable
  public List<String> getScopes() {
    return scopes;
  }

  public static class Builder {
    private String accessToken;
    private String issuedTokenType;
    private String tokenType;
    private Long expiresIn;

    @Nullable private String refreshToken;
    @Nullable private List<String> scopes;

    private Builder(String accessToken,
        String issuedTokenType,
        String tokenType,
        Long expiresIn) {
      this.accessToken = accessToken;
      this.issuedTokenType = issuedTokenType;
      this.tokenType = tokenType;
      this.expiresIn = expiresIn;
    }

    public StsTokenExchangeResponse.Builder setRefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
      return this;
    }

    public StsTokenExchangeResponse.Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public StsTokenExchangeResponse build() {
      return new StsTokenExchangeResponse(accessToken, issuedTokenType, tokenType, expiresIn,
          refreshToken, scopes);
    }
  }
}

