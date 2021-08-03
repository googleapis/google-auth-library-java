/*
 * Copyright 2021 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.annotation.Nullable;

/**
 * Defines an OAuth 2.0 token exchange successful response. Based on
 * https://tools.ietf.org/html/rfc8693#section-2.2.1.
 */
final class StsTokenExchangeResponse {
  private final AccessToken accessToken;
  private final String issuedTokenType;
  private final String tokenType;

  @Nullable private final Long expiresInSeconds;
  @Nullable private final String refreshToken;
  @Nullable private final List<String> scopes;

  private StsTokenExchangeResponse(
      String accessToken,
      String issuedTokenType,
      String tokenType,
      @Nullable Long expiresInSeconds,
      @Nullable String refreshToken,
      @Nullable List<String> scopes) {
    checkNotNull(accessToken);

    this.expiresInSeconds = expiresInSeconds;
    Long expiresAtMilliseconds =
        expiresInSeconds == null ? null : System.currentTimeMillis() + expiresInSeconds * 1000L;
    Date date = expiresAtMilliseconds == null ? null : new Date(expiresAtMilliseconds);
    this.accessToken = new AccessToken(accessToken, date);

    this.issuedTokenType = checkNotNull(issuedTokenType);
    this.tokenType = checkNotNull(tokenType);
    this.refreshToken = refreshToken;
    this.scopes = scopes;
  }

  public static Builder newBuilder(String accessToken, String issuedTokenType, String tokenType) {
    return new Builder(accessToken, issuedTokenType, tokenType);
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

  @Nullable
  public Long getExpiresInSeconds() {
    return expiresInSeconds;
  }

  @Nullable
  public String getRefreshToken() {
    return refreshToken;
  }

  @Nullable
  public List<String> getScopes() {
    if (scopes == null) {
      return null;
    }
    return new ArrayList<>(scopes);
  }

  public static class Builder {
    private final String accessToken;
    private final String issuedTokenType;
    private final String tokenType;

    @Nullable private Long expiresInSeconds;
    @Nullable private String refreshToken;
    @Nullable private List<String> scopes;

    private Builder(String accessToken, String issuedTokenType, String tokenType) {
      this.accessToken = accessToken;
      this.issuedTokenType = issuedTokenType;
      this.tokenType = tokenType;
    }

    public StsTokenExchangeResponse.Builder setExpiresInSeconds(long expiresInSeconds) {
      this.expiresInSeconds = expiresInSeconds;
      return this;
    }

    public StsTokenExchangeResponse.Builder setRefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
      return this;
    }

    public StsTokenExchangeResponse.Builder setScopes(List<String> scopes) {
      if (scopes != null) {
        this.scopes = new ArrayList<>(scopes);
      }
      return this;
    }

    public StsTokenExchangeResponse build() {
      return new StsTokenExchangeResponse(
          accessToken, issuedTokenType, tokenType, expiresInSeconds, refreshToken, scopes);
    }
  }
}
