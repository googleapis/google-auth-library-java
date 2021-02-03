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

import static com.google.api.client.util.Preconditions.checkNotNull;

import java.util.ArrayList;
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
    long expiresAtMilliseconds = System.currentTimeMillis() + expiresIn * 1000L;
    this.accessToken = new AccessToken(accessToken, new Date(expiresAtMilliseconds));
    this.issuedTokenType = checkNotNull(issuedTokenType);
    this.tokenType = checkNotNull(tokenType);
    this.refreshToken = refreshToken;
    this.scopes = scopes;
  }

  public static Builder newBuilder(
      String accessToken, String issuedTokenType, String tokenType, Long expiresIn) {
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
    return new ArrayList<>(scopes);
  }

  public static class Builder {
    private String accessToken;
    private String issuedTokenType;
    private String tokenType;
    private Long expiresIn;

    @Nullable private String refreshToken;
    @Nullable private List<String> scopes;

    private Builder(String accessToken, String issuedTokenType, String tokenType, Long expiresIn) {
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
      return new StsTokenExchangeResponse(
          accessToken, issuedTokenType, tokenType, expiresIn, refreshToken, scopes);
    }
  }
}
