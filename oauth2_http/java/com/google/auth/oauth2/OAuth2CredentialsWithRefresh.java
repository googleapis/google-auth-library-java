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

import java.io.IOException;

/**
 * A refreshable alternative to {@link OAuth2Credentials}.
 *
 * <p>To enable automatic token refreshes, you must provide an {@link OAuth2RefreshHandler}.
 */
public class OAuth2CredentialsWithRefresh extends OAuth2Credentials {

  /** Interface for the refresh handler. */
  public interface OAuth2RefreshHandler {
    AccessToken refreshAccessToken() throws IOException;
  }

  private final OAuth2RefreshHandler refreshHandler;

  protected OAuth2CredentialsWithRefresh(
      AccessToken accessToken, OAuth2RefreshHandler refreshHandler) {
    super(accessToken);
    this.refreshHandler = checkNotNull(refreshHandler);
  }

  /** Refreshes the access token using the provided {@link OAuth2RefreshHandler}. */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    // Delegate refresh to the provided refresh handler.
    return refreshHandler.refreshAccessToken();
  }

  /** Returns the provided {@link OAuth2RefreshHandler}. */
  public OAuth2RefreshHandler getRefreshHandler() {
    return refreshHandler;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends OAuth2Credentials.Builder {

    private OAuth2RefreshHandler refreshHandler;

    private Builder() {}

    @Override
    public Builder setAccessToken(AccessToken token) {
      super.setAccessToken(token);
      return this;
    }

    public Builder setRefreshHandler(OAuth2RefreshHandler handler) {
      this.refreshHandler = handler;
      return this;
    }

    public OAuth2CredentialsWithRefresh build() {
      return new OAuth2CredentialsWithRefresh(getAccessToken(), refreshHandler);
    }
  }
}
