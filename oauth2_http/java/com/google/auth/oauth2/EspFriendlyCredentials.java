/*
 * Copyright 2018, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

import com.google.api.client.util.Preconditions;
import java.util.Objects;

/**
 * Abstract base class for ESP-friendly credentials.
 *
 * Cloud Endpoints' Extensible Service Proxy (ESP), requires JWTs instead of
 * access tokens.  Subclasses provide the required JWT from the "id_token" of
 * their refreshed token.
 */
public abstract class EspFriendlyCredentials extends GoogleCredentials {
  protected static final String ACCESS_TOKEN_TYPE = "access_token";
  protected static final String ID_TOKEN_TYPE = "id_token";
  protected final String tokenType;

  protected EspFriendlyCredentials(String tokenType) {
    Preconditions.checkNotNull(tokenType);
    this.tokenType = tokenType;
  }

  protected EspFriendlyCredentials(AccessToken accessToken, String tokenType) {
    super(accessToken);
    Preconditions.checkNotNull(tokenType);
    this.tokenType = tokenType;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof EspFriendlyCredentials)) return false;
    if (!super.equals(o)) return false;
    EspFriendlyCredentials that = (EspFriendlyCredentials) o;
    return Objects.equals(tokenType, that.tokenType);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), tokenType);
  }
}
