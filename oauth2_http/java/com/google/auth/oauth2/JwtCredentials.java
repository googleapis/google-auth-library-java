/*
 * Copyright 2019, Google Inc. All rights reserved.
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

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.http.AuthHttpConstants;
import com.google.auto.value.AutoValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;

public class JwtCredentials extends Credentials {
  private static final String JWT_ACCESS_PREFIX = OAuth2Utils.BEARER_PREFIX;
  private static final String JWT_INCOMPLETE_ERROR_MESSAGE = "JWT claims must contain audience, "
      + "issuer, and subject.";

  private final PrivateKey privateKey;
  private final String privateKeyId;
  private final Claims claims;
  private final Long lifeSpanSeconds;
  @VisibleForTesting
  transient Clock clock;

  private transient String jwt;
  private transient Long expiry;

  JwtCredentials(Builder builder) {
    this.privateKey = Preconditions.checkNotNull(builder.getPrivateKey());
    this.privateKeyId = Preconditions.checkNotNull(builder.getPrivateKeyId());
    this.claims = Preconditions.checkNotNull(builder.getClaims());
    Preconditions.checkState(claims.isComplete(), JWT_INCOMPLETE_ERROR_MESSAGE);
    this.lifeSpanSeconds = Preconditions.checkNotNull(builder.getLifeSpanSeconds());
    this.clock = Preconditions.checkNotNull(builder.getClock());
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  @Override
  public void refresh() throws IOException {
    // TODO(chingor): Add lock for refreshing credentials
    JsonWebSignature.Header header = new JsonWebSignature.Header();
    header.setAlgorithm("RS256");
    header.setType("JWT");
    header.setKeyId(privateKeyId);

    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    long currentTime = clock.currentTimeMillis();
    payload.setAudience(claims.getAudience());
    payload.setIssuer(claims.getIssuer());
    payload.setSubject(claims.getSubject());
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    expiry = currentTime / 1000 + lifeSpanSeconds;
    payload.setExpirationTimeSeconds(expiry);

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;

    try {
      jwt = JsonWebSignature.signUsingRsaSha256(privateKey, jsonFactory, header, payload);
    } catch (GeneralSecurityException e) {
      throw new IOException("Error signing service account JWT access header with private key.", e);
    }
  }

  private boolean shouldRefresh() {
    return expiry == null || getClock().currentTimeMillis() / 1000 > expiry;
  }

  public JwtCredentials withClaims(Claims newClaims) {
    return JwtCredentials.newBuilder()
        .setPrivateKey(privateKey)
        .setPrivateKeyId(privateKeyId)
        .setClaims(claims.merge(newClaims))
        .build();
  }

  @Override
  public String getAuthenticationType() {
    return "JWT";
  }

  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    if (shouldRefresh()) {
      refresh();
    }
    List<String> newAuthorizationHeaders = Collections.singletonList(JWT_ACCESS_PREFIX + jwt);
    return Collections.singletonMap(AuthHttpConstants.AUTHORIZATION, newAuthorizationHeaders);
  }

  @Override
  public boolean hasRequestMetadata() {
    return true;
  }

  @Override
  public boolean hasRequestMetadataOnly() {
    return true;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof JwtCredentials)) {
      return false;
    }
    JwtCredentials other = (JwtCredentials) obj;
    return Objects.equals(this.privateKey, other.privateKey)
        && Objects.equals(this.privateKeyId, other.privateKeyId)
        && Objects.equals(this.claims, other.claims)
        && Objects.equals(this.lifeSpanSeconds, other.lifeSpanSeconds);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.privateKey, this.privateKeyId, this.claims, this.lifeSpanSeconds);
  }

  Clock getClock() {
    if (clock == null) {
      clock = Clock.SYSTEM;
    }
    return clock;
  }

  public static class Builder {

    private PrivateKey privateKey;
    private String privateKeyId;
    private Claims claims;
    private Clock clock = Clock.SYSTEM;
    private Long lifeSpanSeconds = TimeUnit.HOURS.toSeconds(1);

    public Builder setPrivateKey(PrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public PrivateKey getPrivateKey() {
      return privateKey;
    }

    public Builder setPrivateKeyId(String privateKeyId) {
      this.privateKeyId = privateKeyId;
      return this;
    }

    public String getPrivateKeyId() {
      return privateKeyId;
    }

    public Builder setClaims(Claims claims) {
      this.claims = claims;
      return this;
    }

    public Claims getClaims() {
      return claims;
    }

    public Builder setLifeSpanSeconds(Long lifeSpanSeconds) {
      this.lifeSpanSeconds = lifeSpanSeconds;
      return this;
    }

    public Long getLifeSpanSeconds() {
      return lifeSpanSeconds;
    }

    Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    Clock getClock() {
      return clock;
    }

    public JwtCredentials build() {
      return new JwtCredentials(this);
    }
  }

  @AutoValue
  public abstract static class Claims implements Serializable {
    @Nullable
    abstract String getAudience();

    @Nullable
    abstract String getIssuer();

    @Nullable
    abstract String getSubject();

    static Builder newBuilder() {
      return new AutoValue_JwtCredentials_Claims.Builder();
    }

    public Claims merge(Claims other) {
      return new AutoValue_JwtCredentials_Claims.Builder()
          .setAudience(other.getAudience() == null ? getAudience() : other.getAudience())
          .setIssuer(other.getIssuer() == null ? getIssuer() : other.getIssuer())
          .setSubject(other.getSubject() == null ? getSubject() : other.getSubject())
          .build();
    }

    public boolean isComplete() {
      return getAudience() != null && getIssuer() != null && getSubject() != null;
    }

    @AutoValue.Builder
    abstract static class Builder {
      abstract Builder setAudience(String audience);
      abstract Builder setIssuer(String issuer);
      abstract Builder setSubject(String subject);
      abstract Claims build();
    }
  }
}
