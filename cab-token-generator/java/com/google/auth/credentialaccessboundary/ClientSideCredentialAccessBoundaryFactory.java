/*
 * Copyright 2024, Google LLC
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

package com.google.auth.credentialaccessboundary;

import static com.google.auth.oauth2.OAuth2Credentials.getFromServiceLoader;
import static com.google.auth.oauth2.OAuth2Utils.TOKEN_EXCHANGE_URL_FORMAT;
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auth.Credentials;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.StsRequestHandler;
import com.google.auth.oauth2.StsTokenExchangeRequest;
import com.google.auth.oauth2.StsTokenExchangeResponse;
import com.google.common.base.Strings;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;

public final class ClientSideCredentialAccessBoundaryFactory {
  private final GoogleCredentials sourceCredential;
  private final transient HttpTransportFactory transportFactory;
  private final String tokenExchangeEndpoint;
  private String acceessBoundarySessionKey;
  private AccessToken intermediaryAccessToken;

  private ClientSideCredentialAccessBoundaryFactory(Builder builder) {
    this.transportFactory = builder.transportFactory;
    this.sourceCredential = builder.sourceCredential;
    this.tokenExchangeEndpoint = builder.tokenExchangeEndpoint;
  }

  private void fetchCredentials() throws IOException {
    try {
      this.sourceCredential.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException("Unable to refresh the provided source credential.", e);
    }

    AccessToken sourceAccessToken = sourceCredential.getAccessToken();
    if (sourceAccessToken == null || Strings.isNullOrEmpty(sourceAccessToken.getTokenValue())) {
      throw new IOException("The source credential does not have an access token.");
    }

    StsTokenExchangeRequest request =
        StsTokenExchangeRequest.newBuilder(
                sourceAccessToken.getTokenValue(), OAuth2Utils.TOKEN_TYPE_ACCESS_TOKEN)
            .setRequestTokenType(OAuth2Utils.TOKEN_TYPE_ACCESS_BOUNDARY_INTERMEDIARY_TOKEN)
            .build();

    StsRequestHandler handler =
        StsRequestHandler.newBuilder(
                tokenExchangeEndpoint, request, transportFactory.create().createRequestFactory())
            .build();

    StsTokenExchangeResponse response = handler.exchangeToken();
    this.acceessBoundarySessionKey = response.getAccessBoundarySessionKey();
    this.intermediaryAccessToken = response.getAccessToken();

    // The STS endpoint will only return the expiration time for the intermediary token
    // if the original access token represents a service account.
    // The intermediary token's expiration time will always match the source credential expiration.
    // When no expires_in is returned, we can copy the source credential's expiration time.
    if (response.getAccessToken().getExpirationTime() == null) {
      if (sourceAccessToken.getExpirationTime() != null) {
        this.intermediaryAccessToken =
            new AccessToken(
                response.getAccessToken().getTokenValue(), sourceAccessToken.getExpirationTime());
      }
    }
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private GoogleCredentials sourceCredential;
    private HttpTransportFactory transportFactory;
    private String universeDomain;
    private String tokenExchangeEndpoint;

    private Builder() {}

    /**
     * Sets the required source credential used to acquire the intermediary credential.
     *
     * @param sourceCredential the {@code GoogleCredentials} to set
     * @return this {@code Builder} object
     */
    public Builder setSourceCredential(GoogleCredentials sourceCredential) {
      this.sourceCredential = sourceCredential;
      return this;
    }

    /**
     * Sets the HTTP transport factory.
     *
     * @param transportFactory the {@code HttpTransportFactory} to set
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    /**
     * Sets the optional universe domain.
     *
     * @param universeDomain the universe domain to set
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setUniverseDomain(String universeDomain) {
      this.universeDomain = universeDomain;
      return this;
    }

    public ClientSideCredentialAccessBoundaryFactory build() {
      checkNotNull(sourceCredential, "Source credential must not be null.");

      // Use the default HTTP transport factory if none was provided.
      if (transportFactory == null) {
        this.transportFactory =
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
      }

      // Default to GDU when not supplied.
      if (Strings.isNullOrEmpty(universeDomain)) {
        this.universeDomain = Credentials.GOOGLE_DEFAULT_UNIVERSE;
      }

      // Ensure source credential's universe domain matches.
      try {
        if (!universeDomain.equals(sourceCredential.getUniverseDomain())) {
          throw new IllegalArgumentException(
              "The client side access boundary credential's universe domain must be the same as the source "
                  + "credential.");
        }
      } catch (IOException e) {
        // Throwing an IOException would be a breaking change, so wrap it here.
        throw new IllegalStateException(
            "Error occurred when attempting to retrieve source credential universe domain.", e);
      }

      this.tokenExchangeEndpoint = String.format(TOKEN_EXCHANGE_URL_FORMAT, universeDomain);
      return new ClientSideCredentialAccessBoundaryFactory(this);
    }
  }
}
