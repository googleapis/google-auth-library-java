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

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.CredentialAccessBoundary;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.StsRequestHandler;
import com.google.auth.oauth2.StsTokenExchangeRequest;
import com.google.auth.oauth2.StsTokenExchangeResponse;
import com.google.common.base.Strings;
import com.google.common.util.concurrent.SettableFuture;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.annotation.Nullable;

public final class ClientSideCredentialAccessBoundaryFactory {
  private final GoogleCredentials sourceCredential;
  private final transient HttpTransportFactory transportFactory;
  private final String tokenExchangeEndpoint;
  private String accessBoundarySessionKey;
  private AccessToken intermediateAccessToken;
  private final Duration minimumTokenLifetime;
  private final Duration refreshMargin;
  private static final Duration DEFAULT_REFRESH_MARGIN = Duration.ofMinutes(30);
  private static final Duration DEFAULT_MINIMUM_TOKEN_LIFETIME = Duration.ofMinutes(3);
  private final Object refreshLock = new Object[0]; // Lock for refresh operations
  @Nullable private SettableFuture<Void> currentRefreshFuture;
  private final ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor();

  private ClientSideCredentialAccessBoundaryFactory(Builder builder) {
    this.transportFactory = builder.transportFactory;
    this.sourceCredential = builder.sourceCredential;
    this.tokenExchangeEndpoint = builder.tokenExchangeEndpoint;
    this.refreshMargin =
        builder.refreshMargin != null ? builder.refreshMargin : DEFAULT_REFRESH_MARGIN;
    this.minimumTokenLifetime =
        builder.minimumTokenLifetime != null
            ? builder.minimumTokenLifetime
            : DEFAULT_MINIMUM_TOKEN_LIFETIME;
  }

  /**
   * Refreshes the source credential and exchanges it for an intermediate access token using the STS
   * endpoint.
   *
   * <p>If the source credential is expired, it will be refreshed. A token exchange request is then
   * made to the STS endpoint. The resulting intermediate access token and access boundary session
   * key are stored. The intermediate access token's expiration time is determined as follows:
   *
   * <ol>
   *   <li>If the STS response includes `expires_in`, that value is used.
   *   <li>Otherwise, if the source credential has an expiration time, that value is used.
   *   <li>Otherwise, the intermediate token will have no expiration time.
   * </ol>
   *
   * @throws IOException If an error occurs during credential refresh or token exchange.
   */
  private void refreshCredentials() throws IOException {
    try {
      // Force a refresh on the source credentials. The intermediate token's lifetime is tied to the
      // source credential's expiration. The factory's refreshMargin might be different from the
      // refreshMargin on source credentials. This ensures the intermediate access token
      // meets this factory's refresh margin and minimum lifetime requirements.
      sourceCredential.refresh();
    } catch (IOException e) {
      throw new IOException("Unable to refresh the provided source credential.", e);
    }

    AccessToken sourceAccessToken = sourceCredential.getAccessToken();
    if (sourceAccessToken == null || Strings.isNullOrEmpty(sourceAccessToken.getTokenValue())) {
      throw new IllegalStateException("The source credential does not have an access token.");
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

    synchronized (refreshLock) {
      this.accessBoundarySessionKey = response.getAccessBoundarySessionKey();
      this.intermediateAccessToken = getTokenFromResponse(response, sourceAccessToken);
    }
  }

  private static AccessToken getTokenFromResponse(
      StsTokenExchangeResponse response, AccessToken sourceAccessToken) {
    AccessToken intermediateToken = response.getAccessToken();

    // The STS endpoint will only return the expiration time for the intermediate token
    // if the original access token represents a service account.
    // The intermediate token's expiration time will always match the source credential
    // expiration.
    // When no expires_in is returned, we can copy the source credential's expiration time.
    if (intermediateToken.getExpirationTime() == null
        && sourceAccessToken.getExpirationTime() != null) {
      return new AccessToken(
          intermediateToken.getTokenValue(), sourceAccessToken.getExpirationTime());
    }
    return intermediateToken; // Return original if no modification needed
  }

  private void startAsynchronousRefresh() {
    // Obtain the lock before checking or modifying currentRefreshFuture to prevent race conditions.
    synchronized (refreshLock) {
      // Only start an asynchronous refresh if one is not already in progress.
      if (currentRefreshFuture == null || currentRefreshFuture.isDone()) {
        SettableFuture<Void> future = SettableFuture.create();
        currentRefreshFuture = future;
        backgroundExecutor.execute(
            () -> {
              try {
                refreshCredentials();
                future.set(null); // Signal successful completion.
              } catch (Throwable t) {
                future.setException(t); // Set the exception if refresh fails.
              } finally {
                currentRefreshFuture = null;
              }
            });
      }
    }
  }

  private void blockingRefresh() throws IOException {
    // Obtain the lock before checking the currentRefreshFuture to prevent race conditions.
    synchronized (refreshLock) {
      if (currentRefreshFuture != null && !currentRefreshFuture.isDone()) {
        try {
          currentRefreshFuture.get(); // Wait for the asynchronous refresh to complete.
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt(); // Restore the interrupt status
          throw new IOException("Interrupted while waiting for asynchronous refresh.", e);
        } catch (ExecutionException e) {
          Throwable cause = e.getCause(); // Unwrap the underlying cause
          if (cause instanceof IOException) {
            throw (IOException) cause;
          } else {
            throw new IOException("Asynchronous refresh failed.", cause);
          }
        }
      } else {
        // No asynchronous refresh is running, perform a synchronous refresh.
        refreshCredentials();
      }
    }
  }

  /**
   * Refreshes the intermediate access token and access boundary session key if required.
   *
   * <p>This method checks the expiration time of the current intermediate access token and
   * initiates a refresh if necessary. The refresh process also refreshes the underlying source
   * credentials.
   *
   * @throws IOException If an error occurs during the refresh process, such as network issues,
   *     invalid credentials, or problems with the token exchange endpoint.
   */
  private void refreshCredentialsIfRequired() throws IOException {
    AccessToken localAccessToken = intermediateAccessToken;
    if (localAccessToken != null) {
      Date expirationTime = localAccessToken.getExpirationTime();
      if (expirationTime == null) {
        return; // Token does not expire, no refresh needed.
      }

      Duration remaining =
          Duration.ofMillis(expirationTime.getTime() - Clock.SYSTEM.currentTimeMillis());
      if (remaining.compareTo(minimumTokenLifetime) <= 0) {
        // Intermediate token has expired or remaining lifetime is less than the minimum required
        // for CAB token generation. Perform a synchronous refresh immediately.
        blockingRefresh();
      } else if (remaining.compareTo(refreshMargin) <= 0) {
        // The token is nearing expiration, start an asynchronous refresh in the background.
        startAsynchronousRefresh();
      }
    } else {
      // No intermediate access token exists; a synchronous refresh must be performed.
      blockingRefresh();
    }
  }

  public AccessToken generateToken(CredentialAccessBoundary accessBoundary) {
    // TODO(negarb/jiahuah): Implement generateToken
    throw new UnsupportedOperationException("generateToken is not yet implemented.");
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private GoogleCredentials sourceCredential;
    private HttpTransportFactory transportFactory;
    private String universeDomain;
    private String tokenExchangeEndpoint;
    private Duration minimumTokenLifetime;
    private Duration refreshMargin;

    private Builder() {}

    /**
     * Sets the required source credential.
     *
     * @param sourceCredential the {@code GoogleCredentials} to set
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setSourceCredential(GoogleCredentials sourceCredential) {
      this.sourceCredential = sourceCredential;
      return this;
    }

    /**
     * Sets the minimum acceptable lifetime for a generated CAB token.
     *
     * <p>This value determines the minimum remaining lifetime required on the intermediate token
     * before a CAB token can be generated. If the intermediate token's remaining lifetime is less
     * than this value, CAB token generation will be blocked and a refresh will be initiated. This
     * ensures that generated CAB tokens have a sufficient lifetime for use.
     *
     * @param minimumTokenLifetime The minimum acceptable lifetime for a generated CAB token. Must
     *     be positive.
     * @return This {@code Builder} object.
     * @throws IllegalArgumentException if minimumTokenLifetime is negative or zero.
     */
    @CanIgnoreReturnValue
    public Builder setMinimumTokenLifetime(Duration minimumTokenLifetime) {
      if (minimumTokenLifetime.isNegative() || minimumTokenLifetime.isZero()) {
        throw new IllegalArgumentException("Minimum token lifetime must be positive.");
      }
      this.minimumTokenLifetime = minimumTokenLifetime;
      return this;
    }

    /**
     * Sets the refresh margin for the intermediate access token.
     *
     * <p>This duration specifies how far in advance of the intermediate access token's expiration
     * time an asynchronous refresh should be initiated. If not provided, it will default to 30
     * minutes.
     *
     * @param refreshMargin The refresh margin. Must be positive.
     * @return This {@code Builder} object.
     * @throws IllegalArgumentException if refreshMargin is negative or zero.
     */
    @CanIgnoreReturnValue
    public Builder setRefreshMargin(Duration refreshMargin) {
      if (refreshMargin.isNegative() || refreshMargin.isZero()) {
        throw new IllegalArgumentException("Refresh margin must be positive.");
      }
      this.refreshMargin = refreshMargin;
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
