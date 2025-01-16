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
import com.google.auth.credentialaccessboundary.protobuf.ClientSideAccessBoundaryProto.ClientSideAccessBoundary;
import com.google.auth.credentialaccessboundary.protobuf.ClientSideAccessBoundaryProto.ClientSideAccessBoundaryRule;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.CredentialAccessBoundary;
import com.google.auth.oauth2.CredentialAccessBoundary.AccessBoundaryRule;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.StsRequestHandler;
import com.google.auth.oauth2.StsTokenExchangeRequest;
import com.google.auth.oauth2.StsTokenExchangeResponse;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.util.concurrent.AbstractFuture;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListenableFutureTask;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.CelOptions;
import dev.cel.common.CelProtoAbstractSyntaxTree;
import dev.cel.common.CelValidationException;
import dev.cel.compiler.CelCompiler;
import dev.cel.compiler.CelCompilerFactory;
import dev.cel.expr.Expr;
import java.io.IOException;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import javax.annotation.Nullable;
import java.util.Base64;
import java.util.List;
import java.security.GeneralSecurityException;

public class ClientSideCredentialAccessBoundaryFactory {
  static final Duration DEFAULT_REFRESH_MARGIN = Duration.ofMinutes(30);
  static final Duration DEFAULT_MINIMUM_TOKEN_LIFETIME = Duration.ofMinutes(3);
  private final GoogleCredentials sourceCredential;
  private final transient HttpTransportFactory transportFactory;
  private final String tokenExchangeEndpoint;
  private final Duration minimumTokenLifetime;
  private final Duration refreshMargin;
  private transient RefreshTask refreshTask;
  private final Object refreshLock = new byte[0];
  private volatile IntermediateCredentials intermediateCredentials = null;
  private final Clock clock;
  private final CelCompiler celCompiler;

  enum RefreshType {
    NONE,
    ASYNC,
    BLOCKING
  }

  private ClientSideCredentialAccessBoundaryFactory(Builder builder) {
    this.transportFactory = builder.transportFactory;
    this.sourceCredential = builder.sourceCredential;
    this.tokenExchangeEndpoint = builder.tokenExchangeEndpoint;

    // Initializes the Tink AEAD registry for encrypting the client-side
    // restrictions.
    try {
      AeadConfig.register();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Error occurred when registering Tink", e);
    }

    CelOptions options = CelOptions.current().build();
    this.celCompiler = CelCompilerFactory
      .standardCelCompilerBuilder()
      .setOptions(options)
      .build();

    this.refreshMargin =
        builder.refreshMargin != null ? builder.refreshMargin : DEFAULT_REFRESH_MARGIN;
    this.minimumTokenLifetime =
        builder.minimumTokenLifetime != null
            ? builder.minimumTokenLifetime
            : DEFAULT_MINIMUM_TOKEN_LIFETIME;
    this.clock = builder.clock;
  }

  /**
   * Generates a Client-Side CAB token given the {@link CredentialAccessBoundary}.
   * 
   * @param accessBoundary
   * @return The Client-Side CAB token in an {@link AccessToken} object
   * @throws IOException If an I/O error occurs while refrehsing the source credentials
   * @throws CelValidationException If the availability condition is an invalid CEL expression
   * @throws GeneralSecurityException If an error occurs during encryption
   */
  public AccessToken generateToken(CredentialAccessBoundary accessBoundary)
      throws IOException, CelValidationException, GeneralSecurityException {
    this.refreshCredentialsIfRequired();

    String intermediateToken, sessionKey;
    Date intermediateTokenExpirationTime;

    synchronized (refreshLock) {
      intermediateToken =
          this.intermediateCredentials.intermediateAccessToken.getTokenValue();
      intermediateTokenExpirationTime =
          this.intermediateCredentials.intermediateAccessToken
              .getExpirationTime();
      sessionKey = this.intermediateCredentials.accessBoundarySessionKey;
    }

    byte[] rawRestrictions =
        this.serializeCredentialAccessBoundary(accessBoundary);

    byte[] encryptedRestrictions =
        this.encryptRestrictions(rawRestrictions, sessionKey);

    String tokenValue =
        intermediateToken + "." +
        Base64.getUrlEncoder().encodeToString(encryptedRestrictions);

    return new AccessToken(tokenValue, intermediateTokenExpirationTime);
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
  @VisibleForTesting
  void refreshCredentialsIfRequired() throws IOException {
    RefreshType refreshType = determineRefreshType();

    if (refreshType == RefreshType.NONE) {
      return; // No refresh needed, token is still valid.
    }

    // If a refresh is required, create or retrieve the refresh task.
    RefreshTask refreshTask = getOrCreateRefreshTask();

    // Handle the refresh based on the determined refresh type.
    switch (refreshType) {
      case BLOCKING:
        if (refreshTask.isNew) {
          // Start a new refresh task only if the task is new
          MoreExecutors.directExecutor().execute(refreshTask.task);
        }
        try {
          refreshTask.task.get(); // Wait for the refresh task to complete.
        } catch (InterruptedException e) {
          // Restore the interrupted status and throw an exception.
          Thread.currentThread().interrupt();
          throw new IOException(
              "Interrupted while asynchronously refreshing the intermediate credentials", e);
        } catch (ExecutionException e) {
          // Unwrap the underlying cause of the execution exception.
          Throwable cause = e.getCause();
          if (cause instanceof IOException) {
            throw (IOException) cause;
          } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
          } else {
            // Wrap other exceptions in an IOException.
            throw new IOException("Unexpected error refreshing intermediate credentials", cause);
          }
        }
        break;
      case ASYNC:
        if (refreshTask.isNew) {
          // Starts a new background thread for the refresh task if it's a new task.
          // We create a new thread because the Auth Library doesn't currently include a background
          // executor. Introducing an executor would add complexity in managing its lifecycle and
          // could potentially lead to memory leaks.
          // We limit the number of concurrent refresh threads to 1, so the overhead of creating new
          // threads for asynchronous calls should be acceptable.
          new Thread(refreshTask.task).start();
        } // (No else needed - if not new, another thread is handling the refresh)
        break;
    }
  }

  private RefreshType determineRefreshType() {
    if (intermediateCredentials == null
        || intermediateCredentials.intermediateAccessToken == null) {
      // A blocking refresh is needed if the intermediate access token doesn't exist.
      return RefreshType.BLOCKING;
    }

    AccessToken intermediateAccessToken = intermediateCredentials.intermediateAccessToken;
    Date expirationTime = intermediateAccessToken.getExpirationTime();
    if (expirationTime == null) {
      return RefreshType.NONE; // Token does not expire, no refresh needed.
    }

    Duration remaining = Duration.ofMillis(expirationTime.getTime() - clock.currentTimeMillis());

    if (remaining.compareTo(minimumTokenLifetime) <= 0) {
      // Intermediate token has expired or remaining lifetime is less than the minimum required
      // for CAB token generation. A blocking refresh is necessary.
      return RefreshType.BLOCKING;
    } else if (remaining.compareTo(refreshMargin) <= 0) {
      // The token is nearing expiration, an async refresh is needed.
      return RefreshType.ASYNC;
    }
    // Token is still fresh, no refresh needed.
    return RefreshType.NONE;
  }

  /**
   * Atomically creates a single flight refresh task.
   *
   * <p>Only a single refresh task can be scheduled at a time. If there is an existing task, it will
   * be returned for subsequent invocations. However, if a new task is created, it is the
   * responsibility of the caller to execute it. The task will clear the single flight slot upon
   * completion.
   */
  private RefreshTask getOrCreateRefreshTask() {
    synchronized (refreshLock) {
      if (refreshTask != null) {
        // An existing refresh task is already in progress. Return a NEW RefreshTask instance with
        // the existing task, but set isNew to false. This indicates to the caller that a new
        // refresh task was NOT created.
        return new RefreshTask(refreshTask.task, false);
      }

      final ListenableFutureTask<IntermediateCredentials> task =
          ListenableFutureTask.create(this::fetchIntermediateCredentials);

      // Store the new refresh task in the refreshTask field before returning. This ensures that
      // subsequent calls to this method will return the existing task while it's still in progress.
      refreshTask = new RefreshTask(task, true);
      return refreshTask;
    }
  }

  /**
   * Fetches the credentials by refreshing the source credential and exchanging it for an
   * intermediate access token using the STS endpoint.
   *
   * <p>The source credential is refreshed, and a token exchange request is made to the STS endpoint
   * to obtain an intermediate access token and an associated access boundary session key. This
   * ensures the intermediate access token meets this factory's refresh margin and minimum lifetime
   * requirements.
   *
   * @return The fetched {@link IntermediateCredentials} containing the intermediate access token
   *     and access boundary session key.
   * @throws IOException If an error occurs during credential refresh or token exchange.
   */
  @VisibleForTesting
  IntermediateCredentials fetchIntermediateCredentials() throws IOException {
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
    return new IntermediateCredentials(
        getTokenFromResponse(response, sourceAccessToken), response.getAccessBoundarySessionKey());
  }

  /**
   * Extracts the access token from the STS exchange response and sets the appropriate expiration
   * time.
   *
   * @param response The STS token exchange response.
   * @param sourceAccessToken The original access token used for the exchange.
   * @return The intermediate access token.
   */
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

  /**
   * Completes the refresh task by storing the results and clearing the single flight slot.
   *
   * <p>This method is called when a refresh task finishes. It stores the refreshed credentials if
   * successful. The single-flight "slot" is cleared, allowing subsequent refresh attempts. Any
   * exceptions during the refresh are caught and suppressed to prevent indefinite blocking of
   * subsequent refresh attempts.
   */
  private void finishRefreshTask(ListenableFuture<IntermediateCredentials> finishedTask)
      throws ExecutionException {
    synchronized (refreshLock) {
      try {
        this.intermediateCredentials = Futures.getDone(finishedTask);
      } finally {
        if (this.refreshTask != null && this.refreshTask.task == finishedTask) {
          this.refreshTask = null;
        }
      }
    }
  }

  @VisibleForTesting
  String getAccessBoundarySessionKey() {
    return intermediateCredentials != null
        ? intermediateCredentials.accessBoundarySessionKey
        : null;
  }

  @VisibleForTesting
  AccessToken getIntermediateAccessToken() {
    return intermediateCredentials != null ? intermediateCredentials.intermediateAccessToken : null;
  }

  @VisibleForTesting
  String getTokenExchangeEndpoint() {
    return tokenExchangeEndpoint;
  }

  @VisibleForTesting
  HttpTransportFactory getTransportFactory() {
    return transportFactory;
  }

  /**
   * Holds intermediate credentials obtained from the STS token exchange endpoint.
   *
   * <p>These credentials include an intermediate access token and an access boundary session key.
   */
  @VisibleForTesting
  static class IntermediateCredentials {
    private final AccessToken intermediateAccessToken;
    private final String accessBoundarySessionKey;

    IntermediateCredentials(AccessToken accessToken, String accessBoundarySessionKey) {
      this.intermediateAccessToken = accessToken;
      this.accessBoundarySessionKey = accessBoundarySessionKey;
    }

    String getAccessBoundarySessionKey() {
      return accessBoundarySessionKey;
    }

    AccessToken getIntermediateAccessToken() {
      return intermediateAccessToken;
    }
  }

  /**
   * Represents a task for refreshing intermediate credentials, ensuring that only one refresh
   * operation is in progress at a time.
   *
   * <p>The {@code isNew} flag indicates whether this is a newly initiated refresh operation or an
   * existing one already in progress. This distinction is used to prevent redundant refreshes.
   */
  class RefreshTask extends AbstractFuture<IntermediateCredentials> implements Runnable {
    private final ListenableFutureTask<IntermediateCredentials> task;
    final boolean isNew;

    RefreshTask(ListenableFutureTask<IntermediateCredentials> task, boolean isNew) {
      this.task = task;
      this.isNew = isNew;

      // Add listener to update factory's credentials when the task completes.
      task.addListener(
          () -> {
            try {
              finishRefreshTask(task);
            } catch (ExecutionException e) {
              Throwable cause = e.getCause();
              RefreshTask.this.setException(cause);
            }
          },
          MoreExecutors.directExecutor());

      // Add callback to set the result or exception based on the outcome.
      Futures.addCallback(
          task,
          new FutureCallback<IntermediateCredentials>() {
            @Override
            public void onSuccess(IntermediateCredentials result) {
              RefreshTask.this.set(result);
            }

            @Override
            public void onFailure(@Nullable Throwable t) {
              RefreshTask.this.setException(
                  t != null ? t : new IOException("Refresh failed with null Throwable."));
            }
          },
          MoreExecutors.directExecutor());
    }

    @Override
    public void run() {
      task.run();
    }
  }

  /**
   * Serializes a {@link CredentialAccessBoundary} object into Protobuf wire format.
   */
  private byte[] serializeCredentialAccessBoundary(
      CredentialAccessBoundary credentialAccessBoundary)
      throws CelValidationException {
    List<AccessBoundaryRule> rules =
        credentialAccessBoundary.getAccessBoundaryRules();
    ClientSideAccessBoundary.Builder accessBoundaryBuilder =
        ClientSideAccessBoundary.newBuilder();

    for (AccessBoundaryRule rule : rules) {
      ClientSideAccessBoundaryRule.Builder ruleBuilder =
          accessBoundaryBuilder.addAccessBoundaryRulesBuilder()
              .addAllAvailablePermissions(rule.getAvailablePermissions())
              .setAvailableResource(rule.getAvailableResource());

      // Availability condition is an optional field from the CredentialAccessBoundary
      // CEL compliation is only performed if there is a non-empty availablity condition.
      if (rule.getAvailabilityCondition() != null) {
        String availabilityCondition =
            rule.getAvailabilityCondition().getExpression();

        Expr availabilityConditionExpr = this.compileCel(availabilityCondition);
        ruleBuilder.setCompiledAvailabilityCondition(availabilityConditionExpr);
      }
    }

    return accessBoundaryBuilder.build().toByteArray();
  }

  /**
   * Compiles CEL expression from String to an {@link Expr} proto object. 
   */
  private Expr compileCel(String expr) throws CelValidationException {
    CelAbstractSyntaxTree ast = celCompiler.parse(expr).getAst();

    CelProtoAbstractSyntaxTree astProto =
        CelProtoAbstractSyntaxTree.fromCelAst(ast);

    return astProto.getExpr();
  }

  /**
   * Encrypts the given bytes using a sessionKey using Tink Aead.
   */
  private byte[] encryptRestrictions(byte[] restriction, String sessionKey) throws GeneralSecurityException {
    byte[] rawKey = Base64.getDecoder().decode(sessionKey);

    KeysetHandle keysetHandle = TinkProtoKeysetFormat.parseKeyset(
        rawKey, InsecureSecretKeyAccess.get());

    Aead aead =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // For Client-Side CAB token encryption, empty associated data is expected.
    // Tink requires a byte[0] to be passed for this case.
    return aead.encrypt(restriction, /*associatedData=*/new byte[0]);
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
    private Clock clock = Clock.SYSTEM; // Default to system clock;

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
     *     be greater than zero.
     * @return This {@code Builder} object.
     * @throws IllegalArgumentException if minimumTokenLifetime is negative or zero.
     */
    @CanIgnoreReturnValue
    public Builder setMinimumTokenLifetime(Duration minimumTokenLifetime) {
      checkNotNull(minimumTokenLifetime, "Minimum token lifetime must not be null.");
      if (minimumTokenLifetime.isNegative() || minimumTokenLifetime.isZero()) {
        throw new IllegalArgumentException("Minimum token lifetime must be greater than zero.");
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
     * @param refreshMargin The refresh margin. Must be greater than zero.
     * @return This {@code Builder} object.
     * @throws IllegalArgumentException if refreshMargin is negative or zero.
     */
    @CanIgnoreReturnValue
    public Builder setRefreshMargin(Duration refreshMargin) {
      checkNotNull(refreshMargin, "Refresh margin must not be null.");
      if (refreshMargin.isNegative() || refreshMargin.isZero()) {
        throw new IllegalArgumentException("Refresh margin must be greater than zero.");
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

    /**
     * Set the clock for checking token expiry. Used for testing.
     *
     * @param clock the clock to use. Defaults to the system clock
     * @return the builder
     */
    public Builder setClock(Clock clock) {
      this.clock = clock;
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
