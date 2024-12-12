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
import com.google.common.base.Strings;
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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.security.GeneralSecurityException;

public final class ClientSideCredentialAccessBoundaryFactory {
  private final GoogleCredentials sourceCredential;
  private final transient HttpTransportFactory transportFactory;
  private final String tokenExchangeEndpoint;
  private String accessBoundarySessionKey;
  private AccessToken intermediateAccessToken;
  private CelCompiler celCompiler;

  private ClientSideCredentialAccessBoundaryFactory(Builder builder) {
    this.transportFactory = builder.transportFactory;
    this.sourceCredential = builder.sourceCredential;
    this.tokenExchangeEndpoint = builder.tokenExchangeEndpoint;

    try {
      AeadConfig.register();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Error occurred when registering Tink");
    }

    CelOptions options = CelOptions.current().build();
    this.celCompiler = CelCompilerFactory
      .standardCelCompilerBuilder()
      .setOptions(options)
      .build();
  }

  /**
   * Refreshes the source credential and exchanges it for an intermediary access token using the STS
   * endpoint.
   *
   * <p>If the source credential is expired, it will be refreshed. A token exchange request is then
   * made to the STS endpoint. The resulting intermediary access token and access boundary session
   * key are stored. The intermediary access token's expiration time is determined as follows:
   *
   * <ol>
   *   <li>If the STS response includes `expires_in`, that value is used.
   *   <li>Otherwise, if the source credential has an expiration time, that value is used.
   *   <li>Otherwise, the intermediary token will have no expiration time.
   * </ol>
   *
   * @throws IOException If an error occurs during credential refresh or token exchange.
   */
  private void refreshCredentials() throws IOException {
    try {
      this.sourceCredential.refreshIfExpired();
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
    this.accessBoundarySessionKey = response.getAccessBoundarySessionKey();
    this.intermediateAccessToken = response.getAccessToken();

    // The STS endpoint will only return the expiration time for the intermediary token
    // if the original access token represents a service account.
    // The intermediary token's expiration time will always match the source credential expiration.
    // When no expires_in is returned, we can copy the source credential's expiration time.
    if (response.getAccessToken().getExpirationTime() == null) {
      if (sourceAccessToken.getExpirationTime() != null) {
        this.intermediateAccessToken =
            new AccessToken(
                response.getAccessToken().getTokenValue(), sourceAccessToken.getExpirationTime());
      }
    }
  }

  private void refreshCredentialsIfRequired() throws IOException {
    // TODO(negarb): Implement refreshCredentialsIfRequired
    refreshCredentials();
  }

  public AccessToken generateToken(CredentialAccessBoundary accessBoundary) throws IOException {
    this.refreshCredentialsIfRequired();

    String intermediaryToken, sessionKey;
    Date intermediaryTokenExpirationTime;

    synchronized (this) {
      intermediaryToken = this.intermediateAccessToken.getTokenValue();
      intermediaryTokenExpirationTime =
          this.intermediateAccessToken.getExpirationTime();
      sessionKey = this.accessBoundarySessionKey;
    }

    byte[] rawRestrictions =
        this.serializeCredentialAccessBoundary(accessBoundary);

    byte[] encryptedRestrictions =
        this.encryptRestrictions(rawRestrictions, sessionKey);

    String tokenValue =
        intermediaryToken + "." +
        Base64.getUrlEncoder().encodeToString(encryptedRestrictions);

    return new AccessToken(tokenValue, intermediaryTokenExpirationTime);
  }

  private byte[] serializeCredentialAccessBoundary(
      CredentialAccessBoundary credentialAccessBoundary) throws IOException {
    List<AccessBoundaryRule> rules =
        credentialAccessBoundary.getAccessBoundaryRules();
    ClientSideAccessBoundary.Builder accessBoundaryBuilder =
        ClientSideAccessBoundary.newBuilder();

    for (AccessBoundaryRule rule : rules) {
      ClientSideAccessBoundaryRule.Builder ruleBuilder =
          accessBoundaryBuilder.addAccessBoundaryRulesBuilder()
              .addAllAvailablePermissions(rule.getAvailablePermissions())
              .setAvailableResource(rule.getAvailableResource());

      if (rule.getAvailabilityCondition() != null) {
        String availabilityCondition =
            rule.getAvailabilityCondition().getExpression();

        Expr availabilityConditionExpr = this.compileCel(availabilityCondition);
        ruleBuilder.setCompiledAvailabilityCondition(availabilityConditionExpr);
      }
    }

    return accessBoundaryBuilder.build().toByteArray();
  }

  private Expr compileCel(String expr) throws IOException {
    try {
      CelAbstractSyntaxTree ast = celCompiler.parse(expr).getAst();

      CelProtoAbstractSyntaxTree astProto =
          CelProtoAbstractSyntaxTree.fromCelAst(ast);

      return astProto.getExpr();

    } catch (CelValidationException exception) {
      throw new IOException("Failed to parse CEL expression: " +
                            exception.getMessage());
    }
  }

  private byte[] encryptRestrictions(byte[] restriction, String sessionKey) throws InternalError {
    try {
      byte[] rawKey = Base64.getDecoder().decode(sessionKey);

      KeysetHandle keysetHandle = TinkProtoKeysetFormat.parseKeyset(
          rawKey, InsecureSecretKeyAccess.get());

      Aead aead =
          keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

      return aead.encrypt(restriction, /*associatedData=*/new byte[0]);
    } catch (GeneralSecurityException exception) {
      throw new InternalError("Failed to parse keyset: " + exception.getMessage());
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
