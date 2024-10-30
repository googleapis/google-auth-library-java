package com.google.auth.credentialaccessboundary;

import static com.google.auth.oauth2.OAuth2Credentials.getFromServiceLoader;
import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auth.Credentials;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.StsRequestHandler;
import com.google.auth.oauth2.StsTokenExchangeRequest;
import com.google.auth.oauth2.StsTokenExchangeResponse;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;

public final class ClientSideCredentialAccessBoundaryFactory {
  private final GoogleCredentials sourceCredential;
  private final transient HttpTransportFactory transportFactory;
  private final String tokenExchangeEndpoint;
  private String acceessBoundarySessionKey;
  private AccessToken intermediaryAccessToken;

  private ClientSideCredentialAccessBoundaryFactory(Builder builder) {
    this.transportFactory =
        firstNonNull(
            builder.transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.sourceCredential = checkNotNull(builder.sourceCredential);

    // Default to GDU when not supplied.
    String universeDomain;
    if (builder.universeDomain == null || builder.universeDomain.trim().isEmpty()) {
      universeDomain = Credentials.GOOGLE_DEFAULT_UNIVERSE;
    } else {
      universeDomain = builder.universeDomain;
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
    String TOKEN_EXCHANGE_URL_FORMAT = "https://sts.{universe_domain}/v1/token";
    this.tokenExchangeEndpoint =
        TOKEN_EXCHANGE_URL_FORMAT.replace("{universe_domain}", universeDomain);
  }

  public void fetchCredentials() throws IOException {
    try {
      this.sourceCredential.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException("Unable to refresh the provided source credential.", e);
    }

    AccessToken sourceAccessToken = sourceCredential.getAccessToken();
    if (sourceAccessToken == null || sourceAccessToken.getTokenValue() == null) {
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
      return new ClientSideCredentialAccessBoundaryFactory(this);
    }
  }
}
