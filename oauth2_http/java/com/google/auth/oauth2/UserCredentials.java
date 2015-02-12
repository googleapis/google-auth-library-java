package com.google.auth.oauth2;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Preconditions;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

/**
 * OAuth2 Credentials representing a user's identity and consent.
 */
public class UserCredentials extends GoogleCredentials {

  private static final String GRANT_TYPE = "refresh_token";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";

  private final String clientId;
  private final String clientSecret;
  private final String refreshToken;
  private final HttpTransport transport;
  private final GenericUrl tokenServerUrl;

  /**
   * Constructor with minimum information and default behavior.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   */
  public UserCredentials(String clientId, String clientSecret, String refreshToken) {
    this(clientId, clientSecret, refreshToken, null, null);
  }

  /**
   * Constructor allow override of transport for getting access tokens.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   * @param transport HTTP object used to get acces tokens.
   */
  public UserCredentials(
      String clientId, String clientSecret, String refreshToken, HttpTransport transport) {
    this(clientId, clientSecret, refreshToken, transport, null);
  }

  /**
   * Constructor allowing override of transport and URL for getting access tokens.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   * @param transport HTTP object used to get acces tokens.
   * @param tokenServerUrl URL of the endpoint that provides tokens.
   */
  public UserCredentials(String clientId, String clientSecret, String refreshToken,
      HttpTransport transport, GenericUrl tokenServerUrl) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.clientSecret = Preconditions.checkNotNull(clientSecret);
    this.refreshToken = Preconditions.checkNotNull(refreshToken);
    this.transport = (transport == null) ? OAuth2Utils.HTTP_TRANSPORT : transport;
    this.tokenServerUrl = (tokenServerUrl == null)
        ? new GenericUrl(OAuth2Utils.TOKEN_SERVER_URL) : tokenServerUrl;
  }

  /**
   * Returns user crentials defined by JSON contents using the format supported by the Cloud SDK.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transport the transport for Http calls.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   **/
  static UserCredentials fromJson(Map<String, Object> json, HttpTransport transport)
      throws IOException {
    String clientId = (String) json.get("client_id");
    String clientSecret = (String) json.get("client_secret");
    String refreshToken = (String) json.get("refresh_token");
    if (clientId == null || clientSecret == null || refreshToken == null) {
      throw new IOException("Error reading user credential from JSON, "
          + " expecting 'client_id', 'client_secret' and 'refresh_token'.");
    }
    UserCredentials credentials =
        new UserCredentials(clientId, clientSecret, refreshToken, transport);
    return credentials;
  }

  /**
   * Refreshes the OAuth2 acces token by getting a new access token from the refresh token
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    GenericData tokenRequest = new GenericData();
    tokenRequest.set("client_id", clientId);
    tokenRequest.set("client_secret", clientSecret);
    tokenRequest.set("refresh_token", refreshToken);
    tokenRequest.set("grant_type", GRANT_TYPE);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transport.createRequestFactory();
    HttpRequest request =
        requestFactory.buildPostRequest(tokenServerUrl, content);
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));
    HttpResponse response = request.execute();
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
        OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
        OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    AccessToken access = new AccessToken(accessToken, new Date(expiresAtMilliseconds));
    return access;
  }
}
