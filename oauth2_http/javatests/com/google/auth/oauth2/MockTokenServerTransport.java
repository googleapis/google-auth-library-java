package com.google.auth.oauth2;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.Json;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.TestUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Mock transport to simulate providing Google OAuth2 access tokens
 */
public class MockTokenServerTransport extends MockHttpTransport {

  static final String EXPECTED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  static final JsonFactory JSON_FACTORY = new JacksonFactory();
  int buildRequestCount;
  final Map<String, String> clients = new HashMap<String, String>();
  final Map<String, String> refreshTokens = new HashMap<String, String>();
  final Map<String, String> serviceAccounts = new HashMap<String, String>();
  final Map<String, String> codes = new HashMap<String, String>();
  URI tokenServerUri = OAuth2Utils.TOKEN_SERVER_URI;
  private IOException error;

  public MockTokenServerTransport()  {
  }

  public URI getTokenServerUri() {
    return tokenServerUri;
  }

  public void setTokenServerUri(URI tokenServerUri) {
    this.tokenServerUri = tokenServerUri;
  }

  public void addAuthorizationCode(String code, String refreshToken, String accessToken) {
    codes.put(code, refreshToken);
    refreshTokens.put(refreshToken, accessToken);
  }

  public void addClient(String clientId, String clientSecret) {
    clients.put(clientId, clientSecret);
  }

  public void addRefreshToken(String refreshToken, String accessTokenToReturn) {
    refreshTokens.put(refreshToken, accessTokenToReturn);
  }

  public void addServiceAccount(String email, String accessToken) {
    serviceAccounts.put(email, accessToken);
  }

  public String getAccessToken(String refreshToken) {
    return refreshTokens.get(refreshToken);
  }

  public void setError(IOException error) {
    this.error = error;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
    buildRequestCount++;
    if (error != null) {
      throw error;
    }
    int questionMarkPos = url.indexOf('?');
    final String urlWithoutQUery = (questionMarkPos > 0) ? url.substring(0, questionMarkPos) : url;
    final String query = (questionMarkPos > 0) ? url.substring(questionMarkPos + 1) : "";
    if (urlWithoutQUery.equals(tokenServerUri.toString())) {
      MockLowLevelHttpRequest request = new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          String content = this.getContentAsString();
          Map<String, String> query = TestUtils.parseQuery(content);
          String accessToken = null;
          String refreshToken = null;

          String foundId = query.get("client_id");
          if (foundId != null) {
            if (!clients.containsKey(foundId)) {
              throw new IOException("Client ID not found.");
            }
            String foundSecret = query.get("client_secret");
            String expectedSecret = clients.get(foundId);
            if (foundSecret == null || !foundSecret.equals(expectedSecret)) {
              throw new IOException("Client secret not found.");
            }
            String grantType = query.get("grant_type");
            if (grantType != null && grantType.equals("authorization_code")) {
              String foundCode = query.get("code");
              if (!codes.containsKey(foundCode)) {
                throw new IOException("Authorization code not found");
              }
              refreshToken = codes.get(foundCode);
            } else {
              refreshToken = query.get("refresh_token");
            }
            if (!refreshTokens.containsKey(refreshToken)) {
              throw new IOException("Refresh Token not found.");
            }
            accessToken = refreshTokens.get(refreshToken);
          } else if (query.containsKey("grant_type")) {
            String grantType = query.get("grant_type");
            if (!EXPECTED_GRANT_TYPE.equals(grantType)) {
              throw new IOException("Unexpected Grant Type.");
            }
            String assertion = query.get("assertion");
            JsonWebSignature signature = JsonWebSignature.parse(JSON_FACTORY, assertion);
            String foundEmail = signature.getPayload().getIssuer();
            if (!serviceAccounts.containsKey(foundEmail)) {
              throw new IOException("Service Account Email not found as issuer.");
            }
            accessToken = serviceAccounts.get(foundEmail);
            String foundScopes = (String) signature.getPayload().get("scope");
            if (foundScopes == null || foundScopes.length() == 0) {
              throw new IOException("Scopes not found.");
            }
          } else {
            throw new IOException("Unknown token type.");
          }

          // Create the JSON response
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(JSON_FACTORY);
          refreshContents.put("access_token", accessToken);
          refreshContents.put("expires_in", 3600);
          refreshContents.put("token_type", "Bearer");
          if (refreshToken != null) {
            refreshContents.put("refresh_token", refreshToken);
          }
          String refreshText  = refreshContents.toPrettyString();

          MockLowLevelHttpResponse response = new MockLowLevelHttpResponse()
            .setContentType(Json.MEDIA_TYPE)
            .setContent(refreshText);
          return response;
        }
      };
      return request;
    } else if (urlWithoutQUery.equals(OAuth2Utils.TOKEN_REVOKE_URI.toString())) {
      MockLowLevelHttpRequest request = new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          Map<String, String> parameters = TestUtils.parseQuery(query);
          String token = parameters.get("token");
          if (token == null) {
            throw new IOException("Token to revoke not found.");
          }
          // Token could be access token or refresh token so remove keys and values
          refreshTokens.values().removeAll(Collections.singleton(token));
          refreshTokens.remove(token);
          MockLowLevelHttpResponse response = new MockLowLevelHttpResponse()
          .setContentType(Json.MEDIA_TYPE);
        return response;
        }
      };
      return request;
    }
    return super.buildRequest(method, url);
  }
}
