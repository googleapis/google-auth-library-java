/*
 * Copyright 2015, Google Inc. All rights reserved.
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

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.TestUtils;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;

/** Mock transport to simulate providing Google OAuth2 access tokens */
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
  private Queue<IOException> responseErrorSequence = new ArrayDeque<IOException>();
  private Queue<LowLevelHttpResponse> responseSequence = new ArrayDeque<LowLevelHttpResponse>();
  private int expiresInSeconds = 3600;

  public MockTokenServerTransport() {}

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

  public void addResponseErrorSequence(IOException... errors) {
    for (IOException error : errors) {
      responseErrorSequence.add(error);
    }
  }

  public void addResponseSequence(LowLevelHttpResponse... responses) {
    for (LowLevelHttpResponse response : responses) {
      responseSequence.add(response);
    }
  }

  public void setExpiresInSeconds(int expiresInSeconds) {
    this.expiresInSeconds = expiresInSeconds;
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
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          IOException responseError = responseErrorSequence.poll();
          if (responseError != null) {
            throw responseError;
          }
          LowLevelHttpResponse response = responseSequence.poll();
          if (response != null) {
            return response;
          }
          String content = this.getContentAsString();
          Map<String, String> query = TestUtils.parseQuery(content);
          String accessToken;
          String refreshToken = null;
          boolean generateAccessToken = true;

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
            String foundTargetAudience = (String) signature.getPayload().get("target_audience");
            String foundScopes = (String) signature.getPayload().get("scope");
            if ((foundScopes == null || foundScopes.length() == 0)
                && (foundTargetAudience == null || foundTargetAudience.length() == 0)) {
              throw new IOException("Either target_audience or scopes must be specified.");
            }

            if (foundScopes != null && foundTargetAudience != null) {
              throw new IOException("Only one of target_audience or scopes must be specified.");
            }
            if (foundTargetAudience != null) {
              generateAccessToken = false;
            }
          } else {
            throw new IOException("Unknown token type.");
          }

          // Create the JSON response
          // https://developers.google.com/identity/protocols/OpenIDConnect#server-flow
          GenericJson responseContents = new GenericJson();
          responseContents.setFactory(JSON_FACTORY);
          responseContents.put("token_type", "Bearer");
          responseContents.put("expires_in", expiresInSeconds);
          if (generateAccessToken) {
            responseContents.put("access_token", accessToken);
            if (refreshToken != null) {
              responseContents.put("refresh_token", refreshToken);
            }
          } else {
            responseContents.put("id_token", ServiceAccountCredentialsTest.DEFAULT_ID_TOKEN);
          }
          String refreshText = responseContents.toPrettyString();

          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(refreshText);
        }
      };
    } else if (urlWithoutQUery.equals(OAuth2Utils.TOKEN_REVOKE_URI.toString())) {
      return new MockLowLevelHttpRequest(url) {
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
          return new MockLowLevelHttpResponse().setContentType(Json.MEDIA_TYPE);
        }
      };
    }
    return super.buildRequest(method, url);
  }
}
