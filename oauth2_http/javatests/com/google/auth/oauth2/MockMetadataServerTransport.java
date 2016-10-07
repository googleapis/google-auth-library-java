package com.google.auth.oauth2;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;

import java.io.IOException;

/**
 * Transport that simulates the GCE metadata server for access tokens.
 */
public class MockMetadataServerTransport extends MockHttpTransport {

  private String accessToken;

  private Integer tokenRequestStatusCode;

  public MockMetadataServerTransport() {
  }

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  public void setTokenRequestStatusCode(Integer tokenRequestStatusCode) {
    this.tokenRequestStatusCode = tokenRequestStatusCode;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
    if (url.equals(ComputeEngineCredentials.TOKEN_SERVER_ENCODED_URL)) {

      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {

          if (tokenRequestStatusCode != null) {
            return new MockLowLevelHttpResponse()
              .setStatusCode(tokenRequestStatusCode)
              .setContent("Token Fetch Error");
          }

          String metadataRequestHeader = getFirstHeaderValue("Metadata-Flavor");
          if (!"Google".equals(metadataRequestHeader)) {
            throw new IOException("Metadata request header not found.");
          }

          // Create the JSON response
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(OAuth2Utils.JSON_FACTORY);
          refreshContents.put("access_token", accessToken);
          refreshContents.put("expires_in", 3600000);
          refreshContents.put("token_type", "Bearer");
          String refreshText = refreshContents.toPrettyString();

          return new MockLowLevelHttpResponse()
            .setContentType(Json.MEDIA_TYPE)
            .setContent(refreshText);
        }
      };
    } else if (url.equals(ComputeEngineCredentials.METADATA_SERVER_URL)) {
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() {
          MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
          response.addHeader("Metadata-Flavor", "Google");
          return response;
        }
      };
    }
    return super.buildRequest(method, url);
  }
}
