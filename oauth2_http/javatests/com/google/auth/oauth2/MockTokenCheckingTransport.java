package com.google.auth.oauth2;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.http.AuthHttpConstants;

import java.io.IOException;

/**
 * Mock transport to simulate an http server that checks tokens
 */
public class MockTokenCheckingTransport extends HttpTransport {

  public static final String SUCCESS_CONTENT = "{\"key\":\"value\"}";

  private MockTokenServerTransport tokenServer;
  private String refreshToken;

  public MockTokenCheckingTransport(MockTokenServerTransport tokenServer,
                                    String refreshToken) {
    this.tokenServer = tokenServer;
    this.refreshToken = refreshToken;
  }

  @Override
  public MockLowLevelHttpRequest buildRequest(String method, String url) throws IOException {
    return new MockLowLevelHttpRequest() {
      @Override
      public MockLowLevelHttpResponse execute() throws IOException {
        String credentialValue = getFirstHeaderValue(AuthHttpConstants.AUTHORIZATION);
        String correctAccessToken = tokenServer.getAccessToken(refreshToken);
        if (credentialValue == null) {
          return makeErrorResponse();
        }
        if (!credentialValue.startsWith(OAuth2Utils.BEARER_PREFIX)) {
          return makeErrorResponse();
        }
        String actualAccessToken = credentialValue.substring(OAuth2Utils.BEARER_PREFIX.length());
        if (!correctAccessToken.equals(actualAccessToken)) {
          return makeErrorResponse();
        } else {
          return makeSuccessResponse();
        }
      }
    };
  }

  private MockLowLevelHttpResponse makeErrorResponse() {
    MockLowLevelHttpResponse errorResponse = new MockLowLevelHttpResponse();
    errorResponse.addHeader("custom_header", "value");
    errorResponse.setStatusCode(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
    errorResponse.setContentType(Json.MEDIA_TYPE);
    errorResponse.setContent("{\"error\":\"invalid credentials\"}");
    return errorResponse;
  }

  private MockLowLevelHttpResponse makeSuccessResponse() {
    MockLowLevelHttpResponse successResponse = new MockLowLevelHttpResponse();
    successResponse.addHeader("custom_header", "value");
    successResponse.setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
    successResponse.setContentType(Json.MEDIA_TYPE);
    successResponse.setContent(SUCCESS_CONTENT);
    return successResponse;
  }

}
