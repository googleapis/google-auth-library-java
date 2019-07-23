/*
 * Copyright 2018, Google Inc. All rights reserved.
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

import java.io.IOException;
import java.util.List;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.common.io.BaseEncoding;

import com.google.auth.TestUtils;
/**
 * Transport that simulates the IAMCredentials server for access tokens.
 */
public class MockIAMCredentialsServiceTransport extends MockHttpTransport {

  private static final String IAM_ACCESS_TOKEN_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken";
  private static final String IAM_ID_TOKEN_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken";
  private static final String IAM_SIGN_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signBlob";
  private Integer tokenResponseErrorCode;
  private String tokenResponseErrorContent;
  private String targetPrincipal;
  private byte[] signedBlob;
  private int responseCode = HttpStatusCodes.STATUS_CODE_OK;
  private String errorMessage;

  private String accessToken;
  private String expireTime;

  private MockLowLevelHttpRequest request;

  public MockIAMCredentialsServiceTransport() {
  }

  public void setTokenResponseErrorCode(Integer tokenResponseErrorCode) {
    this.tokenResponseErrorCode = tokenResponseErrorCode;
  }

  public void setTokenResponseErrorContent(String tokenResponseErrorContent) {
    this.tokenResponseErrorContent = tokenResponseErrorContent;
  }

  public void setTargetPrincipal(String targetPrincipal) {
    this.targetPrincipal = targetPrincipal;
  }

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  public void setExpireTime(String expireTime) {
    this.expireTime = expireTime;
  }

  public void setSignedBlob(byte[] signedBlob) {
    this.signedBlob = signedBlob;
  }

  public void setSigningErrorResponseCodeAndMessage(int responseCode, String errorMessage) {
    this.responseCode = responseCode;
    this.errorMessage = errorMessage;
  }

  public MockLowLevelHttpRequest getRequest() {
    return request;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {

    String iamAccesssTokenformattedUrl = String.format(IAM_ACCESS_TOKEN_ENDPOINT, this.targetPrincipal);
    String iamSignBlobformattedUrl = String.format(IAM_SIGN_ENDPOINT, this.targetPrincipal);
    if (url.equals(iamAccesssTokenformattedUrl)) {
      this.request = new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {

          if (tokenResponseErrorCode != null) {
            return new MockLowLevelHttpResponse()
                .setStatusCode(tokenResponseErrorCode)
                .setContentType(Json.MEDIA_TYPE)
                .setContent(tokenResponseErrorContent);
          }

          // Create the JSON response
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(OAuth2Utils.JSON_FACTORY);
          refreshContents.put("accessToken", accessToken);
          refreshContents.put("expireTime", expireTime);
          String refreshText = refreshContents.toPrettyString();
          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(refreshText);
        }
      };
    } else if (url.equals(iamSignBlobformattedUrl) && responseCode != HttpStatusCodes.STATUS_CODE_OK) {
      this.request =  new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {

          if (tokenResponseErrorCode != null) {
            return new MockLowLevelHttpResponse()
                .setStatusCode(tokenResponseErrorCode)
                .setContentType(Json.MEDIA_TYPE)
                .setContent(tokenResponseErrorContent);
          }

          BaseEncoding base64 = BaseEncoding.base64();
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(OAuth2Utils.JSON_FACTORY);
          refreshContents.put("signedBlob", base64.encode(signedBlob));
          String refreshText = refreshContents.toPrettyString();
          return new MockLowLevelHttpResponse()
          .setStatusCode(responseCode)
          .setContent(TestUtils.errorJson(errorMessage));
        }
      };
    } else if (url.equals(iamSignBlobformattedUrl)) {
      this.request = new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {

          if (tokenResponseErrorCode != null) {
            return new MockLowLevelHttpResponse()
                .setStatusCode(tokenResponseErrorCode)
                .setContentType(Json.MEDIA_TYPE)
                .setContent(tokenResponseErrorContent);
          }

          BaseEncoding base64 = BaseEncoding.base64();
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(OAuth2Utils.JSON_FACTORY);
          refreshContents.put("signedBlob", base64.encode(signedBlob));
          String refreshText = refreshContents.toPrettyString();
          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(refreshText);
        }
      };
    } else {
      return super.buildRequest(method, url);
    }

    return this.request;
  }

}
