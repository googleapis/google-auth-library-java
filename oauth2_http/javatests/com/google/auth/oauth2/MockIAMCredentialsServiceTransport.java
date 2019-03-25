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

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;

/**
 * Transport that simulates the IAMCredentials server for access tokens.
 */
public class MockIAMCredentialsServiceTransport extends MockHttpTransport {

  private static final String IAM_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken";

  private Integer tokenResponseErrorCode;
  private String tokenResponseErrorContent;
  private String targetPrincipal;

  private String accessToken;
  private String expireTime;

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

  public void setexpireTime(String expireTime) {
    this.expireTime = expireTime;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {

    String formattedUrl = String.format(IAM_ENDPOINT, this.targetPrincipal);
    if (url.equals(formattedUrl)) {
      return new MockLowLevelHttpRequest(url) {
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
    }
    return super.buildRequest(method, url);
  }

}
