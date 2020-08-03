/*
 * Copyright 2020, Google Inc. All rights reserved.
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

import static com.google.common.truth.Truth.assertThat;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.TestUtils;
import java.io.IOException;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Queue;

/**
 * Mock transport that simulates STS.
 */
public class MockStsServiceTransport extends MockHttpTransport {
  private static final String EXPECTED_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
  private static final String TOKEN_TYPE = "Bearer";
  private static final String ACCESS_TOKEN = "accessToken";
  private static final int EXPIRES_IN = 3600;

  private static final JsonFactory JSON_FACTORY = new JacksonFactory();

  private Queue<IOException> responseErrorSequence = new ArrayDeque<>();
  private Queue<String> refreshTokenSequence = new ArrayDeque<>();
  private Queue<List<String>> scopeSequence = new ArrayDeque<>();
  private MockLowLevelHttpRequest request;

  public void addResponseErrorSequence(IOException... errors) {
    Collections.addAll(responseErrorSequence, errors);
  }

  public void addRefreshTokenSequence(String... refreshTokens) {
    Collections.addAll(refreshTokenSequence, refreshTokens);
  }

  public void addScopeSequence(List<String>... scopes) {
    Collections.addAll(scopeSequence, scopes);
  }

  public MockLowLevelHttpRequest getRequest() {
    return request;
  }

  public String getTokenType() {
    return TOKEN_TYPE;
  }

  public String getAccessToken() {
    return ACCESS_TOKEN;
  }

  public String getIssuedTokenType() {
    return ISSUED_TOKEN_TYPE;
  }

  public int getExpiresIn() {
    return EXPIRES_IN;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) {
    this.request = new MockLowLevelHttpRequest(url) {
      @Override
      public LowLevelHttpResponse execute() throws IOException {
        if (!responseErrorSequence.isEmpty()) {
          throw responseErrorSequence.poll();
        }
        Map<String, String> query = TestUtils.parseQuery(getContentAsString());
        assertThat(query.get("grant_type")).isEqualTo(EXPECTED_GRANT_TYPE);
        assertThat(query.get("subject_token_type")).isNotEmpty();
        assertThat(query.get("subject_token")).isNotEmpty();

        GenericJson response = new GenericJson();
        response.setFactory(JSON_FACTORY);
        response.put("token_type", TOKEN_TYPE);
        response.put("expires_in", EXPIRES_IN);
        response.put("access_token", ACCESS_TOKEN);
        response.put("issued_token_type", ISSUED_TOKEN_TYPE);

        if (!refreshTokenSequence.isEmpty()) {
          response.put("refresh_token", refreshTokenSequence.poll());
        }
        if (!scopeSequence.isEmpty()) {
          response.put("scope", String.join(" ", scopeSequence.poll()));
        }

        return new MockLowLevelHttpResponse()
            .setContentType(Json.MEDIA_TYPE)
            .setContent(response.toPrettyString());
      }
    };
    return this.request;
  }
}
