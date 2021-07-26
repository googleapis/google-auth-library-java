/*
 * Copyright 2021 Google LLC
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

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.TestUtils;
import java.io.IOException;
import java.util.Map;

/** Transport that mocks a basic STS endpoint. */
public class MockStsTransport extends MockHttpTransport {

  private static final String EXPECTED_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
  private static final String STS_URL = "https://sts.googleapis.com/v1/token";
  private static final String ACCESS_TOKEN = "accessToken";
  private static final Long EXPIRES_IN = 3600L;

  private MockLowLevelHttpRequest request;

  @Override
  public LowLevelHttpRequest buildRequest(final String method, final String url) {
    this.request =
        new MockLowLevelHttpRequest(url) {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            if (!STS_URL.equals(url)) {
              return makeErrorResponse();
            }

            Map<String, String> query = TestUtils.parseQuery(getContentAsString());
            assertEquals(EXPECTED_GRANT_TYPE, query.get("grant_type"));
            assertNotNull(query.get("subject_token_type"));
            assertNotNull(query.get("subject_token"));

            GenericJson response = new GenericJson();
            response.setFactory(new GsonFactory());
            response.put("token_type", "Bearer");
            response.put("expires_in", EXPIRES_IN);
            response.put("access_token", ACCESS_TOKEN);
            response.put("issued_token_type", ISSUED_TOKEN_TYPE);

            return new MockLowLevelHttpResponse()
                .setContentType(Json.MEDIA_TYPE)
                .setContent(response.toPrettyString());
          }
        };
    return this.request;
  }

  private MockLowLevelHttpResponse makeErrorResponse() {
    MockLowLevelHttpResponse errorResponse = new MockLowLevelHttpResponse();
    errorResponse.setStatusCode(HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
    errorResponse.setContentType(Json.MEDIA_TYPE);
    errorResponse.setContent("{\"error\":\"error\"}");
    return errorResponse;
  }

  public MockLowLevelHttpRequest getRequest() {
    return request;
  }

  public String getAccessToken() {
    return ACCESS_TOKEN;
  }
}
