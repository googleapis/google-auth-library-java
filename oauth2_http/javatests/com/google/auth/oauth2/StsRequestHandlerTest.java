/*
 * Copyright 2020 Google LLC
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

import static com.google.auth.TestUtils.buildHttpResponseException;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Joiner;
import com.google.auth.TestUtils;
import com.google.auth.oauth2.StsTokenExchangeRequest.ActingParty;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link StsRequestHandler}. */
@RunWith(JUnit4.class)
public final class StsRequestHandlerTest {

  private static final String TOKEN_EXCHANGE_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String DEFAULT_REQUESTED_TOKEN_TYPE =
      "urn:ietf:params:oauth:token-type:access_token";
  private static final String TOKEN_URL = "https://www.sts.google.com";
  private static final String CREDENTIAL = "credential";
  private static final String SUBJECT_TOKEN_TYPE = "subjectTokenType";

  // Optional params.
  private static final String AUDIENCE = "audience";
  private static final String RESOURCE = "resource";
  private static final String ACTOR_TOKEN = "actorToken";
  private static final String ACTOR_TOKEN_TYPE = "actorTokenType";
  private static final String REQUESTED_TOKEN_TYPE = "requestedTokenType";
  private static final String INTERNAL_OPTIONS = "internalOptions";
  private static final String REFRESH_TOKEN = "refreshToken";
  private static final List<String> SCOPES = Arrays.asList("scope1", "scope2", "scope3");

  // Headers.
  private static final String CONTENT_TYPE_KEY = "content-type";
  private static final String CONTENT_TYPE = "application/x-www-form-urlencoded";
  private static final String ACCEPT_ENCODING_KEY = "accept-encoding";
  private static final String ACCEPT_ENCODING = "gzip";
  private static final String CUSTOM_HEADER_KEY = "custom_header_key";
  private static final String CUSTOM_HEADER_VALUE = "custom_header_value";

  private static final String INVALID_REQUEST = "invalid_request";
  private static final String ERROR_DESCRIPTION = "errorDescription";
  private static final String ERROR_URI = "errorUri";

  private MockExternalAccountCredentialsTransport transport;

  @Before
  public void setup() {
    transport = new MockExternalAccountCredentialsTransport();
  }

  @Test
  public void exchangeToken() throws IOException {
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE)
            .setScopes(Arrays.asList(CLOUD_PLATFORM_SCOPE))
            .build();

    StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                TOKEN_URL, stsTokenExchangeRequest, transport.createRequestFactory())
            .build();

    StsTokenExchangeResponse response = requestHandler.exchangeToken();

    // Validate response.
    assertThat(response.getAccessToken().getTokenValue()).isEqualTo(transport.getAccessToken());
    assertThat(response.getTokenType()).isEqualTo(transport.getTokenType());
    assertThat(response.getIssuedTokenType()).isEqualTo(transport.getIssuedTokenType());
    assertThat(response.getExpiresIn()).isEqualTo(transport.getExpiresIn());

    // Validate request content.
    GenericData expectedRequestContent =
        new GenericData()
            .set("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
            .set("scope", CLOUD_PLATFORM_SCOPE)
            .set("requested_token_type", DEFAULT_REQUESTED_TOKEN_TYPE)
            .set("subject_token_type", stsTokenExchangeRequest.getSubjectTokenType())
            .set("subject_token", stsTokenExchangeRequest.getSubjectToken());

    MockLowLevelHttpRequest request = transport.getRequest();
    Map<String, String> actualRequestContent = TestUtils.parseQuery(request.getContentAsString());
    assertThat(actualRequestContent).isEqualTo(expectedRequestContent);
  }

  @Test
  public void exchangeToken_withOptionalParams() throws IOException {
    // Return optional params scope and the refresh_token.
    transport.addScopeSequence(SCOPES);
    transport.addRefreshTokenSequence(REFRESH_TOKEN);

    // Build the token exchange request.
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE)
            .setAudience(AUDIENCE)
            .setResource(RESOURCE)
            .setActingParty(new ActingParty(ACTOR_TOKEN, ACTOR_TOKEN_TYPE))
            .setRequestTokenType(REQUESTED_TOKEN_TYPE)
            .setScopes(SCOPES)
            .build();

    HttpHeaders httpHeaders =
        new HttpHeaders()
            .setContentType(CONTENT_TYPE)
            .setAcceptEncoding(ACCEPT_ENCODING)
            .set(CUSTOM_HEADER_KEY, CUSTOM_HEADER_VALUE);

    StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                TOKEN_URL, stsTokenExchangeRequest, transport.createRequestFactory())
            .setHeaders(httpHeaders)
            .setInternalOptions(INTERNAL_OPTIONS)
            .build();

    StsTokenExchangeResponse response = requestHandler.exchangeToken();

    // Validate response.
    assertThat(response.getAccessToken().getTokenValue()).isEqualTo(transport.getAccessToken());
    assertThat(response.getTokenType()).isEqualTo(transport.getTokenType());
    assertThat(response.getIssuedTokenType()).isEqualTo(transport.getIssuedTokenType());
    assertThat(response.getExpiresIn()).isEqualTo(transport.getExpiresIn());
    assertThat(response.getScopes()).isEqualTo(SCOPES);
    assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);

    // Validate headers.
    MockLowLevelHttpRequest request = transport.getRequest();
    Map<String, List<String>> requestHeaders = request.getHeaders();
    assertThat(requestHeaders.get(CONTENT_TYPE_KEY).get(0)).isEqualTo(CONTENT_TYPE);
    assertThat(requestHeaders.get(ACCEPT_ENCODING_KEY).get(0)).isEqualTo(ACCEPT_ENCODING);
    assertThat(requestHeaders.get(CUSTOM_HEADER_KEY).get(0)).isEqualTo(CUSTOM_HEADER_VALUE);

    // Validate request content.
    GenericData expectedRequestContent =
        new GenericData()
            .set("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
            .set("scope", Joiner.on(' ').join(SCOPES))
            .set("options", INTERNAL_OPTIONS)
            .set("subject_token_type", stsTokenExchangeRequest.getSubjectTokenType())
            .set("subject_token", stsTokenExchangeRequest.getSubjectToken())
            .set("requested_token_type", stsTokenExchangeRequest.getRequestedTokenType())
            .set("actor_token", stsTokenExchangeRequest.getActingParty().getActorToken())
            .set("actor_token_type", stsTokenExchangeRequest.getActingParty().getActorTokenType())
            .set("resource", stsTokenExchangeRequest.getResource())
            .set("audience", stsTokenExchangeRequest.getAudience());

    Map<String, String> actualRequestContent = TestUtils.parseQuery(request.getContentAsString());
    assertThat(actualRequestContent).isEqualTo(expectedRequestContent);
  }

  @Test
  public void exchangeToken_throwsException() throws IOException {
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE).build();

    final StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                TOKEN_URL, stsTokenExchangeRequest, transport.createRequestFactory())
            .build();

    transport.addResponseErrorSequence(
        buildHttpResponseException(
            INVALID_REQUEST, /* errorDescription= */ null, /* errorUri= */ null));

    OAuthException e =
        assertThrows(
            OAuthException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                requestHandler.exchangeToken();
              }
            });

    assertThat(e.getErrorCode()).isEqualTo(INVALID_REQUEST);
    assertThat(e.getErrorDescription()).isNull();
    assertThat(e.getErrorUri()).isNull();
  }

  @Test
  public void exchangeToken_withOptionalParams_throwsException() throws IOException {
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE).build();

    final StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                TOKEN_URL, stsTokenExchangeRequest, transport.createRequestFactory())
            .build();

    transport.addResponseErrorSequence(
        buildHttpResponseException(INVALID_REQUEST, ERROR_DESCRIPTION, ERROR_URI));

    OAuthException e =
        assertThrows(
            OAuthException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                requestHandler.exchangeToken();
              }
            });

    assertThat(e.getErrorCode()).isEqualTo(INVALID_REQUEST);
    assertThat(e.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
    assertThat(e.getErrorUri()).isEqualTo(ERROR_URI);
  }

  @Test
  public void exchangeToken_ioException() {
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE).build();

    final StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                TOKEN_URL, stsTokenExchangeRequest, transport.createRequestFactory())
            .build();

    IOException e = new IOException();
    transport.addResponseErrorSequence(e);

    IOException thrownException =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                requestHandler.exchangeToken();
              }
            });
    assertThat(thrownException).isEqualTo(e);
  }
}
