/*
 * Copyright 2024 Google LLC
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

import static com.google.auth.TestUtils.getDefaultExpireTime;
import static com.google.auth.oauth2.ImpersonatedCredentialsTest.DEFAULT_IMPERSONATION_URL;
import static com.google.auth.oauth2.ImpersonatedCredentialsTest.IMMUTABLE_SCOPES_LIST;
import static com.google.auth.oauth2.ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL;
import static com.google.auth.oauth2.ImpersonatedCredentialsTest.TOKEN_WITH_EMAIL;
import static com.google.auth.oauth2.ImpersonatedCredentialsTest.VALID_LIFETIME;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.ACCESS_TOKEN;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.CALL_URI;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.CLIENT_EMAIL;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.DEFAULT_ID_TOKEN;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.SCOPES;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.createDefaultBuilder;
import static com.google.auth.oauth2.UserCredentialsTest.CLIENT_ID;
import static com.google.auth.oauth2.UserCredentialsTest.CLIENT_SECRET;
import static com.google.auth.oauth2.UserCredentialsTest.REFRESH_TOKEN;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.json.webtoken.JsonWebToken.Payload;
import com.google.auth.TestAppender;
import com.google.auth.TestUtils;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingTest {

  private static final Gson gson = new Gson();

  private TestAppender setupTestLogger(Class<?> clazz) {
    TestAppender testAppender = new TestAppender();
    testAppender.start();
    Logger logger = LoggerFactory.getLogger(clazz);
    ((ch.qos.logback.classic.Logger) logger).addAppender(testAppender);
    return testAppender;
  }

  @Test
  public void userCredentials_getRequestMetadata_fromRefreshToken_hasAccessToken()
      throws IOException {
    TestAppender testAppender = setupTestLogger(UserCredentials.class);
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);

    assertEquals(3, testAppender.events.size());
    JsonObject jsonMessage =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);

    assertEquals(
        "com.google.auth.oauth2.UserCredentials", testAppender.events.get(0).getLoggerName());
    assertEquals(
        "Sending auth request to refresh access token", jsonMessage.get("message").getAsString());
    testAppender.stop();
  }

  @Test
  public void serviceAccountCredentials_getRequestMetadata_hasAccessToken() throws IOException {
    TestAppender testAppender = setupTestLogger(ServiceAccountCredentials.class);
    GoogleCredentials credentials =
        ServiceAccountCredentialsTest.createDefaultBuilderWithToken(ACCESS_TOKEN)
            .setScopes(SCOPES)
            .build();
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);

    assertEquals(3, testAppender.events.size());
    JsonObject jsonMessage =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);

    assertEquals(
        "Sending auth request to refresh access token", jsonMessage.get("message").getAsString());
    testAppender.stop();
  }

  @Test
  public void serviceAccountCredentials_idTokenWithAudience_iamFlow_targetAudienceMatchesAudClaim()
      throws IOException {
    TestAppender testAppender = setupTestLogger(ServiceAccountCredentials.class);
    String nonGDU = "test.com";
    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory(nonGDU);
    transportFactory.getTransport().setTargetPrincipal(CLIENT_EMAIL);
    transportFactory.getTransport().setIdToken(DEFAULT_ID_TOKEN);
    transportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");
    ServiceAccountCredentials credentials =
        createDefaultBuilder()
            .setScopes(SCOPES)
            .setHttpTransportFactory(transportFactory)
            .setUniverseDomain(nonGDU)
            .build();

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());

    // ID Token's aud claim is `https://foo.bar`
    assertEquals(
        targetAudience,
        tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudience());

    assertEquals(2, testAppender.events.size());

    JsonObject jsonMessage1 =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);
    JsonObject jsonMessage2 =
        gson.fromJson(testAppender.events.get(1).getFormattedMessage(), JsonObject.class);
    assertEquals(
        "Sending Auth request to get id token via Iam Endpoint",
        jsonMessage1.get("message").getAsString());
    assertEquals("Auth response payload", jsonMessage2.get("message").getAsString());

    testAppender.stop();
  }

  @Test()
  public void impersonatedCredentials_refreshAccessToken_success()
      throws IOException, IllegalStateException {
    TestAppender testAppender = setupTestLogger(ImpersonatedCredentials.class);
    MockIAMCredentialsServiceTransportFactory mockTransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mockTransportFactory.getTransport().setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.getTransport().setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.getTransport().setExpireTime(getDefaultExpireTime());
    mockTransportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            ImpersonatedCredentialsTest.getSourceCredentials(),
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
    assertEquals(
        DEFAULT_IMPERSONATION_URL, mockTransportFactory.getTransport().getRequest().getUrl());

    // verify metrics header added and authorization header intact
    Map<String, List<String>> requestHeader =
        mockTransportFactory.getTransport().getRequest().getHeaders();
    com.google.auth.oauth2.TestUtils.validateMetricsHeader(requestHeader, "at", "imp");
    assertTrue(requestHeader.containsKey("authorization"));

    assertEquals(3, testAppender.events.size());
    JsonObject jsonMessage =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);

    assertEquals(
        "com.google.auth.oauth2.ImpersonatedCredentials",
        testAppender.events.get(0).getLoggerName());
    assertEquals(
        "Sending auth request to refresh access token", jsonMessage.get("message").getAsString());
    assertEquals(4, testAppender.events.get(0).getMDCPropertyMap().size());
    testAppender.stop();
  }

  @Test
  public void idTokenWithAudience_withEmail() throws IOException {
    TestAppender testAppender = setupTestLogger(IamUtils.class);
    MockIAMCredentialsServiceTransportFactory mockTransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mockTransportFactory.getTransport().setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.getTransport().setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.getTransport().setExpireTime(getDefaultExpireTime());
    mockTransportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            ImpersonatedCredentialsTest.getSourceCredentials(),
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    mockTransportFactory.getTransport().setIdToken(TOKEN_WITH_EMAIL);

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(targetCredentials)
            .setTargetAudience(targetAudience)
            .setOptions(Arrays.asList(IdTokenProvider.Option.INCLUDE_EMAIL))
            .build();
    tokenCredential.refresh();
    assertEquals(TOKEN_WITH_EMAIL, tokenCredential.getAccessToken().getTokenValue());
    Payload p = tokenCredential.getIdToken().getJsonWebSignature().getPayload();
    assertTrue(p.containsKey("email"));

    assertEquals(3, testAppender.events.size());
    JsonObject jsonMessage =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);

    assertEquals("com.google.auth.oauth2.IamUtils", testAppender.events.get(0).getLoggerName());
    assertEquals("Sending auth request to get id token", jsonMessage.get("message").getAsString());
    assertEquals(4, testAppender.events.get(0).getMDCPropertyMap().size());
    testAppender.stop();
  }

  @Test
  public void sign_sameAs() throws IOException {
    TestAppender testAppender = setupTestLogger(IamUtils.class);
    MockIAMCredentialsServiceTransportFactory mockTransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mockTransportFactory.getTransport().setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.getTransport().setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.getTransport().setExpireTime(getDefaultExpireTime());
    mockTransportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            ImpersonatedCredentialsTest.getSourceCredentials(),
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.getTransport().setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.getTransport().setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));

    assertEquals(3, testAppender.events.size());
    JsonObject jsonMessage =
        gson.fromJson(testAppender.events.get(0).getFormattedMessage(), JsonObject.class);

    assertEquals("com.google.auth.oauth2.IamUtils", testAppender.events.get(0).getLoggerName());
    assertEquals(
        "Sending auth request to get signature to sign the blob",
        jsonMessage.get("message").getAsString());
    assertEquals(4, testAppender.events.get(0).getMDCPropertyMap().size());
    assertEquals(1, testAppender.events.get(2).getMDCPropertyMap().size());
    testAppender.stop();
  }
}
