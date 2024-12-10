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

import static com.google.auth.oauth2.ServiceAccountCredentialsTest.ACCESS_TOKEN;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.CALL_URI;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.CLIENT_EMAIL;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.DEFAULT_ID_TOKEN;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.SCOPES;
import static com.google.auth.oauth2.ServiceAccountCredentialsTest.createDefaultBuilder;
import static org.junit.Assert.assertEquals;

import com.google.api.client.http.HttpStatusCodes;
import com.google.auth.TestAppender;
import com.google.auth.TestUtils;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingTest {

  private TestAppender setupTestLogger(Class<?> clazz) {
    TestAppender testAppender = new TestAppender();
    testAppender.start();
    Logger logger = LoggerFactory.getLogger(clazz);
    ((ch.qos.logback.classic.Logger) logger).addAppender(testAppender);
    return testAppender;
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    TestAppender testAppender = setupTestLogger(ServiceAccountCredentials.class);
    GoogleCredentials credentials =
        ServiceAccountCredentialsTest.createDefaultBuilderWithToken(ACCESS_TOKEN)
            .setScopes(SCOPES)
            .build();
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);

    assertEquals(3, testAppender.events.size());
    assertEquals(
        "Sending auth request to refresh access token",
        testAppender.events.get(0).getFormattedMessage());
    testAppender.stop();
  }

  @Test
  public void idTokenWithAudience_iamFlow_targetAudienceMatchesAudClaim() throws IOException {
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
    assertEquals(
        "Sending Auth request to get id token via Iam Endpoint",
        testAppender.events.get(0).getFormattedMessage());
    assertEquals("Auth response payload", testAppender.events.get(1).getFormattedMessage());

    testAppender.stop();
  }
}
