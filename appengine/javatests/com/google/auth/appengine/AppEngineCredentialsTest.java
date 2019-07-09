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

package com.google.auth.appengine;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.auth.Credentials;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.BaseSerializationTest;
import com.google.auth.oauth2.GoogleCredentials;

import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for AppEngineCredentials
 */
@RunWith(JUnit4.class)
public class AppEngineCredentialsTest extends BaseSerializationTest {
  
  private static final Collection<String> SCOPES =
      Collections.unmodifiableCollection(Arrays.asList("scope1", "scope2"));
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  private static final String EXPECTED_ACCOUNT = "serviceAccount";
  
  @Test  
  public void constructor_usesAppIdentityService() throws IOException {
    final String expectedAccessToken = "ExpectedAccessToken";

    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setAccessTokenText(expectedAccessToken);
    Credentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(SCOPES)
        .setAppIdentityService(appIdentity)
        .build();

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    assertEquals(1, appIdentity.getGetAccessTokenCallCount());
    assertContainsBearerToken(metadata, expectedAccessToken);
  }

  @Test
  public void refreshAccessToken_sameAs() throws IOException {
    final String expectedAccessToken = "ExpectedAccessToken";

    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setAccessTokenText(expectedAccessToken);
    appIdentity.setExpiration(new Date(System.currentTimeMillis() + 60L * 60L * 100L));
    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(SCOPES)
        .setAppIdentityService(appIdentity)
        .build();
    AccessToken accessToken = credentials.refreshAccessToken();
    assertEquals(appIdentity.getAccessTokenText(), accessToken.getTokenValue());
    assertEquals(appIdentity.getExpiration(), accessToken.getExpirationTime());
  }

  @Test
  public void getAccount_sameAs() throws IOException {
    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setServiceAccountName(EXPECTED_ACCOUNT);
    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(SCOPES)
        .setAppIdentityService(appIdentity)
        .build();
    assertEquals(EXPECTED_ACCOUNT, credentials.getAccount());
  }

  @Test
  public void sign_sameAs() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};
    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setSignature(expectedSignature);
    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(SCOPES)
        .setAppIdentityService(appIdentity)
        .build();
    assertArrayEquals(expectedSignature, credentials.sign(expectedSignature));
  }

  @Test
  public void createScoped_clonesWithScopes() throws IOException {
    final String expectedAccessToken = "ExpectedAccessToken";
    final Collection<String> emptyScopes = Collections.emptyList();

    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setAccessTokenText(expectedAccessToken);

    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    assertTrue(credentials.createScopedRequired());
    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Should not be able to use credential without scopes.");
    } catch (Exception expected) {
    }
    assertEquals(0, appIdentity.getGetAccessTokenCallCount());

    GoogleCredentials scopedCredentials = credentials.createScoped(SCOPES);
    assertNotSame(credentials, scopedCredentials);
    
    Map<String, List<String>> metadata = scopedCredentials.getRequestMetadata(CALL_URI);

    assertEquals(1, appIdentity.getGetAccessTokenCallCount());
    assertContainsBearerToken(metadata, expectedAccessToken);
  }

  @Test
  public void equals_true() throws IOException {
    final Collection<String> emptyScopes = Collections.emptyList();
    MockAppIdentityService appIdentity = new MockAppIdentityService();

    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    AppEngineCredentials otherCredentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    assertTrue(credentials.equals(credentials));
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_scopes() throws IOException {
    final Collection<String> emptyScopes = Collections.emptyList();
    final Collection<String> scopes = Collections.singleton("SomeScope");
    MockAppIdentityService appIdentity = new MockAppIdentityService();

    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    AppEngineCredentials otherCredentials = AppEngineCredentials.newBuilder()
        .setScopes(scopes)
        .setAppIdentityService(appIdentity)
        .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    String expectedToString = String.format(
        "AppEngineCredentials{scopes=[%s], scopesRequired=%b, appIdentityServiceClassName=%s}",
        "SomeScope",
        false,
        MockAppIdentityService.class.getName());
    final Collection<String> scopes = Collections.singleton("SomeScope");
    MockAppIdentityService appIdentity = new MockAppIdentityService();

    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(scopes)
        .setAppIdentityService(appIdentity)
        .build();

    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    final Collection<String> emptyScopes = Collections.emptyList();
    MockAppIdentityService appIdentity = new MockAppIdentityService();
    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    AppEngineCredentials otherCredentials = AppEngineCredentials.newBuilder()
        .setScopes(emptyScopes)
        .setAppIdentityService(appIdentity)
        .build();
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final Collection<String> scopes = Collections.singleton("SomeScope");
    MockAppIdentityService appIdentity = new MockAppIdentityService();
    AppEngineCredentials credentials = AppEngineCredentials.newBuilder()
        .setScopes(scopes)
        .setAppIdentityService(appIdentity)
        .build();
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
  }

  private static void assertContainsBearerToken(Map<String, List<String>> metadata, String token) {
    assertNotNull(metadata);
    assertNotNull(token);
    String expectedValue = "Bearer " + token;
    List<String> authorizations = metadata.get("Authorization");
    assertNotNull("Authorization headers not found", authorizations);
    boolean found = false;
    for (String authorization : authorizations) {
      if (expectedValue.equals(authorization)) {
        found = true;
        break;
      }
    }
    assertTrue("Bearer token not found", found);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void warnsDefaultCredentials() {
    Logger logger = Logger.getLogger(AppEngineCredentials.class.getName());
    LogHandler handler = new LogHandler();
    logger.addHandler(handler);

    try {
      Credentials unused = AppEngineCredentials.getApplicationDefault();
    } catch (IOException ex) {
      // ignore - this may just fail for not being in a supported environment
    }

    LogRecord message = handler.getRecord();
    assertTrue(message.getMessage().contains("You are attempting to"));
  }

  @Test
  @SuppressWarnings("deprecation")
  public void warnsDefaultCredentialsWithTransport() {
    Logger logger = Logger.getLogger(AppEngineCredentials.class.getName());
    LogHandler handler = new LogHandler();
    logger.addHandler(handler);

    try {
      Credentials unused = AppEngineCredentials.getApplicationDefault(
          new HttpTransportFactory() {
            @Override
            public HttpTransport create() {
              return null;
            }
          });
    } catch (IOException ex) {
      // ignore - this may just fail for not being in a supported environment
    }

    LogRecord message = handler.getRecord();
    assertTrue(message.getMessage().contains("You are attempting to"));
  }

  private class LogHandler extends Handler {
    LogRecord lastRecord;

    public void publish(LogRecord record) {
      lastRecord = record;
    }

    public LogRecord getRecord() {
      return lastRecord;
    }

    public void close() {}
    public void flush() {}
  }
}
