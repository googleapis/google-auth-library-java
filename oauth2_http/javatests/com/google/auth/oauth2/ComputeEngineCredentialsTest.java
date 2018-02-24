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

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static com.google.common.truth.Truth.assertThat;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.common.collect.ImmutableSet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Collection;

/**
 * Test case for {@link ComputeEngineCredentials}.
 */
@RunWith(JUnit4.class)
public class ComputeEngineCredentialsTest extends BaseSerializationTest {

  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  private static final Collection<String> SCOPES =
      ImmutableSet.<String>of("SCOPE1", "SCOPE2");

  static class MockMetadataServerTransportFactory implements HttpTransportFactory {

    MockMetadataServerTransport transport = new MockMetadataServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, accessToken);
  }

  @Test
  public void getRequestMetadata_missingServiceAccount_throws() {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Expected error refreshing token.");
    } catch (IOException expected) {
      String message = expected.getMessage();
      assertTrue(message.contains(Integer.toString(HttpStatusCodes.STATUS_CODE_NOT_FOUND)));
      // Message should mention scopes are missing on the VM.
      assertTrue(message.contains("scope"));
    }
  }

  @Test
  public void createScoped_fromInstanceAndScopes() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    assertThat(credentials.createScopedRequired()).isTrue();

    GoogleCredentials scopedCredentials = credentials.createScoped(SCOPES);
    assertThat(scopedCredentials.createScopedRequired()).isFalse();
  }

  @Test
  public void createScoped_fromBuilder() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials = ComputeEngineCredentials
      .newBuilder()
      .setHttpTransportFactory(transportFactory)
      .setScopes(SCOPES)
      .build();
    assertThat(credentials.createScopedRequired()).isFalse();
  }

  public void getRequestMetadata_serverError_throws() {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Expected error refreshing token.");
    } catch (IOException expected) {
      String message = expected.getMessage();
      assertTrue(message.contains(Integer.toString(HttpStatusCodes.STATUS_CODE_SERVER_ERROR)));
      assertTrue(message.contains("Unexpected"));
    }
  }

  @Test
  public void equals_true() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    ComputeEngineCredentials otherCredentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_transportFactory() throws IOException {
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(serverTransportFactory).build();
    ComputeEngineCredentials otherCredentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(httpTransportFactory).build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    String expectedToString =
        String.format("ComputeEngineCredentials{transportFactoryClassName=%s}",
            MockMetadataServerTransportFactory.class.getName());
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(serverTransportFactory).build();
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(serverTransportFactory).build();
    ComputeEngineCredentials otherCredentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(serverTransportFactory).build();
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(serverTransportFactory).build();
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
    credentials = ComputeEngineCredentials.newBuilder().build();
    deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }
}
