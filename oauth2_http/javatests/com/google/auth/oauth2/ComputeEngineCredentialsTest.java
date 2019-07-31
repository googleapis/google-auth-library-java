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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.Clock;
import com.google.auth.ServiceAccountSigner.SigningException;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link ComputeEngineCredentials}. */
@RunWith(JUnit4.class)
public class ComputeEngineCredentialsTest extends BaseSerializationTest {

  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

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
  public void getRequestMetadata_serverError_throws() {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_SERVER_ERROR);
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
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .build();
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
        String.format(
            "ComputeEngineCredentials{transportFactoryClassName=%s}",
            MockMetadataServerTransportFactory.class.getName());
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .build();
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .build();
    ComputeEngineCredentials otherCredentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .build();
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .build();
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

  @Test
  public void getAccount_sameAs() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    assertEquals(defaultAccountEmail, credentials.getAccount());
  }

  @Test
  public void getAccount_missing_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            if (isGetServiceAccountsUrl(url)) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND)
                      .setContent("");
                }
              };
            }
            return super.buildRequest(method, url);
          }
        };
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      credentials.getAccount();
      fail("Fetching default service account should have failed");
    } catch (RuntimeException e) {
      assertEquals("Failed to to get service account", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("404"));
    }
  }

  @Test
  public void getAccount_emptyContent_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            if (isGetServiceAccountsUrl(url)) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
                }
              };
            }
            return super.buildRequest(method, url);
          }
        };
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      credentials.getAccount();
      fail("Fetching default service account should have failed");
    } catch (RuntimeException e) {
      assertEquals("Failed to to get service account", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("Empty content"));
    }
  }

  @Test
  public void sign_sameAs() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    String defaultAccountEmail = "mail@mail.com";
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);
    transportFactory.transport.setSignature(expectedSignature);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    assertEquals(defaultAccountEmail, credentials.getAccount());
  }

  @Test
  public void sign_getAccountFails() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setSignature(expectedSignature);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      credentials.sign(expectedSignature);
      fail();
    } catch (SigningException ex) {
      assertNotNull(ex.getMessage());
      assertNotNull(ex.getCause());
    }
  }

  @Test
  public void sign_accessDenied_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            if (isSignRequestUrl(url)) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(HttpStatusCodes.STATUS_CODE_FORBIDDEN)
                      .setContent(TestUtils.errorJson("Sign Error"));
                }
              };
            }
            return super.buildRequest(method, url);
          }
        };

    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      byte[] bytes = {0xD, 0xE, 0xA, 0xD};
      credentials.sign(bytes);
      fail("Signing should have failed");
    } catch (SigningException e) {
      assertEquals("Failed to sign the provided bytes", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("403"));
    }
  }

  @Test
  public void sign_serverError_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            if (isSignRequestUrl(url)) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(HttpStatusCodes.STATUS_CODE_SERVER_ERROR)
                      .setContent(TestUtils.errorJson("Sign Error"));
                }
              };
            }
            return super.buildRequest(method, url);
          }
        };

    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      byte[] bytes = {0xD, 0xE, 0xA, 0xD};
      credentials.sign(bytes);
      fail("Signing should have failed");
    } catch (SigningException e) {
      assertEquals("Failed to sign the provided bytes", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("500"));
    }
  }

  @Test
  public void sign_emptyContent_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    String defaultAccountEmail = "mail@mail.com";

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            if (isSignRequestUrl(url)) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(HttpStatusCodes.STATUS_CODE_OK);
                }
              };
            }
            return super.buildRequest(method, url);
          }
        };

    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setServiceAccountEmail(defaultAccountEmail);

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      byte[] bytes = {0xD, 0xE, 0xA, 0xD};
      credentials.sign(bytes);
      fail("Signing should have failed");
    } catch (SigningException e) {
      assertEquals("Failed to sign the provided bytes", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("Empty content"));
    }
  }
}
