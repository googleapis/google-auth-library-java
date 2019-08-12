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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.webtoken.JsonWebToken.Payload;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.ArrayMap;
import com.google.api.client.util.Clock;
import com.google.auth.ServiceAccountSigner.SigningException;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link ComputeEngineCredentials}. */
@RunWith(JUnit4.class)
public class ComputeEngineCredentialsTest extends BaseSerializationTest {

  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  // Id Token which includes basic default claims
  public static final String STANDARD_ID_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIyO"
          + "TNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiL"
          + "CJhenAiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgiLCJleHAiOjE1NjQ0NzUwNTEsImlhdCI6MTU2NDQ3MTQ1MSwi"
          + "aXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTAyMTAxNTUwODM0MjAwNzA4NTY4In0"
          + ".redacted";

  // Id Token which includes GCE extended claims
  public static final String FULL_ID_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIyOTNh"
          + "ZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJhe"
          + "nAiOiIxMTIxNzkwNjI3MjAzOTEzMDU4ODUiLCJlbWFpbCI6IjEwNzEyODQxODQ0MzYtY29tcHV0ZUBkZXZlbG9wZ"
          + "XIuZ3NlcnZpY2VhY2NvdW50LmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE1NjQ1MTk0OTYsImdvb"
          + "2dsZSI6eyJjb21wdXRlX2VuZ2luZSI6eyJpbnN0YW5jZV9jcmVhdGlvbl90aW1lc3RhbXAiOjE1NjMyMzA5MDcsI"
          + "mluc3RhbmNlX2lkIjoiMzQ5Nzk3NDM5MzQ0MTE3OTI0MyIsImluc3RhbmNlX25hbWUiOiJpYW0iLCJwcm9qZWN0X"
          + "2lkIjoibWluZXJhbC1taW51dGlhLTgyMCIsInByb2plY3RfbnVtYmVyIjoxMDcxMjg0MTg0NDM2LCJ6b25lIjoid"
          + "XMtY2VudHJhbDEtYSJ9fSwiaWF0IjoxNTY0NTE1ODk2LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb"
          + "20iLCJzdWIiOiIxMTIxNzkwNjI3MjAzOTEzMDU4ODUifQ.redacted";

  // Id Token which includes GCE extended claims and any VM License data (if applicable)
  public static final String FULL_ID_TOKEN_WITH_LICENSE =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOG"
          + "I3OTIyOTNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.ew0KICAiYXVkIjogImh0dHBzOi8"
          + "vZm9vLmJhciIsDQogICJhenAiOiAiMTEyMTc5MDYyNzIwMzkxMzA1ODg1IiwNCiAgImVtYWlsIjogIjEyMzQ1Ni1"
          + "jb21wdXRlQGRldmVsb3Blci5nc2VydmljZWFjY291bnQuY29tIiwNCiAgImVtYWlsX3ZlcmlmaWVkIjogdHJ1ZSw"
          + "NCiAgImV4cCI6IDE1NjQ1MTk0OTYsDQogICJnb29nbGUiOiB7DQogICAgImNvbXB1dGVfZW5naW5lIjogew0KICA"
          + "gICAgImluc3RhbmNlX2NyZWF0aW9uX3RpbWVzdGFtcCI6IDE1NjMyMzA5MDcsDQogICAgICAiaW5zdGFuY2VfaWQ"
          + "iOiAiMzQ5Nzk3NDM5MzQ0MTE3OTI0MyIsDQogICAgICAiaW5zdGFuY2VfbmFtZSI6ICJpYW0iLA0KICAgICAgInB"
          + "yb2plY3RfaWQiOiAiZm9vLWJhci04MjAiLA0KICAgICAgInByb2plY3RfbnVtYmVyIjogMTA3MTI4NDE4NDQzNiw"
          + "NCiAgICAgICJ6b25lIjogInVzLWNlbnRyYWwxLWEiDQogICAgfSwNCiAgICAibGljZW5zZSI6IFsNCiAgICAgICA"
          + "iTElDRU5TRV8xIiwNCiAgICAgICAiTElDRU5TRV8yIg0KICAgIF0NCiAgfSwNCiAgImlhdCI6IDE1NjQ1MTU4OTY"
          + "sDQogICJpc3MiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwNCiAgInN1YiI6ICIxMTIxNzkwNjI3MjA"
          + "zOTEzMDU4ODUiDQp9.redacted";

  static class MockMetadataServerTransportFactory implements HttpTransportFactory {

    MockMetadataServerTransport transport = new MockMetadataServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, accessToken);
  }

  @Test
  public void getRequestMetadata_missingServiceAccount_throws() {
    String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
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
    String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
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
      assertEquals("Failed to get service account", e.getMessage());
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
      assertEquals("Failed to get service account", e.getMessage());
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

    assertArrayEquals(expectedSignature, credentials.sign(expectedSignature));
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
    String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
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

  @Test
  public void idTokenWithAudience_sameAs() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setIdToken(STANDARD_ID_TOKEN);
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());
    assertEquals(
        targetAudience,
        (String) tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudience());
  }

  @Test
  public void idTokenWithAudience_standard() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());
    assertNull(tokenCredential.getIdToken().getJsonWebSignature().getPayload().get("google"));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void idTokenWithAudience_full() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .setOptions(Arrays.asList(IdTokenProvider.Option.FORMAT_FULL))
            .build();
    tokenCredential.refresh();
    Payload p = tokenCredential.getIdToken().getJsonWebSignature().getPayload();
    if (!p.containsKey("google")) {
      assertFalse("Full ID Token format not provided", false);
    }
    ArrayMap<String, ArrayMap> googleClaim = (ArrayMap<String, ArrayMap>) p.get("google");
    assert (googleClaim.containsKey("compute_engine"));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void idTokenWithAudience_license() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .setOptions(
                Arrays.asList(
                    IdTokenProvider.Option.FORMAT_FULL, IdTokenProvider.Option.LICENSES_TRUE))
            .build();
    tokenCredential.refresh();
    Payload p = tokenCredential.getIdToken().getJsonWebSignature().getPayload();
    if (!p.containsKey("google")) {
      assertFalse("Full ID Token format not provided", false);
    }
    ArrayMap<String, ArrayMap> googleClaim = (ArrayMap<String, ArrayMap>) p.get("google");
    assert (googleClaim.containsKey("license"));
  }
}
