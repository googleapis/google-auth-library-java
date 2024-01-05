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
import com.google.auth.Credentials;
import com.google.auth.ServiceAccountSigner.SigningException;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.DefaultCredentialsProviderTest.MockRequestCountingTransportFactory;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.stream.IntStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link ComputeEngineCredentials}. */
@RunWith(JUnit4.class)
public class ComputeEngineCredentialsTest extends BaseSerializationTest {

  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  private static final String TOKEN_URL =
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

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

  @Test
  public void buildTokenUrlWithScopes_null_scopes() {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setScopes(null).build();
    Collection<String> scopes = credentials.getScopes();
    String tokenUrlWithScopes = credentials.createTokenUrlWithScopes();

    assertEquals(TOKEN_URL, tokenUrlWithScopes);
    assertTrue(scopes.isEmpty());
  }

  @Test
  public void buildTokenUrlWithScopes_empty_scopes() {
    ComputeEngineCredentials.Builder builder =
        ComputeEngineCredentials.newBuilder().setScopes(Collections.<String>emptyList());
    ComputeEngineCredentials credentials = builder.build();
    Collection<String> scopes = credentials.getScopes();
    String tokenUrlWithScopes = credentials.createTokenUrlWithScopes();

    assertEquals(TOKEN_URL, tokenUrlWithScopes);
    assertTrue(scopes.isEmpty());
    assertTrue(builder.getScopes().isEmpty());
  }

  @Test
  public void buildTokenUrlWithScopes_single_scope() {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setScopes(Arrays.asList("foo")).build();
    String tokenUrlWithScopes = credentials.createTokenUrlWithScopes();
    Collection<String> scopes = credentials.getScopes();

    assertEquals(TOKEN_URL + "?scopes=foo", tokenUrlWithScopes);
    assertEquals(1, scopes.size());
    assertEquals("foo", scopes.toArray()[0]);
  }

  @Test
  public void buildTokenUrlWithScopes_multiple_scopes() {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setScopes(Arrays.asList(null, "foo", "", "bar"))
            .build();
    Collection<String> scopes = credentials.getScopes();
    String tokenUrlWithScopes = credentials.createTokenUrlWithScopes();

    assertEquals(TOKEN_URL + "?scopes=foo,bar", tokenUrlWithScopes);
    assertEquals(2, scopes.size());
    assertEquals("foo", scopes.toArray()[0]);
    assertEquals("bar", scopes.toArray()[1]);
  }

  @Test
  public void buildTokenUrlWithScopes_defaultScopes() {
    ComputeEngineCredentials credentials = ComputeEngineCredentials.newBuilder().build();
    credentials =
        (ComputeEngineCredentials)
            credentials.createScoped(null, Arrays.asList(null, "foo", "", "bar"));
    Collection<String> scopes = credentials.getScopes();
    String tokenUrlWithScopes = credentials.createTokenUrlWithScopes();

    assertEquals(TOKEN_URL + "?scopes=foo,bar", tokenUrlWithScopes);
    assertEquals(2, scopes.size());
    assertEquals("foo", scopes.toArray()[0]);
    assertEquals("bar", scopes.toArray()[1]);
  }

  @Test
  public void buildScoped_scopesPresent() throws IOException {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setScopes(null).build();
    ComputeEngineCredentials scopedCredentials =
        (ComputeEngineCredentials) credentials.createScoped(Arrays.asList("foo"));
    Collection<String> scopes = scopedCredentials.getScopes();

    assertEquals(1, scopes.size());
    assertEquals("foo", scopes.toArray()[0]);
  }

  @Test
  public void buildScoped_correctMargins() throws IOException {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setScopes(null).build();
    ComputeEngineCredentials scopedCredentials =
        (ComputeEngineCredentials) credentials.createScoped(Arrays.asList("foo"));

    assertEquals(
        ComputeEngineCredentials.COMPUTE_EXPIRATION_MARGIN,
        scopedCredentials.getExpirationMargin());
    assertEquals(
        ComputeEngineCredentials.COMPUTE_REFRESH_MARGIN, scopedCredentials.getRefreshMargin());
  }

  @Test
  public void buildScoped_explicitUniverse() throws IOException {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setScopes(null)
            .setUniverseDomain("some-universe")
            .build();
    ComputeEngineCredentials scopedCredentials =
        (ComputeEngineCredentials) credentials.createScoped(Arrays.asList("foo"));

    assertEquals("some-universe", scopedCredentials.getUniverseDomain());
    assertEquals(true, scopedCredentials.isExplicitUniverseDomain());
  }

  @Test
  public void createScoped_defaultScopes() {
    GoogleCredentials credentials =
        ComputeEngineCredentials.create().createScoped(null, Arrays.asList("foo"));
    Collection<String> scopes = ((ComputeEngineCredentials) credentials).getScopes();

    assertEquals(1, scopes.size());
    assertEquals("foo", scopes.toArray()[0]);
  }

  @Test
  public void create_scoped_correctMargins() {
    GoogleCredentials credentials =
        ComputeEngineCredentials.create().createScoped(null, Arrays.asList("foo"));

    assertEquals(
        ComputeEngineCredentials.COMPUTE_EXPIRATION_MARGIN, credentials.getExpirationMargin());
    assertEquals(ComputeEngineCredentials.COMPUTE_REFRESH_MARGIN, credentials.getRefreshMargin());
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
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
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
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_SERVER_ERROR);
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
    ComputeEngineCredentials explicitUniverseCredentials =
        ComputeEngineCredentials.newBuilder()
            .setUniverseDomain(Credentials.GOOGLE_DEFAULT_UNIVERSE)
            .setHttpTransportFactory(transportFactory)
            .build();
    ComputeEngineCredentials otherCredentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, otherCredentials.getUniverseDomain());
    assertFalse(explicitUniverseCredentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(explicitUniverseCredentials));
    ComputeEngineCredentials otherExplicitUniverseCredentials =
        ComputeEngineCredentials.newBuilder()
            .setUniverseDomain(Credentials.GOOGLE_DEFAULT_UNIVERSE)
            .setHttpTransportFactory(transportFactory)
            .build();
    assertFalse(explicitUniverseCredentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(explicitUniverseCredentials));
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
  public void toString_explicit_containsFields() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    String expectedToString =
        String.format(
            "ComputeEngineCredentials{quotaProjectId=%s, universeDomain=%s, isExplicitUniverseDomain=%s, transportFactoryClassName=%s, scopes=%s}",
            "some-project",
            "some-domain",
            true,
            MockMetadataServerTransportFactory.class.getName(),
            "[some scope]");
    GoogleCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(serverTransportFactory)
            .setQuotaProjectId("some-project")
            .setUniverseDomain("some-domain")
            .build();
    credentials = credentials.createScoped("some scope");
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
  public void toBuilder() {
    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(new MockMetadataServerTransportFactory())
            .setQuotaProjectId("quota-project")
            .build();

    ComputeEngineCredentials secondCredentials = credentials.toBuilder().build();

    assertEquals(credentials, secondCredentials);
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
      fail("Should not be able to use credential without exception.");
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
  public void refresh_503_retryable_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            return new MockLowLevelHttpRequest(url) {
              @Override
              public LowLevelHttpResponse execute() throws IOException {
                return new MockLowLevelHttpResponse()
                    .setStatusCode(HttpStatusCodes.STATUS_CODE_SERVICE_UNAVAILABLE)
                    .setContent(TestUtils.errorJson("Some error"));
              }
            };
          }
        };

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    try {
      credentials.refreshAccessToken();
      fail("Should have failed");
    } catch (IOException e) {
      assertTrue(e.getCause().getMessage().contains("503"));
      assertTrue(e instanceof GoogleAuthException);
      assertTrue(((GoogleAuthException) e).isRetryable());
    }
  }

  @Test
  public void refresh_non503_ioexception_throws() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    final Queue<Integer> responseSequence = new ArrayDeque<>();
    IntStream.rangeClosed(400, 600).forEach(i -> responseSequence.add(i));

    while (!responseSequence.isEmpty()) {
      if (responseSequence.peek() == 503) {
        responseSequence.poll();
        continue;
      }

      transportFactory.transport =
          new MockMetadataServerTransport() {
            @Override
            public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setStatusCode(responseSequence.poll())
                      .setContent(TestUtils.errorJson("Some error"));
                }
              };
            }
          };

      ComputeEngineCredentials credentials =
          ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

      try {
        credentials.refreshAccessToken();
        fail("Should have failed");
      } catch (IOException e) {
        assertFalse(e instanceof GoogleAuthException);
      }
    }
  }

  @Test
  public void getUniverseDomain_fromMetadata() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            return new MockLowLevelHttpRequest(url) {
              @Override
              public LowLevelHttpResponse execute() throws IOException {
                return new MockLowLevelHttpResponse()
                    .setStatusCode(HttpStatusCodes.STATUS_CODE_OK)
                    .setContent("some-universe.xyz");
              }
            };
          }
        };

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String universeDomain = credentials.getUniverseDomain();
    assertEquals("some-universe.xyz", universeDomain);
    assertEquals(false, credentials.isExplicitUniverseDomain());
  }

  @Test
  public void getUniverseDomain_fromMetadata_emptyBecomesDefault() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            return new MockLowLevelHttpRequest(url) {
              @Override
              public LowLevelHttpResponse execute() throws IOException {
                return new MockLowLevelHttpResponse()
                    .setStatusCode(HttpStatusCodes.STATUS_CODE_OK)
                    .setContent("");
              }
            };
          }
        };

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String universeDomain = credentials.getUniverseDomain();
    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, universeDomain);
    assertEquals(false, credentials.isExplicitUniverseDomain());
  }

  @Test
  public void getUniverseDomain_fromMetadata_404_default() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();

    transportFactory.transport =
        new MockMetadataServerTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            return new MockLowLevelHttpRequest(url) {
              @Override
              public LowLevelHttpResponse execute() throws IOException {
                return new MockLowLevelHttpResponse()
                    .setStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND)
                    .setContent("some content");
              }
            };
          }
        };

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    String universeDomain = credentials.getUniverseDomain();
    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, universeDomain);
    assertEquals(false, credentials.isExplicitUniverseDomain());
  }

  @Test
  public void getUniverseDomain_explicitSet_NoMdsCall() throws IOException {
    MockRequestCountingTransportFactory transportFactory =
        new MockRequestCountingTransportFactory();

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setUniverseDomain("explicit.universe")
            .build();

    String universeDomain = credentials.getUniverseDomain();
    assertEquals("explicit.universe", universeDomain);
    assertEquals(true, credentials.isExplicitUniverseDomain());
    assertEquals(0, transportFactory.transport.getRequestCount());
  }

  @Test
  public void getUniverseDomain_explicitGduSet_NoMdsCall() throws IOException {
    MockRequestCountingTransportFactory transportFactory =
        new MockRequestCountingTransportFactory();

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setUniverseDomain(Credentials.GOOGLE_DEFAULT_UNIVERSE)
            .build();

    String universeDomain = credentials.getUniverseDomain();
    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, universeDomain);
    assertEquals(true, credentials.isExplicitUniverseDomain());
    assertEquals(0, transportFactory.transport.getRequestCount());
  }

  @Test
  public void getUniverseDomain_fromMetadata_non404error_throws() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    MockMetadataServerTransport transport = transportFactory.transport;

    ComputeEngineCredentials credentials =
        ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();

    for (int status = 400; status < 600; status++) {
      // 404 should not throw and tested separately
      if (status == 404) {
        continue;
      }
      try {
        transportFactory.transport.setRequestStatusCode(status);
        credentials.getUniverseDomain();
        fail("Should not be able to use credential without exception.");
      } catch (GoogleAuthException ex) {
        assertTrue(ex.isRetryable());
      }
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
    assertTrue("Full ID Token format not provided", p.containsKey("google"));
    ArrayMap<String, ArrayMap> googleClaim = (ArrayMap<String, ArrayMap>) p.get("google");
    assertTrue(googleClaim.containsKey("compute_engine"));
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
    assertTrue("Full ID Token format not provided", p.containsKey("google"));
    ArrayMap<String, ArrayMap> googleClaim = (ArrayMap<String, ArrayMap>) p.get("google");
    assertTrue(googleClaim.containsKey("license"));
  }

  static class MockMetadataServerTransportFactory implements HttpTransportFactory {

    MockMetadataServerTransport transport = new MockMetadataServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }
}
