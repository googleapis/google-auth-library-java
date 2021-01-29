/*
 * Copyright 2020, Google LLC
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountCredentialsTest.TestExternalAccountCredentials.TestCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ExternalAccountCredentials}. */
@RunWith(JUnit4.class)
public class ExternalAccountCredentialsTest {

  private static final String STS_URL = "https://www.sts.google.com";

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {

    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  private MockExternalAccountCredentialsTransportFactory transportFactory;

  @Before
  public void setup() {
    transportFactory = new MockExternalAccountCredentialsTransportFactory();
  }

  @Test
  public void fromStream_identityPoolCredentials() throws IOException {
    GenericJson json = buildJsonIdentityPoolCredential();
    TestUtils.jsonToInputStream(json);

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof IdentityPoolCredentials);
  }

  @Test
  public void fromStream_awsCredentials() throws IOException {
    GenericJson json = buildJsonAwsCredential();
    TestUtils.jsonToInputStream(json);

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof AwsCredentials);
  }

  @Test
  public void fromStream_nullTransport_throws() {
    assertThrows(
        NullPointerException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            ExternalAccountCredentials.fromStream(
                new ByteArrayInputStream("foo".getBytes()), /* transportFactory= */ null);
          }
        });
  }

  @Test
  public void fromStream_nullStream_throws() {
    assertThrows(
        NullPointerException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            ExternalAccountCredentials.fromStream(
                /* credentialsStream= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
          }
        });
  }

  @Test
  public void fromJson_identityPoolCredentials() {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof IdentityPoolCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  public void fromJson_awsCredentials() {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonAwsCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof AwsCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  public void fromJson_nullJson_throws() {
    assertThrows(
        NullPointerException.class,
        new ThrowingRunnable() {
          @Override
          public void run() {
            ExternalAccountCredentials.fromJson(
                /* json= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
          }
        });
  }

  @Test
  public void fromJson_invalidServiceAccountImpersonationUrl_throws() {
    final GenericJson json = buildJsonIdentityPoolCredential();
    json.put("service_account_impersonation_url", "invalid_url");

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            new ThrowingRunnable() {
              @Override
              public void run() {
                ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
              }
            });
    assertEquals(
        "Unable to determine target principal from service account impersonation URL.",
        e.getMessage());
  }

  @Test
  public void fromJson_nullTransport_throws() {
    assertThrows(
        NullPointerException.class,
        new ThrowingRunnable() {
          @Override
          public void run() {
            ExternalAccountCredentials.fromJson(
                new HashMap<String, Object>(), /* transportFactory= */ null);
          }
        });
  }

  @Test
  public void exchange3PICredentialForAccessToken() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken accessToken =
        credential.exchange3PICredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());
  }

  @Test
  public void exchange3PICredentialForAccessToken_withServiceAccountImpersonation()
      throws IOException {
    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(
            IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
                transportFactory.transport.getStsUrl(),
                transportFactory.transport.getMetadataUrl(),
                transportFactory.transport.getServiceAccountImpersonationUrl()),
            transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken returnedToken =
        credential.exchange3PICredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), returnedToken.getTokenValue());
  }

  @Test
  public void exchange3PICredentialForAccessToken_throws() throws IOException {
    final ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    String errorCode = "invalidRequest";
    String errorDescription = "errorDescription";
    String errorUri = "errorUri";
    transportFactory.transport.addResponseErrorSequence(
        TestUtils.buildHttpResponseException(errorCode, errorDescription, errorUri));

    final StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    OAuthException e =
        assertThrows(
            OAuthException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                credential.exchange3PICredentialForAccessToken(stsTokenExchangeRequest);
              }
            });

    assertEquals(errorCode, e.getErrorCode());
    assertEquals(errorDescription, e.getErrorDescription());
    assertEquals(errorUri, e.getErrorUri());
  }

  @Test
  public void getRequestMetadata_withQuotaProjectId() throws IOException {
    TestExternalAccountCredentials testCredentials =
        new TestExternalAccountCredentials(
            transportFactory,
            "audience",
            "subjectTokenType",
            "tokenUrl",
            "tokenInfoUrl",
            new TestCredentialSource(new HashMap<String, Object>()),
            /* serviceAccountImpersonationUrl= */ null,
            "quotaProjectId",
            /* clientId= */ null,
            /* clientSecret= */ null,
            /* scopes= */ null);

    Map<String, List<String>> requestMetadata =
        testCredentials.getRequestMetadata(URI.create("http://googleapis.com/foo/bar"));

    assertEquals("quotaProjectId", requestMetadata.get("x-goog-user-project").get(0));
  }

  private GenericJson buildJsonIdentityPoolCredential() {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", STS_URL);
    json.put("token_info_url", "tokenInfoUrl");

    Map<String, String> map = new HashMap<>();
    map.put("file", "file");
    json.put("credential_source", map);
    return json;
  }

  private GenericJson buildJsonAwsCredential() {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", STS_URL);
    json.put("token_info_url", "tokenInfoUrl");

    Map<String, String> map = new HashMap<>();
    map.put("environment_id", "aws1");
    map.put("region_url", "regionUrl");
    map.put("url", "url");
    map.put("regional_cred_verification_url", "regionalCredVerificationUrl");
    json.put("credential_source", map);

    return json;
  }

  static class TestExternalAccountCredentials extends ExternalAccountCredentials {
    static class TestCredentialSource extends ExternalAccountCredentials.CredentialSource {
      protected TestCredentialSource(Map<String, Object> credentialSourceMap) {
        super(credentialSourceMap);
      }
    }

    protected TestExternalAccountCredentials(
        HttpTransportFactory transportFactory,
        String audience,
        String subjectTokenType,
        String tokenUrl,
        String tokenInfoUrl,
        CredentialSource credentialSource,
        @Nullable String serviceAccountImpersonationUrl,
        @Nullable String quotaProjectId,
        @Nullable String clientId,
        @Nullable String clientSecret,
        @Nullable Collection<String> scopes) {
      super(
          transportFactory,
          audience,
          subjectTokenType,
          tokenUrl,
          credentialSource,
          tokenInfoUrl,
          serviceAccountImpersonationUrl,
          quotaProjectId,
          clientId,
          clientSecret,
          scopes);
    }

    @Override
    public AccessToken refreshAccessToken() {
      return new AccessToken("accessToken", new Date());
    }

    @Override
    public String retrieveSubjectToken() {
      return "subjectToken";
    }
  }
}
