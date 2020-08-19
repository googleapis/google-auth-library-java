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

import static com.google.auth.TestUtils.buildHttpResponseException;
import static com.google.auth.TestUtils.getDefaultExpireTime;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.util.GenericData;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ExternalAccountCredentials}. */
@RunWith(JUnit4.class)
public class ExternalAccountCredentialsTest {

  private static final String FILE = "file";
  private static final String AUDIENCE = "audience";
  private static final String SUBJECT_TOKEN_TYPE = "subjectTokenType";
  private static final String TOKEN_INFO_URL = "tokenInfoUrl";
  private static final String STS_URL = "https://www.sts.google.com";
  private static final String CREDENTIAL = "credential";
  private static final String ACCESS_TOKEN = "eya23tfgdfga2123as";
  private static final String CONTENT_TYPE_KEY = "content-type";
  private static final String CONTENT_TYPE = "application/x-www-form-urlencoded";
  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {
    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
        new HashMap<String, Object>() {
          {
            put(FILE, FILE);
          }
        };

    private static final IdentityPoolCredentialSource FILE_CREDENTIAL_SOURCE =
        new IdentityPoolCredentialSource(FILE_CREDENTIAL_SOURCE_MAP);

    private static final IdentityPoolCredentials EXTERNAL_ACCOUNT_CREDENTIALS =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder()
                .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                .setAudience(AUDIENCE)
                .setSubjectTokenType(SUBJECT_TOKEN_TYPE)
                .setTokenUrl(STS_URL)
                .setTokenInfoUrl(TOKEN_INFO_URL)
                .setCredentialSource(FILE_CREDENTIAL_SOURCE)
                .build();

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
    GenericJson json = buildDefaultIdentityPoolCredential();
    TestUtils.jsonToInputStream(json);

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertThat(credential).isInstanceOf(IdentityPoolCredentials.class);
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
            buildDefaultIdentityPoolCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);
    assertThat(credential).isInstanceOf(IdentityPoolCredentials.class);

    assertThat(credential.getAudience()).isEqualTo(AUDIENCE);
    assertThat(credential.getSubjectTokenType()).isEqualTo(SUBJECT_TOKEN_TYPE);
    assertThat(credential.getTokenUrl()).isEqualTo(STS_URL);
    assertThat(credential.getTokenInfoUrl()).isEqualTo(TOKEN_INFO_URL);
    assertThat(credential.getCredentialSource()).isNotNull();
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
        ExternalAccountCredentials.fromJson(buildDefaultIdentityPoolCredential(), transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE).build();

    AccessToken accessToken =
        credential.exchange3PICredentialForAccessToken(stsTokenExchangeRequest);

    assertThat(accessToken.getTokenValue()).isEqualTo(transportFactory.transport.getAccessToken());

    Map<String, List<String>> headers = transportFactory.transport.getRequest().getHeaders();

    assertThat(headers.containsKey(CONTENT_TYPE_KEY)).isTrue();
    assertThat(headers.get(CONTENT_TYPE_KEY).get(0)).isEqualTo(CONTENT_TYPE);
  }

  @Test
  public void exchange3PICredentialForAccessToken_throws() throws IOException {
    final ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildDefaultIdentityPoolCredential(), transportFactory);

    String errorCode = "invalidRequest";
    String errorDescription = "errorDescription";
    String errorUri = "errorUri";
    transportFactory.transport.addResponseErrorSequence(
        buildHttpResponseException(errorCode, errorDescription, errorUri));

    final StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(CREDENTIAL, SUBJECT_TOKEN_TYPE).build();

    OAuthException e =
        assertThrows(
            OAuthException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                credential.exchange3PICredentialForAccessToken(stsTokenExchangeRequest);
              }
            });

    assertThat(e.getErrorCode()).isEqualTo(errorCode);
    assertThat(e.getErrorDescription()).isEqualTo(errorDescription);
    assertThat(e.getErrorUri()).isEqualTo(errorUri);
  }

  @Test
  public void attemptServiceAccountImpersonation() throws IOException {
    GenericJson defaultCredential = buildDefaultIdentityPoolCredential();
    defaultCredential.put(
        "service_account_impersonation_url",
        transportFactory.transport.getServiceAccountImpersonationUrl());

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(defaultCredential, transportFactory);

    transportFactory.transport.setExpireTime(getDefaultExpireTime());
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, new Date());

    AccessToken returnedToken = credential.attemptServiceAccountImpersonation(accessToken);

    assertThat(returnedToken.getTokenValue())
        .isEqualTo(transportFactory.transport.getAccessToken());
    assertThat(returnedToken.getTokenValue()).isNotEqualTo(accessToken.getTokenValue());

    // Validate request content.
    MockLowLevelHttpRequest request = transportFactory.transport.getRequest();
    Map<String, String> actualRequestContent = TestUtils.parseQuery(request.getContentAsString());

    GenericData expectedRequestContent = new GenericData().set("scope", CLOUD_PLATFORM_SCOPE);
    assertThat(actualRequestContent).isEqualTo(expectedRequestContent);
  }

  @Test
  public void attemptServiceAccountImpersonation_noUrl() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildDefaultIdentityPoolCredential(), transportFactory);

    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, new Date());
    AccessToken returnedToken = credential.attemptServiceAccountImpersonation(accessToken);

    assertThat(returnedToken).isEqualTo(accessToken);
  }

  private GenericJson buildDefaultIdentityPoolCredential() {
    GenericJson json = new GenericJson();
    json.put("audience", AUDIENCE);
    json.put("subject_token_type", SUBJECT_TOKEN_TYPE);
    json.put("token_url", STS_URL);
    json.put("token_info_url", TOKEN_INFO_URL);

    Map<String, String> map = new HashMap<>();
    map.put("file", "file");
    json.put("credential_source", map);
    return json;
  }
}
