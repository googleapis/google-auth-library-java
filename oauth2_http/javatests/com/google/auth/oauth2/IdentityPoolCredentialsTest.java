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

import static com.google.auth.TestUtils.getDefaultExpireTime;
import static com.google.auth.oauth2.OAuth2Utils.UTF_8;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.api.client.http.HttpTransport;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link IdentityPoolCredentials}. */
@RunWith(JUnit4.class)
public class IdentityPoolCredentialsTest {

  private static final String AUDIENCE = "audience";
  private static final String SUBJECT_TOKEN_TYPE = "subjectTokenType";
  private static final String TOKEN_URL = "tokenUrl";
  private static final String TOKEN_INFO_URL = "tokenInfoUrl";
  private static final String SERVICE_ACCOUNT_IMPERSONATION_URL = "tokenInfoUrl";
  private static final String QUOTA_PROJECT_ID = "quotaProjectId";
  private static final String CLIENT_ID = "clientId";
  private static final String CLIENT_SECRET = "clientSecret";

  private static final String FILE = "file";
  private static final String URL = "url";
  private static final String HEADERS = "headers";

  private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put(FILE, FILE);
        }
      };

  private static final IdentityPoolCredentialSource FILE_CREDENTIAL_SOURCE =
      new IdentityPoolCredentialSource(FILE_CREDENTIAL_SOURCE_MAP);

  private static final IdentityPoolCredentials FILE_SOURCED_CREDENTIAL =
      (IdentityPoolCredentials)
          IdentityPoolCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience(AUDIENCE)
              .setSubjectTokenType(SUBJECT_TOKEN_TYPE)
              .setTokenUrl(TOKEN_URL)
              .setTokenInfoUrl(TOKEN_INFO_URL)
              .setCredentialSource(FILE_CREDENTIAL_SOURCE)
              .build();

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {

    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void createdScoped_clonedCredentialWithAddedScopes() {
    GoogleCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId(QUOTA_PROJECT_ID)
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials newCredentials =
        (IdentityPoolCredentials) credentials.createScoped(newScopes);

    assertThat(newCredentials.getAudience()).isEqualTo(AUDIENCE);
    assertThat(newCredentials.getSubjectTokenType()).isEqualTo(SUBJECT_TOKEN_TYPE);
    assertThat(newCredentials.getTokenUrl()).isEqualTo(TOKEN_URL);
    assertThat(newCredentials.getTokenInfoUrl()).isEqualTo(TOKEN_INFO_URL);
    assertThat(newCredentials.getServiceAccountImpersonationUrl())
        .isEqualTo(SERVICE_ACCOUNT_IMPERSONATION_URL);
    assertThat(newCredentials.getCredentialSource()).isEqualTo(FILE_CREDENTIAL_SOURCE);
    assertThat(newCredentials.getScopes()).isEqualTo(newScopes);
    assertThat(newCredentials.getQuotaProjectId()).isEqualTo(QUOTA_PROJECT_ID);
    assertThat(newCredentials.getClientId()).isEqualTo(CLIENT_ID);
    assertThat(newCredentials.getClientSecret()).isEqualTo(CLIENT_SECRET);
  }

  @Test
  public void retrieveSubjectToken_fileSourced() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    String credential = "credential";
    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(credential.getBytes(UTF_8)), file.getAbsolutePath());

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put(FILE, file.getAbsolutePath());
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credentials.retrieveSubjectToken();
    assertThat(subjectToken).isEqualTo(credential);
  }

  @Test
  public void retrieveSubjectToken_noFile_throws() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    String path = "badPath";
    credentialSourceMap.put(FILE, path);
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    final IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setCredentialSource(credentialSource)
                .build();

    IOException e =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                credentials.retrieveSubjectToken();
              }
            });

    assertThat(e.getMessage()).isEqualTo(String.format(
        "Invalid credential location. The file at %s does not exist.", path));
  }

  @Test
  public void retrieveSubjectToken_urlSourced() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    String subjectToken = credential.retrieveSubjectToken();
    assertThat(subjectToken).isEqualTo(transportFactory.transport.getSubjectToken());
  }

  @Test
  public void retrieveSubjectToken_urlSourcedCredential_throws() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);

    final IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    IOException e =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                credential.retrieveSubjectToken();
              }
            });

    assertThat(e.getMessage())
        .isEqualTo(
            String.format(
                "Error getting subject token from metadata server: %s", response.getMessage()));
  }

  @Test
  public void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    final IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    AccessToken accessToken = credential.refreshAccessToken();
    assertThat(accessToken.getTokenValue()).isEqualTo(transportFactory.transport.getAccessToken());
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(getDefaultExpireTime());
    final IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    AccessToken accessToken = credential.refreshAccessToken();
    assertThat(accessToken.getTokenValue()).isEqualTo(transportFactory.transport.getAccessToken());
  }

  private IdentityPoolCredentialSource buildUrlBasedCredentialSource(String url) {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> headers = new HashMap<>();
    headers.put("Metadata-Flavor", "Google");
    credentialSourceMap.put(URL, url);
    credentialSourceMap.put(HEADERS, headers);

    return new IdentityPoolCredentialSource(credentialSourceMap);
  }
}
