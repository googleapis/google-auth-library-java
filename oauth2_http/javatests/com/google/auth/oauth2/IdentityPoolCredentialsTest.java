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
import static com.google.auth.oauth2.OAuth2Utils.JSON_FACTORY;
import static com.google.auth.oauth2.OAuth2Utils.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
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

  private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("file", "file");
        }
      };

  private static final IdentityPoolCredentialSource FILE_CREDENTIAL_SOURCE =
      new IdentityPoolCredentialSource(FILE_CREDENTIAL_SOURCE_MAP);

  private static final IdentityPoolCredentials FILE_SOURCED_CREDENTIAL =
      (IdentityPoolCredentials)
          IdentityPoolCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl("tokenUrl")
              .setTokenInfoUrl("tokenInfoUrl")
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
            .setServiceAccountImpersonationUrl("serviceAccountImpersonationUrl")
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials newCredentials =
        (IdentityPoolCredentials) credentials.createScoped(newScopes);

    assertEquals("audience", newCredentials.getAudience());
    assertEquals("subjectTokenType", newCredentials.getSubjectTokenType());
    assertEquals("tokenUrl", newCredentials.getTokenUrl());
    assertEquals("tokenInfoUrl", newCredentials.getTokenInfoUrl());
    assertEquals(
        "serviceAccountImpersonationUrl", newCredentials.getServiceAccountImpersonationUrl());
    assertEquals(FILE_CREDENTIAL_SOURCE, newCredentials.getCredentialSource());
    assertEquals(newScopes, newCredentials.getScopes());
    assertEquals("quotaProjectId", newCredentials.getQuotaProjectId());
    assertEquals("clientId", newCredentials.getClientId());
    assertEquals("clientSecret", newCredentials.getClientSecret());
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
    credentialSourceMap.put("file", file.getAbsolutePath());
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credentials.retrieveSubjectToken();

    assertEquals(credential, subjectToken);
  }

  @Test
  public void retrieveSubjectToken_fileSourcedWithJsonFormat() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setMetadataServerContentType("json");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", "json");
    formatMap.put("subject_token_field_name", "subjectToken");

    credentialSourceMap.put("file", file.getAbsolutePath());
    credentialSourceMap.put("format", formatMap);

    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    GenericJson response = new GenericJson();
    response.setFactory(JSON_FACTORY);
    response.put("subjectToken", "subjectToken");

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(response.toString().getBytes(UTF_8)), file.getAbsolutePath());

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals("subjectToken", subjectToken);
  }

  @Test
  public void retrieveSubjectToken_noFile_throws() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    String path = "badPath";
    credentialSourceMap.put("file", path);
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

    assertEquals(
        String.format("Invalid credential location. The file at %s does not exist.", path),
        e.getMessage());
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

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
  }

  @Test
  public void retrieveSubjectToken_urlSourcedWithJsonFormat() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setMetadataServerContentType("json");

    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", "json");
    formatMap.put("subject_token_field_name", "subjectToken");

    IdentityPoolCredentialSource credentialSource =
        buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl(), formatMap);

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
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

    assertEquals(
        String.format(
            "Error getting subject token from metadata server: %s", response.getMessage()),
        e.getMessage());
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

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());
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

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());
  }

  @Test
  public void identityPoolCredentialSource_invalidSourceType() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            new ThrowingRunnable() {
              @Override
              public void run() {
                new IdentityPoolCredentialSource(new HashMap<String, Object>());
              }
            });

    assertEquals(
        "Missing credential source file location or URL. At least one must be specified.",
        e.getMessage());
  }

  @Test
  public void identityPoolCredentialSource_invalidFormatType() {
    final Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "unsupportedType");
    credentialSourceMap.put("format", format);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            new ThrowingRunnable() {
              @Override
              public void run() {
                new IdentityPoolCredentialSource(credentialSourceMap);
              }
            });

    assertEquals("Invalid credential source format type: unsupportedType.", e.getMessage());
  }

  @Test
  public void identityPoolCredentialSource_nullFormatType() {
    final Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", null);
    credentialSourceMap.put("format", format);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            new ThrowingRunnable() {
              @Override
              public void run() {
                new IdentityPoolCredentialSource(credentialSourceMap);
              }
            });

    assertEquals("Invalid credential source format type: null.", e.getMessage());
  }

  @Test
  public void identityPoolCredentialSource_subjectTokenFieldNameUnset() {
    final Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "json");
    credentialSourceMap.put("format", format);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            new ThrowingRunnable() {
              @Override
              public void run() {
                new IdentityPoolCredentialSource(credentialSourceMap);
              }
            });

    assertEquals(
        "When specifying a JSON credential type, the subject_token_field_name must be set.",
        e.getMessage());
  }

  static InputStream writeIdentityPoolCredentialsStream(String tokenUrl, String url)
      throws IOException {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", tokenUrl);
    json.put("token_info_url", "tokenInfoUrl");
    json.put("type", ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE);

    GenericJson credentialSource = new GenericJson();
    GenericJson headers = new GenericJson();
    headers.put("Metadata-Flavor", "Google");
    credentialSource.put("url", url);
    credentialSource.put("headers", headers);

    json.put("credential_source", credentialSource);
    return TestUtils.jsonToInputStream(json);
  }

  private static IdentityPoolCredentialSource buildUrlBasedCredentialSource(String url) {
    return buildUrlBasedCredentialSource(url, /* formatMap= */ null);
  }

  private static IdentityPoolCredentialSource buildUrlBasedCredentialSource(
      String url, Map<String, String> formatMap) {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> headers = new HashMap<>();
    headers.put("Metadata-Flavor", "Google");
    credentialSourceMap.put("url", url);
    credentialSourceMap.put("headers", headers);
    credentialSourceMap.put("format", formatMap);

    return new IdentityPoolCredentialSource(credentialSourceMap);
  }
}
