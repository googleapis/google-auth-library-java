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
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AwsCredentials.AwsCredentialSource;
import com.google.auth.oauth2.ExternalAccountCredentialsTest.MockExternalAccountCredentialsTransportFactory;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link AwsCredentials}. */
@RunWith(JUnit4.class)
public class AwsCredentialsTest {

  private static final String GET_CALLER_IDENTITY_URL =
      "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";

  private static final Map<String, Object> AWS_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("region_url", "regionUrl");
          put("url", "url");
          put("regional_cred_verification_url", "regionalCredVerificationUrl");
        }
      };

  private static final AwsCredentialSource AWS_CREDENTIAL_SOURCE =
      new AwsCredentialSource(AWS_CREDENTIAL_SOURCE_MAP);

  private static final AwsCredentials AWS_CREDENTIAL =
      (AwsCredentials)
          AwsCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl("tokenUrl")
              .setTokenInfoUrl("tokenInfoUrl")
              .setCredentialSource(AWS_CREDENTIAL_SOURCE)
              .build();

  @Test
  public void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    final AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    AccessToken accessToken = awsCredential.refreshAccessToken();
    assertThat(accessToken.getTokenValue()).isEqualTo(transportFactory.transport.getAccessToken());
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(getDefaultExpireTime());

    final AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    AccessToken accessToken = awsCredential.refreshAccessToken();
    assertThat(accessToken.getTokenValue()).isEqualTo(transportFactory.transport.getAccessToken());
  }

  @Test
  public void retrieveSubjectToken() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    String subjectToken = awsCredential.retrieveSubjectToken();

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(subjectToken);
    GenericJson json = parser.parseAndClose(GenericJson.class);

    Map<String, String> headers = (Map<String, String>) json.get("headers");

    assertThat(json.get("method")).isEqualTo("POST");
    assertThat(json.get("url")).isEqualTo(GET_CALLER_IDENTITY_URL);
    assertThat(headers.get("host")).isEqualTo(URI.create(GET_CALLER_IDENTITY_URL).getHost());
    assertThat(headers.containsKey("x-amz-date")).isTrue();
    assertThat(headers.get("x-amz-security-token")).isEqualTo("token");
    assertThat(headers.get("x-goog-cloud-target-resource")).isEqualTo(awsCredential.getAudience());
    assertThat(headers.get("Authorization")).isNotNull();
  }

  @Test
  public void retrieveSubjectToken_noRegion_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);

    final AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    IOException e =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                awsCredential.retrieveSubjectToken();
              }
            });

    assertThat(e.getMessage()).isEqualTo("Failed to retrieve AWS region.");
  }

  @Test
  public void retrieveSubjectToken_noRole_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);
    transportFactory.transport.addResponseSequence(true, false);

    final AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    IOException e =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                awsCredential.retrieveSubjectToken();
              }
            });

    assertThat(e.getMessage()).isEqualTo("Failed to retrieve AWS IAM role.");
  }

  @Test
  public void retrieveSubjectToken_noCredentials_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);
    transportFactory.transport.addResponseSequence(true, true, false);

    final AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    IOException e =
        assertThrows(
            IOException.class,
            new ThrowingRunnable() {
              @Override
              public void run() throws Throwable {
                awsCredential.retrieveSubjectToken();
              }
            });

    assertThat(e.getMessage()).isEqualTo("Failed to retrieve AWS credentials.");
  }

  @Test
  public void getAwsSecurityCredentials_fromEnvironmentVariablesNoToken() throws IOException {
    TestAwsCredentials testAwsCredentials = TestAwsCredentials.newBuilder(AWS_CREDENTIAL).build();
    testAwsCredentials.setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId");
    testAwsCredentials.setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");

    AwsSecurityCredentials credentials = testAwsCredentials.getAwsSecurityCredentials();

    assertThat(credentials.getAccessKeyId()).isEqualTo("awsAccessKeyId");
    assertThat(credentials.getSecretAccessKey()).isEqualTo("awsSecretAccessKey");
    assertThat(credentials.getToken()).isNull();
  }

  @Test
  public void getAwsSecurityCredentials_fromEnvironmentVariablesWithToken() throws IOException {
    TestAwsCredentials testAwsCredentials = TestAwsCredentials.newBuilder(AWS_CREDENTIAL).build();
    testAwsCredentials.setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId");
    testAwsCredentials.setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");
    testAwsCredentials.setEnv("Token", "token");

    AwsSecurityCredentials credentials = testAwsCredentials.getAwsSecurityCredentials();

    assertThat(credentials.getAccessKeyId()).isEqualTo("awsAccessKeyId");
    assertThat(credentials.getSecretAccessKey()).isEqualTo("awsSecretAccessKey");
    assertThat(credentials.getToken()).isEqualTo("token");
  }

  @Test
  public void getAwsSecurityCredentials_fromMetadataServer() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    AwsSecurityCredentials credentials = awsCredential.getAwsSecurityCredentials();

    assertThat(credentials.getAccessKeyId()).isEqualTo("accessKeyId");
    assertThat(credentials.getSecretAccessKey()).isEqualTo("secretAccessKey");
    assertThat(credentials.getToken()).isEqualTo("token");
  }

  @Test
  public void createdScoped_clonedCredentialWithAddedScopes() {
    AwsCredentials credentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setServiceAccountImpersonationUrl("tokenInfoUrl")
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    AwsCredentials newCredentials = (AwsCredentials) credentials.createScoped(newScopes);

    assertThat(newCredentials.getAudience()).isEqualTo(credentials.getAudience());
    assertThat(newCredentials.getSubjectTokenType()).isEqualTo(credentials.getSubjectTokenType());
    assertThat(newCredentials.getTokenUrl()).isEqualTo(credentials.getTokenUrl());
    assertThat(newCredentials.getTokenInfoUrl()).isEqualTo(credentials.getTokenInfoUrl());
    assertThat(newCredentials.getServiceAccountImpersonationUrl())
        .isEqualTo(credentials.getServiceAccountImpersonationUrl());
    assertThat(newCredentials.getCredentialSource()).isEqualTo(credentials.getCredentialSource());
    assertThat(newCredentials.getQuotaProjectId()).isEqualTo(credentials.getQuotaProjectId());
    assertThat(newCredentials.getClientId()).isEqualTo(credentials.getClientId());
    assertThat(newCredentials.getClientSecret()).isEqualTo(credentials.getClientSecret());
    assertThat(newCredentials.getScopes()).isEqualTo(newScopes);
  }

  private AwsCredentialSource buildAwsCredentialSource(
      MockExternalAccountCredentialsTransportFactory transportFactory) {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("region_url", transportFactory.transport.getAwsRegionEndpoint());
    credentialSourceMap.put("url", transportFactory.transport.getAwsCredentialsEndpoint());
    credentialSourceMap.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);
    return new AwsCredentialSource(credentialSourceMap);
  }

  /** Used to test the retrieval of AWS credentials from environment variables. */
  private static class TestAwsCredentials extends AwsCredentials {

    private final Map<String, String> environmentVariables = new HashMap<>();

    TestAwsCredentials(
        HttpTransportFactory transportFactory,
        String audience,
        String subjectTokenType,
        String tokenUrl,
        String tokenInfoUrl,
        AwsCredentialSource credentialSource,
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
          tokenInfoUrl,
          credentialSource,
          serviceAccountImpersonationUrl,
          quotaProjectId,
          clientId,
          clientSecret,
          scopes);
    }

    public static TestAwsCredentials.Builder newBuilder(AwsCredentials awsCredentials) {
      return new TestAwsCredentials.Builder(awsCredentials);
    }

    public static class Builder extends AwsCredentials.Builder {

      protected Builder(AwsCredentials credentials) {
        super(credentials);
      }

      @Override
      public TestAwsCredentials build() {
        return new TestAwsCredentials(
            transportFactory,
            audience,
            subjectTokenType,
            tokenUrl,
            tokenInfoUrl,
            (AwsCredentialSource) credentialSource,
            serviceAccountImpersonationUrl,
            quotaProjectId,
            clientId,
            clientSecret,
            scopes);
      }
    }

    @Override
    String getEnv(String name) {
      return environmentVariables.get(name);
    }

    void setEnv(String name, String value) {
      environmentVariables.put(name, value);
    }
  }
}
