/*
 * Copyright 2021 Google LLC
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
 *    * Neither the name of Google LLC nor the names of its
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.auth.TestUtils;
import com.google.auth.oauth2.AwsCredentials.AwsCredentialSource;
import com.google.auth.oauth2.ExternalAccountCredentialsTest.MockExternalAccountCredentialsTransportFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link AwsCredentials}. */
@RunWith(JUnit4.class)
public class AwsCredentialsTest {

  private static final String STS_URL = "https://sts.googleapis.com";
  private static final String AWS_CREDENTIALS_URL = "https://169.254.169.254";
  private static final String AWS_CREDENTIALS_URL_WITH_ROLE = "https://169.254.169.254/roleName";
  private static final String AWS_REGION_URL = "https://169.254.169.254/region";
  private static final String AWS_IMDSV2_SESSION_TOKEN_URL = "https://169.254.169.254/imdsv2";
  private static final String AWS_IMDSV2_SESSION_TOKEN = "sessiontoken";

  private static final String GET_CALLER_IDENTITY_URL =
      "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";

  private static final String SERVICE_ACCOUNT_IMPERSONATION_URL =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/testn@test.iam.gserviceaccount.com:generateAccessToken";

  private static final Map<String, Object> AWS_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("environment_id", "aws1");
          put("region_url", AWS_REGION_URL);
          put("url", AWS_CREDENTIALS_URL);
          put("regional_cred_verification_url", "regionalCredVerificationUrl");
        }
      };

  private static final Map<String, Object> EMPTY_METADATA_HEADERS = Collections.emptyMap();
  private static final Map<String, String> EMPTY_STRING_HEADERS = Collections.emptyMap();

  private static final AwsCredentialSource AWS_CREDENTIAL_SOURCE =
      new AwsCredentialSource(AWS_CREDENTIAL_SOURCE_MAP);

  private static final AwsCredentials AWS_CREDENTIAL =
      (AwsCredentials)
          AwsCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl(STS_URL)
              .setTokenInfoUrl("tokenInfoUrl")
              .setCredentialSource(AWS_CREDENTIAL_SOURCE)
              .build();

  @Test
  public void test_awsCredentialSource_ipv6() {
    // If no exception is thrown, it means the urls were valid.
    new AwsCredentialSource(buildAwsIpv6CredentialSourceMap());
  }

  @Test
  public void test_awsCredentialSource_invalid_urls() {
    String keys[] = {"region_url", "url", "imdsv2_session_token_url"};
    for (String key : keys) {
      Map<String, Object> credentialSourceWithInvalidUrl = buildAwsIpv6CredentialSourceMap();
      credentialSourceWithInvalidUrl.put(key, "https://badhost.com/fake");
      IllegalArgumentException e =
          assertThrows(
              IllegalArgumentException.class,
              new ThrowingRunnable() {
                @Override
                public void run() throws Throwable {
                  new AwsCredentialSource(credentialSourceWithInvalidUrl);
                }
              });

      assertEquals(String.format("Invalid host badhost.com for %s.", key), e.getMessage());
    }
  }

  @Test
  public void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    AccessToken accessToken = awsCredential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    AccessToken accessToken = awsCredential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonationOptions() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .setServiceAccountImpersonationOptions(
                    ExternalAccountCredentialsTest.buildServiceAccountImpersonationOptions(2800))
                .build();

    AccessToken accessToken = awsCredential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate that default lifetime was set correctly on the request.
    GenericJson query =
        OAuth2Utils.JSON_FACTORY
            .createJsonParser(transportFactory.transport.getLastRequest().getContentAsString())
            .parseAndClose(GenericJson.class);

    assertEquals("2800s", query.get("lifetime"));
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

    String subjectToken = URLDecoder.decode(awsCredential.retrieveSubjectToken(), "UTF-8");

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(subjectToken);
    GenericJson json = parser.parseAndClose(GenericJson.class);

    List<Map<String, String>> headersList = (List<Map<String, String>>) json.get("headers");
    Map<String, String> headers = new HashMap<>();
    for (Map<String, String> header : headersList) {
      headers.put(header.get("key"), header.get("value"));
    }

    assertEquals("POST", json.get("method"));
    assertEquals(GET_CALLER_IDENTITY_URL, json.get("url"));
    assertEquals(URI.create(GET_CALLER_IDENTITY_URL).getHost(), headers.get("host"));
    assertEquals("token", headers.get("x-amz-security-token"));
    assertEquals(awsCredential.getAudience(), headers.get("x-goog-cloud-target-resource"));
    assertTrue(headers.containsKey("x-amz-date"));
    assertNotNull(headers.get("Authorization"));

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(3, requests.size());

    // Validate region request.
    ValidateRequest(requests.get(0), AWS_REGION_URL, EMPTY_STRING_HEADERS);

    // Validate role request.
    ValidateRequest(requests.get(1), AWS_CREDENTIALS_URL, EMPTY_STRING_HEADERS);

    // Validate security credentials request.
    ValidateRequest(requests.get(2), AWS_CREDENTIALS_URL_WITH_ROLE, EMPTY_STRING_HEADERS);
  }

  @Test
  public void retrieveSubjectTokenWithSessionTokenUrl() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("environment_id", "aws1");
    credentialSourceMap.put("region_url", transportFactory.transport.getAwsRegionUrl());
    credentialSourceMap.put("url", transportFactory.transport.getAwsCredentialsUrl());
    credentialSourceMap.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);
    credentialSourceMap.put(
        "imdsv2_session_token_url", transportFactory.transport.getAwsImdsv2SessionTokenUrl());

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(new AwsCredentialSource(credentialSourceMap))
                .build();

    String subjectToken = URLDecoder.decode(awsCredential.retrieveSubjectToken(), "UTF-8");

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(subjectToken);
    GenericJson json = parser.parseAndClose(GenericJson.class);

    List<Map<String, String>> headersList = (List<Map<String, String>>) json.get("headers");
    Map<String, String> headers = new HashMap<>();
    for (Map<String, String> header : headersList) {
      headers.put(header.get("key"), header.get("value"));
    }

    assertEquals("POST", json.get("method"));
    assertEquals(GET_CALLER_IDENTITY_URL, json.get("url"));
    assertEquals(URI.create(GET_CALLER_IDENTITY_URL).getHost(), headers.get("host"));
    assertEquals("token", headers.get("x-amz-security-token"));
    assertEquals(awsCredential.getAudience(), headers.get("x-goog-cloud-target-resource"));
    assertTrue(headers.containsKey("x-amz-date"));
    assertNotNull(headers.get("Authorization"));

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(4, requests.size());

    // Validate the session token request
    ValidateRequest(
        requests.get(0),
        AWS_IMDSV2_SESSION_TOKEN_URL,
        new HashMap<String, String>() {
          {
            put(
                AwsCredentials.AWS_IMDSV2_SESSION_TOKEN_TTL_HEADER,
                AwsCredentials.AWS_IMDSV2_SESSION_TOKEN_TTL);
          }
        });

    Map<String, String> sessionTokenHeader =
        new HashMap<String, String>() {
          {
            put(AwsCredentials.AWS_IMDSV2_SESSION_TOKEN_HEADER, AWS_IMDSV2_SESSION_TOKEN);
          }
        };

    // Validate region request.
    ValidateRequest(requests.get(1), AWS_REGION_URL, sessionTokenHeader);

    // Validate role request.
    ValidateRequest(requests.get(2), AWS_CREDENTIALS_URL, sessionTokenHeader);

    // Validate security credentials request.
    ValidateRequest(requests.get(3), AWS_CREDENTIALS_URL_WITH_ROLE, sessionTokenHeader);
  }

  @Test
  public void retrieveSubjectToken_noRegion_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    try {
      awsCredential.retrieveSubjectToken();
      fail("Should not be able to use credential without exception.");
    } catch (IOException exception) {
      assertEquals("Failed to retrieve AWS region.", exception.getMessage());
    }

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(1, requests.size());

    // Validate region request.
    ValidateRequest(requests.get(0), AWS_REGION_URL, EMPTY_STRING_HEADERS);
  }

  @Test
  public void retrieveSubjectToken_noRole_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);
    transportFactory.transport.addResponseSequence(true, false);

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    try {
      awsCredential.retrieveSubjectToken();
      fail("Should not be able to use credential without exception.");
    } catch (IOException exception) {
      assertEquals("Failed to retrieve AWS IAM role.", exception.getMessage());
    }

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(2, requests.size());

    // Validate region request.
    ValidateRequest(requests.get(0), AWS_REGION_URL, EMPTY_STRING_HEADERS);

    // Validate role request.
    ValidateRequest(requests.get(1), AWS_CREDENTIALS_URL, EMPTY_STRING_HEADERS);
  }

  @Test
  public void retrieveSubjectToken_noCredentials_expectThrows() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);
    transportFactory.transport.addResponseSequence(true, true, false);

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    try {
      awsCredential.retrieveSubjectToken();
      fail("Should not be able to use credential without exception.");
    } catch (IOException exception) {
      assertEquals("Failed to retrieve AWS credentials.", exception.getMessage());
    }

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(3, requests.size());

    // Validate region request.
    ValidateRequest(requests.get(0), AWS_REGION_URL, EMPTY_STRING_HEADERS);

    // Validate role request.
    ValidateRequest(requests.get(1), AWS_CREDENTIALS_URL, EMPTY_STRING_HEADERS);

    // Validate security credentials request.
    ValidateRequest(requests.get(2), AWS_CREDENTIALS_URL_WITH_ROLE, EMPTY_STRING_HEADERS);
  }

  @Test
  public void retrieveSubjectToken_noRegionUrlProvided() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    Map<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("environment_id", "aws1");
    credentialSource.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(new AwsCredentialSource(credentialSource))
                .build();

    try {
      awsCredential.retrieveSubjectToken();
      fail("Should not be able to use credential without exception.");
    } catch (IOException exception) {
      assertEquals(
          "Unable to determine the AWS region. The credential source does not "
              + "contain the region URL.",
          exception.getMessage());
    }

    // No requests because the credential source does not contain region URL.
    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertTrue(requests.isEmpty());
  }

  @Test
  public void getAwsSecurityCredentials_fromEnvironmentVariablesNoToken() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider
        .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId")
        .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");

    AwsCredentials testAwsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setEnvironmentProvider(environmentProvider)
                .build();

    AwsSecurityCredentials credentials =
        testAwsCredentials.getAwsSecurityCredentials(EMPTY_METADATA_HEADERS);

    assertEquals("awsAccessKeyId", credentials.getAccessKeyId());
    assertEquals("awsSecretAccessKey", credentials.getSecretAccessKey());
    assertNull(credentials.getToken());
  }

  @Test
  public void getAwsSecurityCredentials_fromEnvironmentVariablesWithToken() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider
        .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId")
        .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey")
        .setEnv("AWS_SESSION_TOKEN", "awsSessionToken");

    AwsCredentialSource credSource = new AwsCredentialSource(
      new HashMap<String, Object>() {
        {
          put("environment_id", "aws1");
          put("region_url", "");
          put("url", "");
          put("regional_cred_verification_url", "regionalCredVerificationUrl");
        }
      }
    );

    AwsCredentials testAwsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setEnvironmentProvider(environmentProvider)
                .setCredentialSource(credSource)
                .build();

    AwsSecurityCredentials credentials =
        testAwsCredentials.getAwsSecurityCredentials(EMPTY_METADATA_HEADERS);

    assertEquals("awsAccessKeyId", credentials.getAccessKeyId());
    assertEquals("awsSecretAccessKey", credentials.getSecretAccessKey());
    assertEquals("awsSessionToken", credentials.getToken());
  }

  @Test
  public void getAwsSecurityCredentials_fromEnvironmentVariables_noMetadataServerCall() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider
        .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId")
        .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey")
        .setEnv("AWS_SESSION_TOKEN", "awsSessionToken");

    AwsCredentials testAwsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setEnvironmentProvider(environmentProvider)
                .build();

    AwsSecurityCredentials credentials =
        testAwsCredentials.getAwsSecurityCredentials(EMPTY_METADATA_HEADERS);

    assertEquals("awsAccessKeyId", credentials.getAccessKeyId());
    assertEquals("awsSecretAccessKey", credentials.getSecretAccessKey());
    assertEquals("awsSessionToken", credentials.getToken());
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

    AwsSecurityCredentials credentials =
        awsCredential.getAwsSecurityCredentials(EMPTY_METADATA_HEADERS);

    assertEquals("accessKeyId", credentials.getAccessKeyId());
    assertEquals("secretAccessKey", credentials.getSecretAccessKey());
    assertEquals("token", credentials.getToken());

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(2, requests.size());

    // Validate role request.
    ValidateRequest(requests.get(0), AWS_CREDENTIALS_URL, EMPTY_STRING_HEADERS);

    // Validate security credentials request.
    ValidateRequest(requests.get(1), AWS_CREDENTIALS_URL_WITH_ROLE, EMPTY_STRING_HEADERS);
  }

  @Test
  public void getAwsSecurityCredentials_fromMetadataServer_noUrlProvided() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    Map<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("environment_id", "aws1");
    credentialSource.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(new AwsCredentialSource(credentialSource))
                .build();

    try {
      awsCredential.getAwsSecurityCredentials(EMPTY_METADATA_HEADERS);
      fail("Should not be able to use credential without exception.");
    } catch (IOException exception) {
      assertEquals(
          "Unable to determine the AWS IAM role name. The credential source does not contain the url field.",
          exception.getMessage());
    }

    // No requests because url field is not present in credential source.
    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertTrue(requests.isEmpty());
  }

  @Test
  public void getAwsRegion_awsRegionEnvironmentVariable() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("AWS_REGION", "region");
    environmentProvider.setEnv("AWS_DEFAULT_REGION", "defaultRegion");

    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    AwsCredentials awsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .setEnvironmentProvider(environmentProvider)
                .build();

    String region = awsCredentials.getAwsRegion(EMPTY_METADATA_HEADERS);

    // Should attempt to retrieve the region from AWS_REGION env var first.
    // Metadata server would return us-east-1b.
    assertEquals("region", region);

    // No requests because region is obtained from environment variables.
    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertTrue(requests.isEmpty());
  }

  @Test
  public void getAwsRegion_awsDefaultRegionEnvironmentVariable() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("AWS_DEFAULT_REGION", "defaultRegion");

    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    AwsCredentials awsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .setEnvironmentProvider(environmentProvider)
                .build();

    String region = awsCredentials.getAwsRegion(EMPTY_METADATA_HEADERS);

    // Should attempt to retrieve the region from DEFAULT_AWS_REGION before calling the metadata
    // server. Metadata server would return us-east-1b.
    assertEquals("defaultRegion", region);

    // No requests because region is obtained from environment variables.
    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertTrue(requests.isEmpty());
  }

  @Test
  public void getAwsRegion_metadataServer() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    AwsCredentials awsCredentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(buildAwsCredentialSource(transportFactory))
                .build();

    String region = awsCredentials.getAwsRegion(EMPTY_METADATA_HEADERS);

    // Should retrieve the region from the Metadata server.
    String expectedRegion =
        transportFactory
            .transport
            .getAwsRegion()
            .substring(0, transportFactory.transport.getAwsRegion().length() - 1);
    assertEquals(expectedRegion, region);

    List<MockLowLevelHttpRequest> requests = transportFactory.transport.getRequests();
    assertEquals(1, requests.size());

    // Validate region request.
    ValidateRequest(requests.get(0), AWS_REGION_URL, EMPTY_STRING_HEADERS);
  }

  @Test
  public void createdScoped_clonedCredentialWithAddedScopes() {
    AwsCredentials credentials =
        (AwsCredentials)
            AwsCredentials.newBuilder(AWS_CREDENTIAL)
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    AwsCredentials newCredentials = (AwsCredentials) credentials.createScoped(newScopes);

    assertEquals(credentials.getAudience(), newCredentials.getAudience());
    assertEquals(credentials.getSubjectTokenType(), newCredentials.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), newCredentials.getTokenUrl());
    assertEquals(credentials.getTokenInfoUrl(), newCredentials.getTokenInfoUrl());
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(),
        newCredentials.getServiceAccountImpersonationUrl());
    assertEquals(credentials.getCredentialSource(), newCredentials.getCredentialSource());
    assertEquals(credentials.getQuotaProjectId(), newCredentials.getQuotaProjectId());
    assertEquals(credentials.getClientId(), newCredentials.getClientId());
    assertEquals(credentials.getClientSecret(), newCredentials.getClientSecret());
    assertEquals(newScopes, newCredentials.getScopes());
  }

  @Test
  public void credentialSource_invalidAwsEnvironmentId() {
    Map<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);
    credentialSource.put("environment_id", "azure1");

    try {
      new AwsCredentialSource(credentialSource);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals("Invalid AWS environment ID.", e.getMessage());
    }
  }

  @Test
  public void credentialSource_invalidAwsEnvironmentVersion() {
    Map<String, Object> credentialSource = new HashMap<>();
    int environmentVersion = 2;
    credentialSource.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);
    credentialSource.put("environment_id", "aws" + environmentVersion);

    try {
      new AwsCredentialSource(credentialSource);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          String.format(
              "AWS version %s is not supported in the current build.", environmentVersion),
          e.getMessage());
    }
  }

  @Test
  public void credentialSource_missingRegionalCredVerificationUrl() {
    try {
      new AwsCredentialSource(new HashMap<String, Object>());
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          "A regional_cred_verification_url representing the GetCallerIdentity action URL must be specified.",
          e.getMessage());
    }
  }

  @Test
  public void builder() {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    AwsCredentials credentials =
        (AwsCredentials)
            AwsCredentials.newBuilder()
                .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                .setAudience("audience")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setTokenInfoUrl("tokenInfoUrl")
                .setCredentialSource(AWS_CREDENTIAL_SOURCE)
                .setTokenInfoUrl("tokenInfoUrl")
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .setScopes(scopes)
                .build();

    assertEquals("audience", credentials.getAudience());
    assertEquals("subjectTokenType", credentials.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), STS_URL);
    assertEquals(credentials.getTokenInfoUrl(), "tokenInfoUrl");
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(), SERVICE_ACCOUNT_IMPERSONATION_URL);
    assertEquals(credentials.getCredentialSource(), AWS_CREDENTIAL_SOURCE);
    assertEquals(credentials.getQuotaProjectId(), "quotaProjectId");
    assertEquals(credentials.getClientId(), "clientId");
    assertEquals(credentials.getClientSecret(), "clientSecret");
    assertEquals(credentials.getScopes(), scopes);
    assertEquals(credentials.getEnvironmentProvider(), SystemEnvironmentProvider.getInstance());
  }

  private static void ValidateRequest(
      MockLowLevelHttpRequest request, String expectedUrl, Map<String, String> expectedHeaders) {
    assertEquals(expectedUrl, request.getUrl());
    Map<String, List<String>> actualHeaders = request.getHeaders();

    for (Map.Entry<String, String> expectedHeader : expectedHeaders.entrySet()) {
      assertTrue(actualHeaders.containsKey(expectedHeader.getKey()));
      List<String> actualValues = actualHeaders.get(expectedHeader.getKey());
      assertEquals(1, actualValues.size());
      assertEquals(expectedHeader.getValue(), actualValues.get(0));
    }
  }

  private static AwsCredentialSource buildAwsCredentialSource(
      MockExternalAccountCredentialsTransportFactory transportFactory) {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("environment_id", "aws1");
    credentialSourceMap.put("region_url", transportFactory.transport.getAwsRegionUrl());
    credentialSourceMap.put("url", transportFactory.transport.getAwsCredentialsUrl());
    credentialSourceMap.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);

    return new AwsCredentialSource(credentialSourceMap);
  }

  private static Map<String, Object> buildAwsIpv6CredentialSourceMap() {
    String regionUrl = "http://[fd00:ec2::254]/region";
    String url = "http://[fd00:ec2::254]";
    String imdsv2SessionTokenUrl = "http://[fd00:ec2::254]/imdsv2";
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("environment_id", "aws1");
    credentialSourceMap.put("region_url", regionUrl);
    credentialSourceMap.put("url", url);
    credentialSourceMap.put("imdsv2_session_token_url", imdsv2SessionTokenUrl);
    credentialSourceMap.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);

    return credentialSourceMap;
  }

  static InputStream writeAwsCredentialsStream(String stsUrl, String regionUrl, String metadataUrl)
      throws IOException {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", stsUrl);
    json.put("token_info_url", "tokenInfoUrl");
    json.put("type", ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE);

    GenericJson credentialSource = new GenericJson();
    credentialSource.put("environment_id", "aws1");
    credentialSource.put("region_url", regionUrl);
    credentialSource.put("url", metadataUrl);
    credentialSource.put("regional_cred_verification_url", GET_CALLER_IDENTITY_URL);
    json.put("credential_source", credentialSource);

    return TestUtils.jsonToInputStream(json);
  }
}
