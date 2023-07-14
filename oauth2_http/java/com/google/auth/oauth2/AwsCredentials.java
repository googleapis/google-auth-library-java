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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpMethods;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * AWS credentials representing a third-party identity for calling Google APIs.
 *
 * <p>By default, attempts to exchange the external credential for a GCP access token.
 */
public class AwsCredentials extends ExternalAccountCredentials {

  // Supported environment variables.
  static final String AWS_REGION = "AWS_REGION";
  static final String AWS_DEFAULT_REGION = "AWS_DEFAULT_REGION";
  static final String AWS_ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID";
  static final String AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY";
  static final String AWS_SESSION_TOKEN = "AWS_SESSION_TOKEN";

  static final String AWS_IMDSV2_SESSION_TOKEN_HEADER = "x-aws-ec2-metadata-token";
  static final String AWS_IMDSV2_SESSION_TOKEN_TTL_HEADER = "x-aws-ec2-metadata-token-ttl-seconds";
  static final String AWS_IMDSV2_SESSION_TOKEN_TTL = "300";
  private static final long serialVersionUID = -3670131891574618105L;

  private final AwsCredentialSource awsCredentialSource;

  /** Internal constructor. See {@link AwsCredentials.Builder}. */
  AwsCredentials(Builder builder) {
    super(builder);
    this.awsCredentialSource = (AwsCredentialSource) builder.externalAccountCredentialSource;
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    StsTokenExchangeRequest.Builder stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(retrieveSubjectToken(), getSubjectTokenType())
            .setAudience(getAudience());

    // Add scopes, if possible.
    Collection<String> scopes = getScopes();
    if (scopes != null && !scopes.isEmpty()) {
      stsTokenExchangeRequest.setScopes(new ArrayList<>(scopes));
    }

    return exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest.build());
  }

  @Override
  public String retrieveSubjectToken() throws IOException {
    Map<String, Object> metadataRequestHeaders = new HashMap<>();
    if (shouldUseMetadataServer()) {
      metadataRequestHeaders = createMetadataRequestHeaders(awsCredentialSource);
    }

    // The targeted region is required to generate the signed request. The regional
    // endpoint must also be used.
    String region = getAwsRegion(metadataRequestHeaders);

    AwsSecurityCredentials credentials = getAwsSecurityCredentials(metadataRequestHeaders);

    // Generate the signed request to the AWS STS GetCallerIdentity API.
    Map<String, String> headers = new HashMap<>();
    headers.put("x-goog-cloud-target-resource", getAudience());

    AwsRequestSigner signer =
        AwsRequestSigner.newBuilder(
                credentials,
                "POST",
                awsCredentialSource.regionalCredentialVerificationUrl.replace("{region}", region),
                region)
            .setAdditionalHeaders(headers)
            .build();

    AwsRequestSignature awsRequestSignature = signer.sign();
    return buildSubjectToken(awsRequestSignature);
  }

  /** Clones the AwsCredentials with the specified scopes. */
  @Override
  public GoogleCredentials createScoped(Collection<String> newScopes) {
    return new AwsCredentials((AwsCredentials.Builder) newBuilder(this).setScopes(newScopes));
  }

  private String retrieveResource(String url, String resourceName, Map<String, Object> headers)
      throws IOException {
    return retrieveResource(url, resourceName, HttpMethods.GET, headers, /* content= */ null);
  }

  private String retrieveResource(
      String url,
      String resourceName,
      String requestMethod,
      Map<String, Object> headers,
      @Nullable HttpContent content)
      throws IOException {
    try {
      HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
      HttpRequest request =
          requestFactory.buildRequest(requestMethod, new GenericUrl(url), content);

      HttpHeaders requestHeaders = request.getHeaders();
      for (Map.Entry<String, Object> header : headers.entrySet()) {
        requestHeaders.set(header.getKey(), header.getValue());
      }

      HttpResponse response = request.execute();
      return response.parseAsString();
    } catch (IOException e) {
      throw new IOException(String.format("Failed to retrieve AWS %s.", resourceName), e);
    }
  }

  private String buildSubjectToken(AwsRequestSignature signature)
      throws UnsupportedEncodingException {
    Map<String, String> canonicalHeaders = signature.getCanonicalHeaders();
    List<GenericJson> headerList = new ArrayList<>();
    for (String headerName : canonicalHeaders.keySet()) {
      headerList.add(formatTokenHeaderForSts(headerName, canonicalHeaders.get(headerName)));
    }

    headerList.add(formatTokenHeaderForSts("Authorization", signature.getAuthorizationHeader()));

    // The canonical resource name of the workload identity pool provider.
    headerList.add(formatTokenHeaderForSts("x-goog-cloud-target-resource", getAudience()));

    GenericJson token = new GenericJson();
    token.setFactory(OAuth2Utils.JSON_FACTORY);

    token.put("headers", headerList);
    token.put("method", signature.getHttpMethod());
    token.put(
        "url",
        awsCredentialSource.regionalCredentialVerificationUrl.replace(
            "{region}", signature.getRegion()));
    return URLEncoder.encode(token.toString(), "UTF-8");
  }

  private boolean canRetrieveRegionFromEnvironment() {
    // The AWS region can be provided through AWS_REGION or AWS_DEFAULT_REGION. Only one is
    // required.
    List<String> keys = ImmutableList.of(AWS_REGION, AWS_DEFAULT_REGION);
    for (String env : keys) {
      String value = getEnvironmentProvider().getEnv(env);
      if (value != null && value.trim().length() > 0) {
        // Region available.
        return true;
      }
    }
    return false;
  }

  private boolean canRetrieveSecurityCredentialsFromEnvironment() {
    // Check if both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are available.
    List<String> keys = ImmutableList.of(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY);
    for (String env : keys) {
      String value = getEnvironmentProvider().getEnv(env);
      if (value == null || value.trim().length() == 0) {
        // Return false if one of them are missing.
        return false;
      }
    }
    return true;
  }

  @VisibleForTesting
  boolean shouldUseMetadataServer() {
    return !canRetrieveRegionFromEnvironment() || !canRetrieveSecurityCredentialsFromEnvironment();
  }

  @VisibleForTesting
  Map<String, Object> createMetadataRequestHeaders(AwsCredentialSource awsCredentialSource)
      throws IOException {
    Map<String, Object> metadataRequestHeaders = new HashMap<>();

    // AWS IDMSv2 introduced a requirement for a session token to be present
    // with the requests made to metadata endpoints. This requirement is to help
    // prevent SSRF attacks.
    // Presence of "imdsv2_session_token_url" in Credential Source of config file
    // will trigger a flow with session token, else there will not be a session
    // token with the metadata requests.
    // Both flows work for IDMS v1 and v2. But if IDMSv2 is enabled, then if
    // session token is not present, Unauthorized exception will be thrown.
    if (awsCredentialSource.imdsv2SessionTokenUrl != null) {
      Map<String, Object> tokenRequestHeaders =
          new HashMap<String, Object>() {
            {
              put(AWS_IMDSV2_SESSION_TOKEN_TTL_HEADER, AWS_IMDSV2_SESSION_TOKEN_TTL);
            }
          };

      String imdsv2SessionToken =
          retrieveResource(
              awsCredentialSource.imdsv2SessionTokenUrl,
              "Session Token",
              HttpMethods.PUT,
              tokenRequestHeaders,
              /* content= */ null);

      metadataRequestHeaders.put(AWS_IMDSV2_SESSION_TOKEN_HEADER, imdsv2SessionToken);
    }

    return metadataRequestHeaders;
  }

  @VisibleForTesting
  String getAwsRegion(Map<String, Object> metadataRequestHeaders) throws IOException {
    String region;
    if (canRetrieveRegionFromEnvironment()) {
      // For AWS Lambda, the region is retrieved through the AWS_REGION environment variable.
      region = getEnvironmentProvider().getEnv(AWS_REGION);
      if (region != null && region.trim().length() > 0) {
        return region;
      }
      return getEnvironmentProvider().getEnv(AWS_DEFAULT_REGION);
    }

    if (awsCredentialSource.regionUrl == null || awsCredentialSource.regionUrl.isEmpty()) {
      throw new IOException(
          "Unable to determine the AWS region. The credential source does not contain the region URL.");
    }

    region = retrieveResource(awsCredentialSource.regionUrl, "region", metadataRequestHeaders);

    // There is an extra appended character that must be removed. If `us-east-1b` is returned,
    // we want `us-east-1`.
    return region.substring(0, region.length() - 1);
  }

  @VisibleForTesting
  AwsSecurityCredentials getAwsSecurityCredentials(Map<String, Object> metadataRequestHeaders)
      throws IOException {
    // Check environment variables for credentials first.
    if (canRetrieveSecurityCredentialsFromEnvironment()) {
      String accessKeyId = getEnvironmentProvider().getEnv(AWS_ACCESS_KEY_ID);
      String secretAccessKey = getEnvironmentProvider().getEnv(AWS_SECRET_ACCESS_KEY);
      String token = getEnvironmentProvider().getEnv(AWS_SESSION_TOKEN);
      return new AwsSecurityCredentials(accessKeyId, secretAccessKey, token);
    }

    // Credentials not retrievable from environment variables - call metadata server.
    // Retrieve the IAM role that is attached to the VM. This is required to retrieve the AWS
    // security credentials.
    if (awsCredentialSource.url == null || awsCredentialSource.url.isEmpty()) {
      throw new IOException(
          "Unable to determine the AWS IAM role name. The credential source does not contain the"
              + " url field.");
    }
    String roleName = retrieveResource(awsCredentialSource.url, "IAM role", metadataRequestHeaders);

    // Retrieve the AWS security credentials by calling the endpoint specified by the credential
    // source.
    String awsCredentials =
        retrieveResource(
            awsCredentialSource.url + "/" + roleName, "credentials", metadataRequestHeaders);

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(awsCredentials);
    GenericJson genericJson = parser.parseAndClose(GenericJson.class);

    String accessKeyId = (String) genericJson.get("AccessKeyId");
    String secretAccessKey = (String) genericJson.get("SecretAccessKey");
    String token = (String) genericJson.get("Token");

    // These credentials last for a few hours - we may consider caching these in the
    // future.
    return new AwsSecurityCredentials(accessKeyId, secretAccessKey, token);
  }

  @VisibleForTesting
  String getEnv(String name) {
    return System.getenv(name);
  }

  private static GenericJson formatTokenHeaderForSts(String key, String value) {
    // The GCP STS endpoint expects the headers to be formatted as:
    // [
    //  {key: 'x-amz-date', value: '...'},
    //  {key: 'Authorization', value: '...'},
    //  ...
    // ]
    GenericJson header = new GenericJson();
    header.setFactory(OAuth2Utils.JSON_FACTORY);
    header.put("key", key);
    header.put("value", value);
    return header;
  }

  public static AwsCredentials.Builder newBuilder() {
    return new AwsCredentials.Builder();
  }

  public static AwsCredentials.Builder newBuilder(AwsCredentials awsCredentials) {
    return new AwsCredentials.Builder(awsCredentials);
  }

  public static class Builder extends ExternalAccountCredentials.Builder {

    Builder() {}

    Builder(AwsCredentials credentials) {
      super(credentials);
    }

    @Override
    public AwsCredentials build() {
      return new AwsCredentials(this);
    }
  }
}
