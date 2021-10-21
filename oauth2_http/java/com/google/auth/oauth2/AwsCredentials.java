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
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AWS credentials representing a third-party identity for calling Google APIs.
 *
 * <p>By default, attempts to exchange the external credential for a GCP access token.
 */
public class AwsCredentials extends ExternalAccountCredentials {

  /**
   * The AWS credential source. Stores data required to retrieve the AWS credential from the AWS
   * metadata server.
   */
  static class AwsCredentialSource extends CredentialSource {

    private final String regionUrl;
    private final String url;
    private final String regionalCredentialVerificationUrl;

    /**
     * The source of the AWS credential. The credential source map must contain the
     * `regional_cred_verification_url` field.
     *
     * <p>The `regional_cred_verification_url` is the regional GetCallerIdentity action URL, used to
     * determine the account ID and its roles.
     *
     * <p>The `environment_id` is the environment identifier, in the format “aws${version}”. This
     * indicates whether breaking changes were introduced to the underlying AWS implementation.
     *
     * <p>The `region_url` identifies the targeted region. Optional.
     *
     * <p>The `url` locates the metadata server used to retrieve the AWS credentials. Optional.
     */
    AwsCredentialSource(Map<String, Object> credentialSourceMap) {
      super(credentialSourceMap);
      if (!credentialSourceMap.containsKey("regional_cred_verification_url")) {
        throw new IllegalArgumentException(
            "A regional_cred_verification_url representing the"
                + " GetCallerIdentity action URL must be specified.");
      }

      String environmentId = (String) credentialSourceMap.get("environment_id");

      // Environment version is prefixed by "aws". e.g. "aws1".
      Matcher matcher = Pattern.compile("(aws)([\\d]+)").matcher(environmentId);
      if (!matcher.matches()) {
        throw new IllegalArgumentException("Invalid AWS environment ID.");
      }

      int environmentVersion = Integer.parseInt(matcher.group(2));
      if (environmentVersion != 1) {
        throw new IllegalArgumentException(
            String.format(
                "AWS version %s is not supported in the current build.", environmentVersion));
      }

      this.regionUrl = (String) credentialSourceMap.get("region_url");
      this.url = (String) credentialSourceMap.get("url");
      this.regionalCredentialVerificationUrl =
          (String) credentialSourceMap.get("regional_cred_verification_url");
    }
  }

  private final AwsCredentialSource awsCredentialSource;

  /** Internal constructor. See {@link AwsCredentials.Builder}. */
  AwsCredentials(Builder builder) {
    super(builder);
    this.awsCredentialSource = (AwsCredentialSource) builder.credentialSource;
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
    // The targeted region is required to generate the signed request. The regional
    // endpoint must also be used.
    String region = getAwsRegion();

    AwsSecurityCredentials credentials = getAwsSecurityCredentials();

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

  private String retrieveResource(String url, String resourceName) throws IOException {
    try {
      HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
      HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));
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

  @VisibleForTesting
  String getAwsRegion() throws IOException {
    // For AWS Lambda, the region is retrieved through the AWS_REGION environment variable.
    String region = getEnvironmentProvider().getEnv("AWS_REGION");
    if (region != null) {
      return region;
    }

    String defaultRegion = getEnvironmentProvider().getEnv("AWS_DEFAULT_REGION");
    if (defaultRegion != null) {
      return defaultRegion;
    }

    if (awsCredentialSource.regionUrl == null || awsCredentialSource.regionUrl.isEmpty()) {
      throw new IOException(
          "Unable to determine the AWS region. The credential source does not contain the region URL.");
    }

    region = retrieveResource(awsCredentialSource.regionUrl, "region");

    // There is an extra appended character that must be removed. If `us-east-1b` is returned,
    // we want `us-east-1`.
    return region.substring(0, region.length() - 1);
  }

  @VisibleForTesting
  AwsSecurityCredentials getAwsSecurityCredentials() throws IOException {
    // Check environment variables for credentials first.
    String accessKeyId = getEnvironmentProvider().getEnv("AWS_ACCESS_KEY_ID");
    String secretAccessKey = getEnvironmentProvider().getEnv("AWS_SECRET_ACCESS_KEY");
    String token = getEnvironmentProvider().getEnv("AWS_SESSION_TOKEN");
    if (accessKeyId != null && secretAccessKey != null) {
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
    String roleName = retrieveResource(awsCredentialSource.url, "IAM role");

    // Retrieve the AWS security credentials by calling the endpoint specified by the credential
    // source.
    String awsCredentials =
        retrieveResource(awsCredentialSource.url + "/" + roleName, "credentials");

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(awsCredentials);
    GenericJson genericJson = parser.parseAndClose(GenericJson.class);

    accessKeyId = (String) genericJson.get("AccessKeyId");
    secretAccessKey = (String) genericJson.get("SecretAccessKey");
    token = (String) genericJson.get("Token");

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
