/*
 * Copyright 2020 Google LLC
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

import static com.google.api.client.util.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.api.client.util.Clock;
import com.google.api.client.util.Joiner;
import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Internal utility that signs AWS API requests based on the AWS Signature Version 4 signing
 * process.
 *
 * <p>https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
public class AwsRequestSigner {

  // AWS Signature Version 4 signing algorithm identifier.
  private static final String HASHING_ALGORITHM = "AWS4-HMAC-SHA256";

  // The termination string for the AWS credential scope value as defined in
  // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
  private static final String AWS_REQUEST_TYPE = "aws4_request";

  private AwsSecurityCredentials awsSecurityCredentials;
  private Map<String, String> additionalHeaders;
  private String httpMethod;
  private String region;
  private String requestPayload;
  private URI uri;

  /**
   * Internal constructor.
   *
   * @param awsSecurityCredentials AWS security credentials.
   * @param httpMethod The HTTP request method.
   * @param url The request URL.
   * @param region The targeted region.
   * @param requestPayload The request payload.
   * @param additionalHeaders A map of additional HTTP headers to be included with the signed
   *     request.
   */
  private AwsRequestSigner(
      AwsSecurityCredentials awsSecurityCredentials,
      String httpMethod,
      String url,
      String region,
      @Nullable String requestPayload,
      @Nullable Map<String, String> additionalHeaders) {
    this.awsSecurityCredentials = checkNotNull(awsSecurityCredentials);
    this.httpMethod = checkNotNull(httpMethod);
    this.uri = URI.create(url).normalize();
    this.region = checkNotNull(region);
    this.requestPayload = requestPayload == null ? "" : requestPayload;
    this.additionalHeaders =
        (additionalHeaders != null)
            ? new HashMap<>(additionalHeaders)
            : new HashMap<String, String>();
  }

  /**
   * Signs the specified AWS API request.
   *
   * @return the {@link AwsRequestSignature}.
   */
  AwsRequestSignature sign() {
    // Get the dates to be used to sign the request.
    AwsDates dates = getDates();

    // Retrieve the service name. For example: iam.amazonaws.com host => iam service.
    String serviceName = Splitter.on(".").split(uri.getHost()).iterator().next();

    Map<String, String> canonicalHeaders = getCanonicalHeaders(dates.getOriginalDate());
    // Headers must be sorted.
    List<String> sortedHeaders = new ArrayList<>();
    for (String headerName : canonicalHeaders.keySet()) {
      sortedHeaders.add(headerName.toLowerCase(Locale.US));
    }
    Collections.sort(sortedHeaders);

    String canonicalRequestHash = createCanonicalRequestHash(canonicalHeaders, sortedHeaders);
    String credentialScope =
        dates.getFormattedDate() + "/" + region + "/" + serviceName + "/" + AWS_REQUEST_TYPE;
    String stringToSign =
        createStringToSign(canonicalRequestHash, dates.getAmzDate(), credentialScope);
    String signature =
        calculateAwsV4Signature(
            serviceName,
            awsSecurityCredentials.getSecretAccessKey(),
            dates.getFormattedDate(),
            region,
            stringToSign);

    return new AwsRequestSignature.Builder()
        .setSignature(signature)
        .setCanonicalHeaders(canonicalHeaders)
        .setHttpMethod(httpMethod)
        .setSecurityCredentials(awsSecurityCredentials)
        .setCredentialScope(credentialScope)
        .setUrl(uri.toString())
        .setDate(dates.getOriginalDate())
        .setRegion(region)
        .build();
  }

  /** Task 1: Create a canonical request for Signature Version 4. */
  private String createCanonicalRequestHash(
      Map<String, String> headers, List<String> sortedHeaderNames) {
    // Append the HTTP request method.
    StringBuilder canonicalRequest = new StringBuilder(httpMethod).append("\n");

    // Append the path.
    String urlPath = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    canonicalRequest.append(urlPath).append("\n");

    // Append the canonical query string.
    String actionQueryString = uri.getRawQuery() != null ? uri.getRawQuery() : "";
    canonicalRequest.append(actionQueryString).append("\n");

    // Append the canonical headers.
    StringBuilder canonicalHeaders = new StringBuilder();
    for (String headerName : sortedHeaderNames) {
      canonicalHeaders.append(headerName).append(":").append(headers.get(headerName)).append("\n");
    }
    canonicalRequest.append(canonicalHeaders).append("\n");

    // Append the signed headers.
    canonicalRequest.append(Joiner.on(';').join(sortedHeaderNames)).append("\n");

    // Append the hashed request payload.
    canonicalRequest.append(getHexEncodedSha256Hash(requestPayload.getBytes()));

    // Return the hashed canonical request.
    return getHexEncodedSha256Hash(canonicalRequest.toString().getBytes());
  }

  /** Task 2: Create a string to sign for Signature Version 4. */
  private String createStringToSign(
      String canonicalRequestHash, String xAmzDate, String credentialScope) {
    return HASHING_ALGORITHM
        + "\n"
        + xAmzDate
        + "\n"
        + credentialScope
        + "\n"
        + canonicalRequestHash;
  }

  /**
   * Task 3: Calculate the signature for AWS Signature Version 4.
   *
   * @param date the date used in the hashing process in YYYYMMDD format
   */
  private String calculateAwsV4Signature(
      String serviceName, String secret, String date, String region, String stringToSign) {
    byte[] kDate = sign(("AWS4" + secret).getBytes(UTF_8), date.getBytes(UTF_8));
    byte[] kRegion = sign(kDate, region.getBytes(UTF_8));
    byte[] kService = sign(kRegion, serviceName.getBytes(UTF_8));
    byte[] kSigning = sign(kService, AWS_REQUEST_TYPE.getBytes(UTF_8));
    return BaseEncoding.base16().lowerCase().encode(sign(kSigning, stringToSign.getBytes(UTF_8)));
  }

  private Map<String, String> getCanonicalHeaders(String date) {
    Map<String, String> headers = new HashMap<>();
    headers.put("host", uri.getHost());

    // Only add the date if it hasn't been specified through the "date" header.
    if (!additionalHeaders.containsKey("date")) {
      headers.put("x-amz-date", date);
    }

    if (awsSecurityCredentials.getToken() != null && !awsSecurityCredentials.getToken().isEmpty()) {
      headers.put("x-amz-security-token", awsSecurityCredentials.getToken());
    }

    // Add all additional headers.
    for (String key : additionalHeaders.keySet()) {
      // Header keys need to be lowercase.
      headers.put(key.toLowerCase(), additionalHeaders.get(key));
    }
    return headers;
  }

  private AwsDates getDates() {
    if (additionalHeaders.containsKey("date")) {
      return AwsDates.fromDateHeader(additionalHeaders.get("date"));
    }
    if (additionalHeaders.containsKey("x-amz-date")) {
      return AwsDates.fromXAmzDate(additionalHeaders.get("x-amz-date"));
    }
    return AwsDates.generateXAmzDate();
  }

  private static byte[] sign(byte[] key, byte[] value) {
    try {
      String algorithm = "HmacSHA256";
      Mac mac = Mac.getInstance(algorithm);
      mac.init(new SecretKeySpec(key, algorithm));
      return mac.doFinal(value);
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new IllegalStateException("Failed to calculate the AWS V4 Signature.", ex);
    }
  }

  private static String getHexEncodedSha256Hash(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return BaseEncoding.base16().lowerCase().encode(digest.digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Failed to compute SHA-256 hash.", e);
    }
  }

  static Builder newBuilder(
      AwsSecurityCredentials awsSecurityCredentials, String httpMethod, String url, String region) {
    return new Builder(awsSecurityCredentials, httpMethod, url, region);
  }

  static class Builder {

    private AwsSecurityCredentials awsSecurityCredentials;
    private String httpMethod;
    private String url;
    private String region;

    @Nullable private String requestPayload;
    @Nullable private Map<String, String> additionalHeaders;

    private Builder(
        AwsSecurityCredentials awsSecurityCredentials,
        String httpMethod,
        String url,
        String region) {
      this.awsSecurityCredentials = awsSecurityCredentials;
      this.httpMethod = httpMethod;
      this.url = url;
      this.region = region;
    }

    Builder setRequestPayload(String requestPayload) {
      this.requestPayload = requestPayload;
      return this;
    }

    Builder setAdditionalHeaders(Map<String, String> additionalHeaders) {
      this.additionalHeaders = additionalHeaders;
      return this;
    }

    AwsRequestSigner build() {
      return new AwsRequestSigner(
          awsSecurityCredentials, httpMethod, url, region, requestPayload, additionalHeaders);
    }
  }

  static final class AwsDates {

    private static final String X_AMZ_DATE_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
    private static final String CUSTOM_DATE_FORMAT = "E, dd MMM yyyy HH:mm:ss z";

    private String originalDate;
    private String amzDate;
    private String formattedDate;

    private AwsDates(String originalDate, String amzDate, String formattedDate) {
      this.originalDate = checkNotNull(originalDate);
      this.amzDate = checkNotNull(amzDate);
      this.formattedDate = checkNotNull(formattedDate);
    }

    static AwsDates fromXAmzDate(String xAmzDate) {
      return new AwsDates(xAmzDate, xAmzDate, xAmzDate.substring(0, 8));
    }

    static AwsDates fromDateHeader(String date) {
      DateFormat dateFormat = new SimpleDateFormat(X_AMZ_DATE_FORMAT);
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      try {
        Date inputDate = new SimpleDateFormat(CUSTOM_DATE_FORMAT).parse(date);
        String xAmzDate = dateFormat.format(inputDate);
        return new AwsDates(date, xAmzDate, xAmzDate.substring(0, 8));
      } catch (ParseException e) {
        throw new IllegalArgumentException("Invalid date provided: " + date, e);
      }
    }

    static AwsDates generateXAmzDate() {
      DateFormat dateFormat = new SimpleDateFormat(X_AMZ_DATE_FORMAT);
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      String xAmzDate = dateFormat.format(new Date(Clock.SYSTEM.currentTimeMillis()));
      return fromXAmzDate(xAmzDate);
    }

    /**
     * Returns the original date. This can either be the x-amz-date or a specified date in the
     * format of E, dd MMM yyyy HH:mm:ss z.
     */
    String getOriginalDate() {
      return originalDate;
    }

    /** Returns the x-amz-date in yyyyMMdd'T'HHmmss'Z' format. */
    String getAmzDate() {
      return amzDate;
    }

    /** Returns the x-amz-date in YYYYMMDD format. */
    String getFormattedDate() {
      return formattedDate;
    }
  }
}
