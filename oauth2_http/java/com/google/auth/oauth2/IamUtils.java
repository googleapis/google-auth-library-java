/*
 * Copyright 2019, Google Inc. All rights reserved.
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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.Credentials;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * This internal class provides shared utilities for interacting with the IAM API for common
 * features like signing.
 */
class IamUtils {
  private static final String SIGN_BLOB_URL_FORMAT =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signBlob";
  private static final String ID_TOKEN_URL_FORMAT =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken";
  private static final String PARSE_ERROR_MESSAGE = "Error parsing error message response. ";
  private static final String PARSE_ERROR_SIGNATURE = "Error parsing signature response. ";

  /**
   * Returns a signature for the provided bytes.
   *
   * @param serviceAccountEmail the email address for the service account used for signing
   * @param credentials credentials required for making the IAM call
   * @param transport transport used for building the HTTP request
   * @param toSign bytes to sign
   * @param additionalFields additional fields to send in the IAM call
   * @return signed bytes
   * @throws ServiceAccountSigner.SigningException if signing fails
   */
  static byte[] sign(
      String serviceAccountEmail,
      Credentials credentials,
      HttpTransport transport,
      byte[] toSign,
      Map<String, ?> additionalFields) {
    BaseEncoding base64 = BaseEncoding.base64();
    String signature;
    try {
      signature =
          getSignature(
              serviceAccountEmail, credentials, transport, base64.encode(toSign), additionalFields);
    } catch (IOException ex) {
      throw new ServiceAccountSigner.SigningException("Failed to sign the provided bytes", ex);
    }
    return base64.decode(signature);
  }

  private static String getSignature(
      String serviceAccountEmail,
      Credentials credentials,
      HttpTransport transport,
      String bytes,
      Map<String, ?> additionalFields)
      throws IOException {
    String signBlobUrl = String.format(SIGN_BLOB_URL_FORMAT, serviceAccountEmail);
    GenericUrl genericUrl = new GenericUrl(signBlobUrl);

    GenericData signRequest = new GenericData();
    signRequest.set("payload", bytes);
    for (Map.Entry<String, ?> entry : additionalFields.entrySet()) {
      signRequest.set(entry.getKey(), entry.getValue());
    }
    JsonHttpContent signContent = new JsonHttpContent(OAuth2Utils.JSON_FACTORY, signRequest);

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpRequest request =
        transport.createRequestFactory(adapter).buildPostRequest(genericUrl, signContent);

    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.setThrowExceptionOnExecuteError(false);

    HttpResponse response = request.execute();
    int statusCode = response.getStatusCode();
    if (statusCode >= 400 && statusCode < HttpStatusCodes.STATUS_CODE_SERVER_ERROR) {
      GenericData responseError = response.parseAs(GenericData.class);
      Map<String, Object> error =
          OAuth2Utils.validateMap(responseError, "error", PARSE_ERROR_MESSAGE);
      String errorMessage = OAuth2Utils.validateString(error, "message", PARSE_ERROR_MESSAGE);
      throw new IOException(
          String.format(
              "Error code %s trying to sign provided bytes: %s", statusCode, errorMessage));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(
          String.format(
              "Unexpected Error code %s trying to sign provided bytes: %s",
              statusCode, response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from sign blob server request.");
    }

    GenericData responseData = response.parseAs(GenericData.class);
    return OAuth2Utils.validateString(responseData, "signedBlob", PARSE_ERROR_SIGNATURE);
  }

  /**
   * Returns an IdToken issued to the serviceAccount with a specified targetAudience
   *
   * @param serviceAccountEmail the email address for the service account to get an ID Token for
   * @param credentials credentials required for making the IAM call
   * @param transport transport used for building the HTTP request
   * @param targetAudience the audience the issued ID token should include
   * @param additionalFields additional fields to send in the IAM call
   * @return IdToken issed to the serviceAccount
   * @throws IOException if the IdToken cannot be issued.
   * @see
   *     https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateIdToken
   */
  static IdToken getIdToken(
      String serviceAccountEmail,
      Credentials credentials,
      HttpTransport transport,
      String targetAudience,
      boolean includeEmail,
      Map<String, ?> additionalFields)
      throws IOException {

    String idTokenUrl = String.format(ID_TOKEN_URL_FORMAT, serviceAccountEmail);
    GenericUrl genericUrl = new GenericUrl(idTokenUrl);

    GenericData idTokenRequest = new GenericData();
    idTokenRequest.set("audience", targetAudience);
    idTokenRequest.set("includeEmail", includeEmail);
    for (Map.Entry<String, ?> entry : additionalFields.entrySet()) {
      idTokenRequest.set(entry.getKey(), entry.getValue());
    }
    JsonHttpContent idTokenContent = new JsonHttpContent(OAuth2Utils.JSON_FACTORY, idTokenRequest);

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpRequest request =
        transport.createRequestFactory(adapter).buildPostRequest(genericUrl, idTokenContent);

    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.setThrowExceptionOnExecuteError(false);

    HttpResponse response = request.execute();
    int statusCode = response.getStatusCode();
    if (statusCode >= 400 && statusCode < HttpStatusCodes.STATUS_CODE_SERVER_ERROR) {
      GenericData responseError = response.parseAs(GenericData.class);
      Map<String, Object> error =
          OAuth2Utils.validateMap(responseError, "error", PARSE_ERROR_MESSAGE);
      String errorMessage = OAuth2Utils.validateString(error, "message", PARSE_ERROR_MESSAGE);
      throw new IOException(
          String.format("Error code %s trying to getIDToken: %s", statusCode, errorMessage));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(
          String.format(
              "Unexpected Error code %s trying to getIDToken: %s",
              statusCode, response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from
      // parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from generateIDToken server request.");
    }

    GenericJson responseData = response.parseAs(GenericJson.class);
    String rawToken = OAuth2Utils.validateString(responseData, "token", PARSE_ERROR_MESSAGE);
    return IdToken.create(rawToken);
  }
}
