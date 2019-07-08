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
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.ServiceAccountSigner;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

class IamSigner implements ServiceAccountSigner {
  private static final String SIGN_BLOB_URL_FORMAT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signBlob";
  private static final String PARSE_ERROR_MESSAGE = "Error parsing error message response. ";
  private static final String PARSE_ERROR_SIGNATURE = "Error parsing signature response. ";

  private String account;
  private Map<String, List<String>> headers;
  private HttpRequestFactory requestFactory;

  IamSigner(Builder builder) {
    account = builder.getAccount();
    headers = builder.getHeaders();
    requestFactory = builder.getRequestFactory();
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  @Override
  public String getAccount() {
    return account;
  }

  @Override
  public byte[] sign(byte[] toSign) {
    BaseEncoding base64 = BaseEncoding.base64();
    String signature;
    try {
      signature = getSignature(base64.encode(toSign));
    } catch (IOException ex) {
      throw new SigningException("Failed to sign the provided bytes", ex);
    }
    return base64.decode(signature);
  }

  private String getSignature(String bytes) throws IOException {
    String signBlobUrl = String.format(SIGN_BLOB_URL_FORMAT, getAccount());
    GenericUrl genericUrl = new GenericUrl(signBlobUrl);

    GenericData signRequest = new GenericData();
    signRequest.set("payload", bytes);
    JsonHttpContent signContent = new JsonHttpContent(OAuth2Utils.JSON_FACTORY, signRequest);
    HttpRequest request = requestFactory.buildPostRequest(genericUrl, signContent);

    HttpHeaders requestHeaders = request.getHeaders();
    for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
      requestHeaders.put(entry.getKey(), entry.getValue());
    }
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.setThrowExceptionOnExecuteError(false);

    HttpResponse response = request.execute();
    int statusCode = response.getStatusCode();
    if (statusCode >= 400 && statusCode < HttpStatusCodes.STATUS_CODE_SERVER_ERROR) {
      GenericData responseError = response.parseAs(GenericData.class);
      Map<String, Object> error = OAuth2Utils.validateMap(responseError, "error", PARSE_ERROR_MESSAGE);
      String errorMessage = OAuth2Utils.validateString(error, "message", PARSE_ERROR_MESSAGE);
      throw new IOException(String.format("Error code %s trying to sign provided bytes: %s",
          statusCode, errorMessage));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(String.format("Unexpected Error code %s trying to sign provided bytes: %s", statusCode,
          response.parseAsString()));
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

  static class Builder {
    private String account;
    private Map<String, List<String>> headers;
    private HttpRequestFactory requestFactory;

    public Builder setAccount(String account) {
      this.account = account;
      return this;
    }

    public String getAccount() {
      return account;
    }

    public Builder setHeaders(Map<String, List<String>> headers) {
      this.headers = headers;
      return this;
    }

    public Map<String, List<String>> getHeaders() {
      return headers;
    }

    public Builder setRequestFactory(HttpRequestFactory requestFactory) {
      this.requestFactory = requestFactory;
      return this;
    }

    public HttpRequestFactory getRequestFactory() {
      return requestFactory;
    }

    IamSigner build() {
      return new IamSigner(this);
    }
  }
}
