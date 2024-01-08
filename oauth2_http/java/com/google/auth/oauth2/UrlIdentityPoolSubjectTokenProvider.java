/*
 * Copyright 2024 Google LLC
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
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;
import java.io.IOException;
import java.util.function.Supplier;

class UrlIdentityPoolSubjectTokenProvider extends IdentityPoolSubjectTokenProvider {

  private final IdentityPoolCredentialSource credentialSource;
  private final transient HttpTransportFactory transportFactory;

  UrlIdentityPoolSubjectTokenProvider(
      IdentityPoolCredentialSource credentialSource, HttpTransportFactory transportFactory) {
    this.credentialSource = credentialSource;
    this.transportFactory = transportFactory;
  }

  @Override
  public String getSubjectToken() throws IOException {
    return this.getSubjectTokenFromMetadataServer();
  }

  @Override
  public boolean isUserSupplied() {
    return false;
  }

  @Override
  public Supplier<String> getSupplier() {
    return () -> {
      try {
        return this.getSubjectToken();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    };
  }

  private String getSubjectTokenFromMetadataServer() throws IOException {
    HttpRequest request =
        transportFactory
            .create()
            .createRequestFactory()
            .buildGetRequest(new GenericUrl(credentialSource.credentialLocation));
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));

    if (credentialSource.hasHeaders()) {
      HttpHeaders headers = new HttpHeaders();
      headers.putAll(credentialSource.headers);
      request.setHeaders(headers);
    }

    try {
      HttpResponse response = request.execute();
      return parseToken(response.getContent(), this.credentialSource);
    } catch (IOException e) {
      throw new IOException(
          String.format("Error getting subject token from metadata server: %s", e.getMessage()), e);
    }
  }
}
