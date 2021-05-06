/*
 * Copyright 2015, Google Inc. All rights reserved.
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

package com.google.auth.http;

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.auth.Credentials;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** A wrapper for using Credentials with the Google API Client Libraries for Java with Http. */
public class HttpUserCredentialsAdapter extends HttpCredentialsAdapter {

  /** @param credentials Credentials instance to adapt for HTTP */
  public HttpUserCredentialsAdapter(Credentials credentials) {
    super(credentials);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Initialize the HTTP request prior to execution.
   *
   * @param request HTTP request
   */
  @Override
  public void initialize(HttpRequest request) throws IOException {
    request.setUnsuccessfulResponseHandler(this);

    if (!credentials.hasRequestMetadata()) {
      return;
    }
    HttpHeaders requestHeaders = request.getHeaders();
    URI uri = null;
    if (request.getUrl() != null) {
      uri = request.getUrl().toURI();
    }
    Map<String, List<String>> credentialHeaders = credentials.getRequestMetadata(uri);
    if (credentialHeaders == null) {
      return;
    }
    for (Map.Entry<String, List<String>> entry : credentialHeaders.entrySet()) {
      String headerName = entry.getKey();
      List<String> requestValues = new ArrayList<>();
      requestValues.addAll(entry.getValue());
      requestHeaders.put(headerName, requestValues);
    }
  }
}