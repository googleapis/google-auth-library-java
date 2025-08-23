/*
 * Copyright 2024, Google LLC
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

import java.io.IOException;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;

/**
 * Represents a trust boundary that can be used to restrict access to resources. This is an
 * experimental feature.
 */
public final class TrustBoundary {

  static final String TRUST_BOUNDARY_KEY = "x-goog-trust-boundary";
  private static final String TRUST_BOUNDARY_ENDPOINT = "https://sts.googleapis.com/v1/trustBoundary";

  private final boolean enabled;
  private final String value;

  private TrustBoundary(boolean enabled, String value) {
    this.enabled = enabled;
    this.value = value;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public String getValue() {
    return value;
  }

  public static TrustBoundary refresh(HttpTransportFactory transportFactory) throws IOException {
    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(TRUST_BOUNDARY_ENDPOINT));
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));
    HttpResponse response = request.execute();
    GenericJson json = response.parseAs(GenericJson.class);
    boolean enabled = (boolean) json.get("enabled");
    String value = (String) json.get("value");
    return new TrustBoundary(enabled, value);
  }
}