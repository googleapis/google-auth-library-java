/*
 * Copyright 2016, Google Inc. All rights reserved.
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
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.collect.Iterables;
import java.io.IOException;
import java.io.InputStream;
import java.util.ServiceLoader;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Utilities to fetch the S2A (Secure Session Agent) address from the mTLS configuration.
 *
 * <p>mTLS configuration is queried from the MDS MTLS Autoconfiguration endpoint.
 */
@ThreadSafe
public final class S2A {
  public static final String S2A_CONFIG_ENDPOINT_POSTFIX =
      "/computeMetadata/v1/instance/platform-security/auto-mtls-configuration";

  public static final String METADATA_FLAVOR = "Metadata-Flavor";
  public static final String GOOGLE = "Google";
  private static final String PARSE_ERROR_S2A = "Error parsing S2A Config from MDS JSON response.";

  private S2AConfig config;

  private transient HttpTransportFactory transportFactory;

  public void setHttpTransportFactory(HttpTransportFactory tf) {
    this.transportFactory = tf;
    this.config = getS2AConfigFromMDS();
  }

  /** @return the mTLS S2A Address from the mTLS config. */
  public String getMtlsS2AAddress() {
    return config.getMtlsAddress();
  }

  /** @return the plaintext S2A Address from the mTLS config. */
  public String getPlaintextS2AAddress() {
    return config.getPlaintextAddress();
  }

  /**
   * Queries the MDS mTLS Autoconfiguration endpoint and returns the {@link S2AConfig}.
   *
   * <p>Returns {@link S2AConfig} with empty addresses on error.
   *
   * @return the {@link S2AConfig}.
   */
  private S2AConfig getS2AConfigFromMDS() {
    String url = getMdsMtlsEndpoint();
    GenericUrl genericUrl = new GenericUrl(url);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY); 
    if (transportFactory == null) {
      transportFactory =
          Iterables.getFirst(
              ServiceLoader.load(HttpTransportFactory.class), OAuth2Utils.HTTP_TRANSPORT_FACTORY);
    }

    HttpRequest request;
    try {
      request =
              transportFactory.create().createRequestFactory().buildGetRequest(genericUrl);
      request.setParser(parser);
      request.getHeaders().set(METADATA_FLAVOR, GOOGLE);
      request.setThrowExceptionOnExecuteError(false);
    } catch (IOException e) {
      return S2AConfig.createBuilder().build();
    }

    for (int i = 0; i < OAuth2Utils.DEFAULT_NUMBER_OF_RETRIES; i++) {
      String plaintextS2AAddress = "";
      String mtlsS2AAddress = "";
      try {
        HttpResponse response = request.execute();
        if (!response.isSuccessStatusCode()) {
          continue;
        }
        InputStream content = response.getContent();
        if (content == null) {
          continue;
        }
        GenericData responseData = response.parseAs(GenericData.class);
        plaintextS2AAddress =
            OAuth2Utils.validateString(responseData, "plaintext_address", PARSE_ERROR_S2A);
        mtlsS2AAddress = OAuth2Utils.validateString(responseData, "mtls_address", PARSE_ERROR_S2A);
      } catch (IOException e) {
        continue;
      }
      return S2AConfig.createBuilder()
          .setPlaintextAddress(plaintextS2AAddress)
          .setMtlsAddress(mtlsS2AAddress)
          .build();
    }
    return S2AConfig.createBuilder().build();
  }

  /** @return MDS mTLS autoconfig endpoint. */
  private String getMdsMtlsEndpoint() {
    return ComputeEngineCredentials.getMetadataServerUrl() + S2A_CONFIG_ENDPOINT_POSTFIX;
  }
}
