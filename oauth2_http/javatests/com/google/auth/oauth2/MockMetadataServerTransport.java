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

package com.google.auth.oauth2;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

/** Transport that simulates the GCE metadata server for access tokens. */
public class MockMetadataServerTransport extends MockHttpTransport {

  private String accessToken;

  private Integer tokenRequestStatusCode;

  private String serviceAccountEmail;

  private String idToken;

  private byte[] signature;

  public MockMetadataServerTransport() {}

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  public void setTokenRequestStatusCode(Integer tokenRequestStatusCode) {
    this.tokenRequestStatusCode = tokenRequestStatusCode;
  }

  public void setServiceAccountEmail(String serviceAccountEmail) {
    this.serviceAccountEmail = serviceAccountEmail;
  }

  public void setSignature(byte[] signature) {
    this.signature = signature;
  }

  public void setIdToken(String idToken) {
    this.idToken = idToken;
  }

  @Override
  public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
    if (url.equals(ComputeEngineCredentials.getTokenServerEncodedUrl())) {

      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {

          if (tokenRequestStatusCode != null) {
            return new MockLowLevelHttpResponse()
                .setStatusCode(tokenRequestStatusCode)
                .setContent("Token Fetch Error");
          }

          String metadataRequestHeader = getFirstHeaderValue("Metadata-Flavor");
          if (!"Google".equals(metadataRequestHeader)) {
            throw new IOException("Metadata request header not found.");
          }

          // Create the JSON response
          GenericJson refreshContents = new GenericJson();
          refreshContents.setFactory(OAuth2Utils.JSON_FACTORY);
          refreshContents.put("access_token", accessToken);
          refreshContents.put("expires_in", 3600000);
          refreshContents.put("token_type", "Bearer");
          String refreshText = refreshContents.toPrettyString();

          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(refreshText);
        }
      };
    } else if (url.equals(ComputeEngineCredentials.getMetadataServerUrl())) {
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() {
          MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
          response.addHeader("Metadata-Flavor", "Google");
          return response;
        }
      };
    } else if (isGetServiceAccountsUrl(url)) {
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          // Create the JSON response
          GenericJson serviceAccountsContents = new GenericJson();
          serviceAccountsContents.setFactory(OAuth2Utils.JSON_FACTORY);
          GenericJson defaultAccount = new GenericJson();
          defaultAccount.put("email", serviceAccountEmail);
          serviceAccountsContents.put("default", defaultAccount);

          String serviceAccounts = serviceAccountsContents.toPrettyString();

          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(serviceAccounts);
        }
      };
    } else if (isSignRequestUrl(url)) {
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          // Create the JSON response
          GenericJson signContents = new GenericJson();
          signContents.setFactory(OAuth2Utils.JSON_FACTORY);
          signContents.put("signedBlob", BaseEncoding.base64().encode(signature));

          String signature = signContents.toPrettyString();

          return new MockLowLevelHttpResponse()
              .setContentType(Json.MEDIA_TYPE)
              .setContent(signature);
        }
      };
    } else if (isIdentityDocumentUrl(url)) {
      if (idToken != null) {
        return new MockLowLevelHttpRequest(url) {
          @Override
          public LowLevelHttpResponse execute() throws IOException {
            return new MockLowLevelHttpResponse().setContent(idToken);
          }
        };
      }

      // https://cloud.google.com/compute/docs/instances/verifying-instance-identity#token_format
      Map<String, String> queryPairs = new HashMap<String, String>();
      String query = (new URL(url)).getQuery();
      String[] pairs = query.split("&");
      for (String pair : pairs) {
        int idx = pair.indexOf("=");
        queryPairs.put(
            URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
            URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
      }

      if (queryPairs.containsKey("format")) {
        if (((String) queryPairs.get("format")).equals("full")) {

          // return license only if format=full is set
          if (queryPairs.containsKey("license")) {
            if (((String) queryPairs.get("license")).equals("TRUE")) {
              return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                  return new MockLowLevelHttpResponse()
                      .setContent(ComputeEngineCredentialsTest.FULL_ID_TOKEN_WITH_LICENSE);
                }
              };
            }
          }
          // otherwise return full format
          return new MockLowLevelHttpRequest(url) {
            @Override
            public LowLevelHttpResponse execute() throws IOException {
              return new MockLowLevelHttpResponse()
                  .setContent(ComputeEngineCredentialsTest.FULL_ID_TOKEN);
            }
          };
        }
      }
      // Return default format if nothing is set
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          return new MockLowLevelHttpResponse()
              .setContent(ComputeEngineCredentialsTest.STANDARD_ID_TOKEN);
        }
      };
    }
    return super.buildRequest(method, url);
  }

  protected boolean isGetServiceAccountsUrl(String url) {
    return url.equals(ComputeEngineCredentials.getServiceAccountsUrl());
  }

  protected boolean isSignRequestUrl(String url) {
    return serviceAccountEmail != null
        && url.equals(
            String.format(ComputeEngineCredentials.SIGN_BLOB_URL_FORMAT, serviceAccountEmail));
  }

  protected boolean isIdentityDocumentUrl(String url) {
    return url.startsWith(String.format(ComputeEngineCredentials.getIdentityDocumentUrl()));
  }
}
