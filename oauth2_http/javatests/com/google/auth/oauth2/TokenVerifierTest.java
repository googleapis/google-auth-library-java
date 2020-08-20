/*
 * Copyright 2020, Google LLC
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.Clock;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.io.CharStreams;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TokenVerifierTest {
  private static final String ES256_TOKEN =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1wZjBEQSJ9.eyJhdWQiOiIvcHJvamVjdHMvNjUyNTYyNzc2Nzk4L2FwcHMvY2xvdWQtc2FtcGxlcy10ZXN0cy1waHAtaWFwIiwiZW1haWwiOiJjaGluZ29yQGdvb2dsZS5jb20iLCJleHAiOjE1ODQwNDc2MTcsImdvb2dsZSI6eyJhY2Nlc3NfbGV2ZWxzIjpbImFjY2Vzc1BvbGljaWVzLzUxODU1MTI4MDkyNC9hY2Nlc3NMZXZlbHMvcmVjZW50U2VjdXJlQ29ubmVjdERhdGEiLCJhY2Nlc3NQb2xpY2llcy81MTg1NTEyODA5MjQvYWNjZXNzTGV2ZWxzL3Rlc3ROb09wIiwiYWNjZXNzUG9saWNpZXMvNTE4NTUxMjgwOTI0L2FjY2Vzc0xldmVscy9ldmFwb3JhdGlvblFhRGF0YUZ1bGx5VHJ1c3RlZCJdfSwiaGQiOiJnb29nbGUuY29tIiwiaWF0IjoxNTg0MDQ3MDE3LCJpc3MiOiJodHRwczovL2Nsb3VkLmdvb2dsZS5jb20vaWFwIiwic3ViIjoiYWNjb3VudHMuZ29vZ2xlLmNvbToxMTIxODE3MTI3NzEyMDE5NzI4OTEifQ.yKNtdFY5EKkRboYNexBdfugzLhC3VuGyFcuFYA8kgpxMqfyxa41zkML68hYKrWu2kOBTUW95UnbGpsIi_u1fiA";

  private static final String FEDERATED_SIGNON_RS256_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY5ZDk3YjRjYWU5MGJjZDc2YWViMjAwMjZmNmI3NzBjYWMyMjE3ODMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL3BhdGgiLCJhenAiOiJpbnRlZ3JhdGlvbi10ZXN0c0BjaGluZ29yLXRlc3QuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbCI6ImludGVncmF0aW9uLXRlc3RzQGNoaW5nb3ItdGVzdC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE1ODc2Mjk4ODgsImlhdCI6MTU4NzYyNjI4OCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTA0MDI5MjkyODUzMDk5OTc4MjkzIn0.Pj4KsJh7riU7ZIbPMcHcHWhasWEcbVjGP4yx_5E0iOpeDalTdri97E-o0dSSkuVX2FeBIgGUg_TNNgJ3YY97T737jT5DUYwdv6M51dDlLmmNqlu_P6toGCSRC8-Beu5gGmqS2Y82TmpHH9Vhoh5PsK7_rVHk8U6VrrVVKKTWm_IzTFhqX1oYKPdvfyaNLsXPbCt_NFE0C3DNmFkgVhRJu7LtzQQN-ghaqd3Ga3i6KH222OEI_PU4BUTvEiNOqRGoMlT_YOsyFN3XwqQ6jQGWhhkArL1z3CG2BVQjHTKpgVsRyy_H6WTZiju2Q-XWobgH-UPSZbyymV8-cFT9XKEtZQ";
  private static final String LEGACY_FEDERATED_SIGNON_CERT_URL =
      "https://www.googleapis.com/oauth2/v1/certs";

  private static final String SERVICE_ACCOUNT_RS256_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJlZjc3YjM4YTFiMDM3MDQ4NzA0MzkxNmFjYmYyN2Q3NGVkZDA4YjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL2F1ZGllbmNlIiwiZXhwIjoxNTg3NjMwNTQzLCJpYXQiOjE1ODc2MjY5NDMsImlzcyI6InNvbWUgaXNzdWVyIiwic3ViIjoic29tZSBzdWJqZWN0In0.gGOQW0qQgs4jGUmCsgRV83RqsJLaEy89-ZOG6p1u0Y26FyY06b6Odgd7xXLsSTiiSnch62dl0Lfi9D0x2ByxvsGOCbovmBl2ZZ0zHr1wpc4N0XS9lMUq5RJQbonDibxXG4nC2zroDfvD0h7i-L8KMXeJb9pYwW7LkmrM_YwYfJnWnZ4bpcsDjojmPeUBlACg7tjjOgBFbyQZvUtaERJwSRlaWibvNjof7eCVfZChE0PwBpZc_cGqSqKXv544L4ttqdCnmONjqrTATXwC4gYxruevkjHfYI5ojcQmXoWDJJ0-_jzfyPE4MFFdCFgzLgnfIOwe5ve0MtquKuv2O0pgvg";
  private static final String SERVICE_ACCOUNT_CERT_URL =
      "https://www.googleapis.com/robot/v1/metadata/x509/integration-tests%40chingor-test.iam.gserviceaccount.com";

  private static final List<String> ALL_TOKENS =
      Arrays.asList(ES256_TOKEN, FEDERATED_SIGNON_RS256_TOKEN, SERVICE_ACCOUNT_RS256_TOKEN);

  // Fixed to 2020-02-26 08:00:00 to allow expiration tests to pass
  private static final Clock FIXED_CLOCK =
      new Clock() {
        @Override
        public long currentTimeMillis() {
          return 1582704000000L;
        }
      };

  @Test
  public void verifyExpiredToken() {
    for (String token : ALL_TOKENS) {
      TokenVerifier tokenVerifier = TokenVerifier.newBuilder().build();
      try {
        tokenVerifier.verify(token);
        fail("Should have thrown a VerificationException");
      } catch (TokenVerifier.VerificationException e) {
        assertTrue(e.getMessage().contains("expired"));
      }
    }
  }

  @Test
  public void verifyExpectedAudience() {
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder().setAudience("expected audience").build();
    for (String token : ALL_TOKENS) {
      try {
        tokenVerifier.verify(token);
        fail("Should have thrown a VerificationException");
      } catch (TokenVerifier.VerificationException e) {
        assertTrue(e.getMessage().contains("audience does not match"));
      }
    }
  }

  @Test
  public void verifyExpectedIssuer() {
    TokenVerifier tokenVerifier = TokenVerifier.newBuilder().setIssuer("expected issuer").build();
    for (String token : ALL_TOKENS) {
      try {
        tokenVerifier.verify(token);
        fail("Should have thrown a VerificationException");
      } catch (TokenVerifier.VerificationException e) {
        assertTrue(e.getMessage().contains("issuer does not match"));
      }
    }
  }

  @Test
  public void verifyEs256Token404CertificateUrl() {
    // Mock HTTP requests
    HttpTransportFactory httpTransportFactory =
        new HttpTransportFactory() {
          @Override
          public HttpTransport create() {
            return new MockHttpTransport() {
              @Override
              public LowLevelHttpRequest buildRequest(String method, String url)
                  throws IOException {
                return new MockLowLevelHttpRequest() {
                  @Override
                  public LowLevelHttpResponse execute() throws IOException {
                    MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
                    response.setStatusCode(404);
                    response.setContentType("application/json");
                    response.setContent("");
                    return response;
                  }
                };
              }
            };
          }
        };
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setClock(FIXED_CLOCK)
            .setHttpTransportFactory(httpTransportFactory)
            .build();
    try {
      tokenVerifier.verify(ES256_TOKEN);
    } catch (TokenVerifier.VerificationException e) {
      assertTrue(e.getMessage().contains("Could not find PublicKey"));
    }
  }

  @Test
  public void verifyEs256TokenPublicKeyMismatch() {
    // Mock HTTP requests
    HttpTransportFactory httpTransportFactory =
        new HttpTransportFactory() {
          @Override
          public HttpTransport create() {
            return new MockHttpTransport() {
              @Override
              public LowLevelHttpRequest buildRequest(String method, String url)
                  throws IOException {
                return new MockLowLevelHttpRequest() {
                  @Override
                  public LowLevelHttpResponse execute() throws IOException {
                    MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
                    response.setStatusCode(200);
                    response.setContentType("application/json");
                    response.setContent("");
                    return response;
                  }
                };
              }
            };
          }
        };
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setClock(FIXED_CLOCK)
            .setHttpTransportFactory(httpTransportFactory)
            .build();
    try {
      tokenVerifier.verify(ES256_TOKEN);
      fail("Should have failed verification");
    } catch (TokenVerifier.VerificationException e) {
      assertTrue(e.getMessage().contains("Error fetching PublicKey"));
    }
  }

  @Test
  public void verifyEs256Token() throws TokenVerifier.VerificationException, IOException {
    HttpTransportFactory httpTransportFactory =
        mockTransport(
            "https://www.gstatic.com/iap/verify/public_key-jwk",
            readResourceAsString("iap_keys.json"));
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setClock(FIXED_CLOCK)
            .setHttpTransportFactory(httpTransportFactory)
            .build();
    assertNotNull(tokenVerifier.verify(ES256_TOKEN));
  }

  @Test
  public void verifyRs256Token() throws TokenVerifier.VerificationException, IOException {
    HttpTransportFactory httpTransportFactory =
        mockTransport(
            "https://www.googleapis.com/oauth2/v3/certs",
            readResourceAsString("federated_keys.json"));
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setClock(FIXED_CLOCK)
            .setHttpTransportFactory(httpTransportFactory)
            .build();
    assertNotNull(tokenVerifier.verify(FEDERATED_SIGNON_RS256_TOKEN));
  }

  @Test
  public void verifyRs256TokenWithLegacyCertificateUrlFormat()
      throws TokenVerifier.VerificationException, IOException {
    HttpTransportFactory httpTransportFactory =
        mockTransport(
            LEGACY_FEDERATED_SIGNON_CERT_URL, readResourceAsString("legacy_federated_keys.json"));
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setCertificatesLocation(LEGACY_FEDERATED_SIGNON_CERT_URL)
            .setClock(FIXED_CLOCK)
            .setHttpTransportFactory(httpTransportFactory)
            .build();
    assertNotNull(tokenVerifier.verify(FEDERATED_SIGNON_RS256_TOKEN));
  }

  @Test
  public void verifyServiceAccountRs256Token()
      throws TokenVerifier.VerificationException, IOException {
    HttpTransportFactory httpTransportFactory =
        mockTransport(SERVICE_ACCOUNT_CERT_URL, readResourceAsString("service_account_keys.json"));
    TokenVerifier tokenVerifier =
        TokenVerifier.newBuilder()
            .setClock(FIXED_CLOCK)
            .setCertificatesLocation(SERVICE_ACCOUNT_CERT_URL)
            .build();
    assertNotNull(tokenVerifier.verify(SERVICE_ACCOUNT_RS256_TOKEN));
  }

  static String readResourceAsString(String resourceName) throws IOException {
    InputStream inputStream =
        TokenVerifierTest.class.getClassLoader().getResourceAsStream(resourceName);
    try (final Reader reader = new InputStreamReader(inputStream)) {
      return CharStreams.toString(reader);
    }
  }

  static HttpTransportFactory mockTransport(String url, String certificates) {
    final String certificatesContent = certificates;
    final String certificatesUrl = url;
    return new HttpTransportFactory() {
      @Override
      public HttpTransport create() {
        return new MockHttpTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            assertEquals(certificatesUrl, url);
            return new MockLowLevelHttpRequest() {
              @Override
              public LowLevelHttpResponse execute() throws IOException {
                MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
                response.setStatusCode(200);
                response.setContentType("application/json");
                response.setContent(certificatesContent);
                return response;
              }
            };
          }
        };
      }
    };
  }
}
