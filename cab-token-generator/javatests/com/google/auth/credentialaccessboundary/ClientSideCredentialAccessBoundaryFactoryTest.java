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

package com.google.auth.credentialaccessboundary;

import static com.google.auth.oauth2.OAuth2Utils.TOKEN_EXCHANGE_URL_FORMAT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.auth.Credentials;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.MockStsTransport;
import com.google.auth.oauth2.MockTokenServerTransportFactory;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link com.google.auth.oauth2.DownscopedCredentials}. */
@RunWith(JUnit4.class)
public class ClientSideCredentialAccessBoundaryFactoryTest {
  private static final String SA_PRIVATE_KEY_PKCS8 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALX0PQoe1igW12i"
          + "kv1bN/r9lN749y2ijmbc/mFHPyS3hNTyOCjDvBbXYbDhQJzWVUikh4mvGBA07qTj79Xc3yBDfKP2IeyYQIFe0t0"
          + "zkd7R9Zdn98Y2rIQC47aAbDfubtkU1U72t4zL11kHvoa0/RuFZjncvlr42X7be7lYh4p3NAgMBAAECgYASk5wDw"
          + "4Az2ZkmeuN6Fk/y9H+Lcb2pskJIXjrL533vrDWGOC48LrsThMQPv8cxBky8HFSEklPpkfTF95tpD43iVwJRB/Gr"
          + "CtGTw65IfJ4/tI09h6zGc4yqvIo1cHX/LQ+SxKLGyir/dQM925rGt/VojxY5ryJR7GLbCzxPnJm/oQJBANwOCO6"
          + "D2hy1LQYJhXh7O+RLtA/tSnT1xyMQsGT+uUCMiKS2bSKx2wxo9k7h3OegNJIu1q6nZ6AbxDK8H3+d0dUCQQDTrP"
          + "SXagBxzp8PecbaCHjzNRSQE2in81qYnrAFNB4o3DpHyMMY6s5ALLeHKscEWnqP8Ur6X4PvzZecCWU9BKAZAkAut"
          + "LPknAuxSCsUOvUfS1i87ex77Ot+w6POp34pEX+UWb+u5iFn2cQacDTHLV1LtE80L8jVLSbrbrlH43H0DjU5AkEA"
          + "gidhycxS86dxpEljnOMCw8CKoUBd5I880IUahEiUltk7OLJYS/Ts1wbn3kPOVX3wyJs8WBDtBkFrDHW2ezth2QJ"
          + "ADj3e1YhMVdjJW5jqwlD/VNddGjgzyunmiZg0uOXsHXbytYmsA545S8KRQFaJKFXYYFo2kOjqOiC1T2cAzMDjCQ"
          + "==\n-----END PRIVATE KEY-----\n";

  static class MockStsTransportFactory implements HttpTransportFactory {

    MockStsTransport transport = new MockStsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void refreshCredentials() throws Exception {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    transportFactory.transport.setReturnAccessBoundarySessionKey(true);
    GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);

    ClientSideCredentialAccessBoundaryFactory factory =
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setSourceCredential(sourceCredentials)
            .setHttpTransportFactory(transportFactory)
            .build();

    factory.refreshCredentials();

    // Verify requested token type.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getRequest().getContentAsString());
    assertEquals(
        OAuth2Utils.TOKEN_TYPE_ACCESS_BOUNDARY_INTERMEDIARY_TOKEN,
        query.get("requested_token_type"));

    // Verify intermediate token and session key.
    AccessToken intermediateAccessToken = factory.getIntermediateAccessToken();
    String accessBoundarySessionKey = factory.getAccessBoundarySessionKey();
    assertEquals(
        transportFactory.transport.getAccessBoundarySessionKey(), accessBoundarySessionKey);
    assertEquals(
        transportFactory.transport.getAccessToken(), intermediateAccessToken.getTokenValue());
  }

  @Test
  public void refreshCredentials_withCustomUniverseDomain() throws IOException {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    String universeDomain = "foobar";
    GoogleCredentials sourceCredentials =
        getServiceAccountSourceCredentials(/* canRefresh= */ true)
            .toBuilder()
            .setUniverseDomain(universeDomain)
            .build();

    ClientSideCredentialAccessBoundaryFactory factory =
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setUniverseDomain(universeDomain)
            .setSourceCredential(sourceCredentials)
            .setHttpTransportFactory(transportFactory)
            .build();

    factory.refreshCredentials();

    // Verify domain.
    String url = transportFactory.transport.getRequest().getUrl();
    assertEquals(url, String.format(TOKEN_EXCHANGE_URL_FORMAT, universeDomain));
  }

  @Test
  public void refreshCredentials_sourceCredentialCannotRefresh_throwsIOException()
      throws Exception {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(false);

    ClientSideCredentialAccessBoundaryFactory factory =
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setSourceCredential(sourceCredentials)
            .setHttpTransportFactory(transportFactory)
            .build();

    try {
      factory.refreshCredentials(); // Expecting an IOException
      fail("Should fail as the source credential should not be able to be refreshed.");
    } catch (IOException e) {
      assertEquals("Unable to refresh the provided source credential.", e.getMessage());
    }
  }

  @Test
  public void refreshCredentials_noExpiresInReturned_copiesSourceExpiration() throws Exception {

    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    transportFactory.transport.setReturnExpiresIn(false); // Simulate STS not returning expires_in

    GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);

    ClientSideCredentialAccessBoundaryFactory factory =
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setSourceCredential(sourceCredentials)
            .setHttpTransportFactory(transportFactory)
            .build();

    factory.refreshCredentials();
    AccessToken intermediateAccessToken = factory.getIntermediateAccessToken();

    assertEquals(
        transportFactory.transport.getAccessToken(), intermediateAccessToken.getTokenValue());

    // Validate that the expires_in has been copied from the source credential.
    assertEquals(
        Objects.requireNonNull(sourceCredentials.getAccessToken()).getExpirationTime(),
        intermediateAccessToken.getExpirationTime());
  }

  /** Tests for {@link ClientSideCredentialAccessBoundaryFactory.Builder}. */
  public static class BuilderTest {
    @Test
    public void builder_noSourceCredential_throws() {
      try {
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
            .build();
        fail("Should fail as the source credential is null.");
      } catch (NullPointerException e) {
        assertEquals("Source credential must not be null.", e.getMessage());
      }
    }

    @Test
    public void builder_minimumTokenLifetime_negative_throws() throws IOException {
      GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  ClientSideCredentialAccessBoundaryFactory.newBuilder()
                      .setSourceCredential(sourceCredentials)
                      .setMinimumTokenLifetime(Duration.ofMinutes(-1)));

      assertEquals("Minimum token lifetime must be positive.", exception.getMessage());
    }

    @Test
    public void builder_minimumTokenLifetime_zero_throws() throws IOException {
      GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  ClientSideCredentialAccessBoundaryFactory.newBuilder()
                      .setSourceCredential(sourceCredentials)
                      .setMinimumTokenLifetime(Duration.ZERO));

      assertEquals("Minimum token lifetime must be positive.", exception.getMessage());
    }

    @Test
    public void builder_refreshMargin_negative_throws() throws IOException {
      GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  ClientSideCredentialAccessBoundaryFactory.newBuilder()
                      .setSourceCredential(sourceCredentials)
                      .setRefreshMargin(Duration.ofMinutes(-1)));

      assertEquals("Refresh margin must be positive.", exception.getMessage());
    }

    @Test
    public void builder_refreshMargin_zero_throws() throws IOException {
      GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  ClientSideCredentialAccessBoundaryFactory.newBuilder()
                      .setSourceCredential(sourceCredentials)
                      .setRefreshMargin(Duration.ZERO));

      assertEquals("Refresh margin must be positive.", exception.getMessage());
    }

    @Test
    public void builder_setsCorrectDefaultValues() throws IOException {
      GoogleCredentials sourceCredentials = getServiceAccountSourceCredentials(true);
      ClientSideCredentialAccessBoundaryFactory factory =
          ClientSideCredentialAccessBoundaryFactory.newBuilder()
              .setSourceCredential(sourceCredentials)
              .build();

      assertEquals(OAuth2Utils.HTTP_TRANSPORT_FACTORY, factory.getTransportFactory());
      assertEquals(
          String.format(OAuth2Utils.TOKEN_EXCHANGE_URL_FORMAT, Credentials.GOOGLE_DEFAULT_UNIVERSE),
          factory.getTokenExchangeEndpoint());
    }

    @Test
    public void builder_universeDomainMismatch_throws() throws IOException {
      GoogleCredentials sourceCredentials =
          getServiceAccountSourceCredentials(/* canRefresh= */ true);

      try {
        ClientSideCredentialAccessBoundaryFactory.newBuilder()
            .setSourceCredential(sourceCredentials)
            .setUniverseDomain("differentUniverseDomain")
            .build();

        fail("Should fail with universe domain mismatch.");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "The client side access boundary credential's universe domain must be the same as the source credential.",
            e.getMessage());
      }
    }
  }

  private static GoogleCredentials getServiceAccountSourceCredentials(boolean canRefresh)
      throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();

    String email = "service-account@google.com";

    ServiceAccountCredentials sourceCredentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(email)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId("privateKeyId")
            .setProjectId("projectId")
            .setHttpTransportFactory(transportFactory)
            .build();

    transportFactory.transport.addServiceAccount(email, "accessToken");

    if (!canRefresh) {
      transportFactory.transport.setError(new IOException());
    }

    return sourceCredentials.createScoped("https://www.googleapis.com/auth/cloud-platform");
  }
}
