package com.google.auth.oauth2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.auth.ServiceAccountSigner;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mockito;

@RunWith(JUnit4.class)
public class IamUtilsTest {

  private static final String CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";

  @Test
  public void sign_noRetry() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    // Mock this call because signing requires an access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setSignedBlob(expectedSignature);
    transportFactory.transport.setTargetPrincipal(CLIENT_EMAIL);

    byte[] signature =
        IamUtils.sign(
            CLIENT_EMAIL,
            credentials,
            transportFactory.transport,
            expectedSignature,
            ImmutableMap.of());
    assertArrayEquals(expectedSignature, signature);
  }

  @Test
  public void sign_4xxServerError_exception() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    // Mock this call because signing requires an access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setSignedBlob(expectedSignature);
    transportFactory.transport.setTargetPrincipal(CLIENT_EMAIL);
    transportFactory.transport.setErrorResponseCodeAndMessage(
        HttpStatusCodes.STATUS_CODE_UNAUTHORIZED, "Failed to sign the provided bytes");

    ServiceAccountSigner.SigningException exception =
        assertThrows(
            ServiceAccountSigner.SigningException.class,
            () ->
                IamUtils.sign(
                    CLIENT_EMAIL,
                    credentials,
                    transportFactory.transport,
                    expectedSignature,
                    ImmutableMap.of()));
    assertTrue(exception.getMessage().contains("Failed to sign the provided bytes"));
    assertTrue(
        exception
            .getCause()
            .getMessage()
            .contains("Error code 401 trying to sign provided bytes:"));
  }
}
