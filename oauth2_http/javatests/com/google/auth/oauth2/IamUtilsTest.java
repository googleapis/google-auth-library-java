/*
 * Copyright 2024, Google Inc. All rights reserved.
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

    // Mock this call because signing requires an access token. The call is initialized with
    // HttpCredentialsAdapter which will make a call to get the access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setSignedBlob(expectedSignature);
    transportFactory.transport.setTargetPrincipal(CLIENT_EMAIL);
    transportFactory.transport.addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");

    byte[] signature =
        IamUtils.sign(
            CLIENT_EMAIL,
            credentials,
            transportFactory.transport,
            expectedSignature,
            ImmutableMap.of());
    assertArrayEquals(expectedSignature, signature);
  }

  // The SignBlob RPC will retry up to three times before it gives up. This test will fail twice
  // before returning a success.
  @Test
  public void sign_retryTwoTimes_success() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    // Mock this call because signing requires an access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");
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

  // The rpc will retry up to three times before it gives up. This test will fail four times before
  // returning a success. After the third failure, the failure will be reported back to the user.
  @Test
  public void sign_retryFourTimes_exception() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    // Mock this call because signing requires an access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setSignedBlob(expectedSignature);
    transportFactory.transport.setTargetPrincipal(CLIENT_EMAIL);
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(502, "Bad Gateway");
    transportFactory.transport.addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");

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
            .contains("Unexpected Error code 502 trying to sign provided bytes"));
  }

  @Test
  public void sign_4xxServerError_exception() throws IOException {
    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    // Mock this call because signing requires an access token. The call is initialized with
    // HttpCredentialsAdapter which will make a call to get the access token
    ServiceAccountCredentials credentials = Mockito.mock(ServiceAccountCredentials.class);
    Mockito.when(credentials.getRequestMetadata(Mockito.any())).thenReturn(ImmutableMap.of());

    ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory transportFactory =
        new ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setSignedBlob(expectedSignature);
    transportFactory.transport.setTargetPrincipal(CLIENT_EMAIL);
    transportFactory.transport.addStatusCodeAndMessage(
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
