/*
 * Copyright 2025, Google LLC
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

import static org.junit.Assert.*;

import com.google.auth.oauth2.IdentityPoolCredentialSource.CertificateConfig;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link CertificateIdentityPoolSubjectTokenSupplier}. */
@RunWith(JUnit4.class)
public class CertificateIdentityPoolSubjectTokenSupplierTest {

  @Rule public MockitoRule mockitoRule = MockitoJUnit.rule();
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();

  @Mock private IdentityPoolCredentialSource mockCredentialSource;
  @Mock private CertificateConfig mockCertificateConfig;
  @Mock private ExternalAccountSupplierContext mockContext;

  private CertificateIdentityPoolSubjectTokenSupplier supplier;
  private static final Gson GSON = new Gson();

  // Certificate data from X509ProviderTest
  private static final String TEST_CERT_PEM =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICGzCCAYSgAwIBAgIIWrt6xtmHPs4wDQYJKoZIhvcNAQEFBQAwMzExMC8GA1UE\n"
          + "AxMoMTAwOTEyMDcyNjg3OC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbTAeFw0x\n"
          + "MjEyMDExNjEwNDRaFw0yMjExMjkxNjEwNDRaMDMxMTAvBgNVBAMTKDEwMDkxMjA3\n"
          + "MjY4NzguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20wgZ8wDQYJKoZIhvcNAQEB\n"
          + "BQADgY0AMIGJAoGBAL1SdY8jTUVU7O4/XrZLYTw0ON1lV6MQRGajFDFCqD2Fd9tQ\n"
          + "GLW8Iftx9wfXe1zuaehJSgLcyCxazfyJoN3RiONBihBqWY6d3lQKqkgsRTNZkdFJ\n"
          + "Wdzl/6CxhK9sojh2p0r3tydtv9iwq5fuuWIvtODtT98EgphhncQAqkKoF3zVAgMB\n"
          + "AAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQM\n"
          + "MAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBAD8XQEqzGePa9VrvtEGpf+R4\n"
          + "fkxKbcYAzqYq202nKu0kfjhIYkYSBj6gi348YaxE64yu60TVl42l5HThmswUheW4\n"
          + "uQIaq36JvwvsDP5Zoj5BgiNSnDAFQp+jJFBRUA5vooJKgKgMDf/r/DCOsbO6VJF1\n"
          + "kWwa9n19NFiV0z3m6isj\n"
          + "-----END CERTIFICATE-----\n";

  private static final byte[] TEST_CERT_BYTES = TEST_CERT_PEM.getBytes(StandardCharsets.UTF_8);
  private static final byte[] INVALID_CERT_BYTES =
      "invalid certificate data".getBytes(StandardCharsets.UTF_8);

  @Before
  public void setUp() throws IOException {
    File testCertFile = tempFolder.newFile("certificate.pem");
    Files.write(testCertFile.toPath(), TEST_CERT_BYTES);
    mockCredentialSource.certificateConfig = mockCertificateConfig;
    mockCredentialSource.credentialLocation = testCertFile.getAbsolutePath();
    supplier = new CertificateIdentityPoolSubjectTokenSupplier(mockCredentialSource);
  }

  @Test
  public void parseCertificate_validData_returnsCertificate() throws Exception {
    X509Certificate cert =
        CertificateIdentityPoolSubjectTokenSupplier.parseCertificate(TEST_CERT_BYTES);
    assertNotNull(cert);
  }

  @Test
  public void parseCertificate_emptyData_throwsIllegalArgumentException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificateIdentityPoolSubjectTokenSupplier.parseCertificate(new byte[0]));
    assertEquals("Invalid certificate data: empty or null input", exception.getMessage());
  }

  @Test
  public void parseCertificate_nullData_throwsIllegalArgumentException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificateIdentityPoolSubjectTokenSupplier.parseCertificate(null));
    assertEquals("Invalid certificate data: empty or null input", exception.getMessage());
  }

  @Test
  public void parseCertificate_invalidData_throwsCertificateException() {
    CertificateException exception =
        assertThrows(
            CertificateException.class,
            () -> CertificateIdentityPoolSubjectTokenSupplier.parseCertificate(INVALID_CERT_BYTES));
    assertEquals("Failed to parse X.509 certificate data.", exception.getMessage());
  }

  @Test
  public void getSubjectToken_success() throws Exception {
    // Calculate expected result
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate expectedCert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(TEST_CERT_BYTES));
    String expectedEncodedDer = Base64.getEncoder().encodeToString(expectedCert.getEncoded());
    JsonArray expectedJsonArray = new JsonArray();
    expectedJsonArray.add(new JsonPrimitive(expectedEncodedDer));
    String expectedSubjectToken = GSON.toJson(expectedJsonArray);

    // Execute
    String actualSubjectToken = supplier.getSubjectToken(mockContext);

    // Verify
    assertEquals(expectedSubjectToken, actualSubjectToken);
  }
}
