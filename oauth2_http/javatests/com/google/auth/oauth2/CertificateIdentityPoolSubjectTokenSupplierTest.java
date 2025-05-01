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
import static org.mockito.Mockito.when;

import com.google.auth.oauth2.IdentityPoolCredentialSource.CertificateConfig;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link CertificateIdentityPoolSubjectTokenSupplier}. */
@RunWith(JUnit4.class)
public class CertificateIdentityPoolSubjectTokenSupplierTest {

  @Rule public MockitoRule mockitoRule = MockitoJUnit.rule();

  @Mock private IdentityPoolCredentialSource mockCredentialSource;
  @Mock private CertificateConfig mockCertificateConfig;
  @Mock private ExternalAccountSupplierContext mockContext;

  private CertificateIdentityPoolSubjectTokenSupplier supplier;
  private static final Gson GSON = new Gson();

  private static final byte[] INVALID_CERT_BYTES =
      "invalid certificate data".getBytes(StandardCharsets.UTF_8);

  private byte[] testCertBytesFromFile;

  @Before
  public void setUp() throws IOException, URISyntaxException {
    ClassLoader classLoader = getClass().getClassLoader();
    URL leafCertUrl = classLoader.getResource("x509_leaf_certificate.pem");
    assertNotNull("Test leaf certificate file not found!", leafCertUrl);
    File testCertFile = new File(leafCertUrl.getFile());

    when(mockCertificateConfig.useDefaultCertificateConfig()).thenReturn(false);
    when(mockCertificateConfig.getCertificateConfigLocation())
        .thenReturn(testCertFile.getAbsolutePath());

    when(mockCredentialSource.getCertificateConfig()).thenReturn(mockCertificateConfig);
    when(mockCredentialSource.getCredentialLocation()).thenReturn(testCertFile.getAbsolutePath());

    supplier = new CertificateIdentityPoolSubjectTokenSupplier(mockCredentialSource);
    testCertBytesFromFile = Files.readAllBytes(Paths.get(leafCertUrl.toURI()));
  }

  @Test
  public void parseCertificate_validData_returnsCertificate() throws Exception {
    X509Certificate cert =
        CertificateIdentityPoolSubjectTokenSupplier.parseCertificate(testCertBytesFromFile);
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
    // Calculate expected result based on the file content.
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate expectedCert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(testCertBytesFromFile));
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
