/*
 * Copyright 2025 Google LLC
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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.VisibleForTesting;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Provider for retrieving the subject tokens for {@link IdentityPoolCredentials} by reading an
 * X.509 certificate from the filesystem. The certificate file (e.g., PEM or DER encoded) is read,
 * the leaf certificate is base64-encoded (DER format), wrapped in a JSON array, and used as the
 * subject token for STS exchange.
 */
public class CertificateIdentityPoolSubjectTokenSupplier
    implements IdentityPoolSubjectTokenSupplier {

  private final IdentityPoolCredentialSource credentialSource;

  CertificateIdentityPoolSubjectTokenSupplier(IdentityPoolCredentialSource credentialSource) {
    this.credentialSource = checkNotNull(credentialSource, "credentialSource cannot be null");
    // This check ensures that the credential source was intended for certificate usage.
    // IdentityPoolCredentials logic should guarantee credentialLocation is set in this case.
    checkNotNull(
        credentialSource.getCertificateConfig(),
        "credentialSource.certificateConfig cannot be null when creating"
            + " CertificateIdentityPoolSubjectTokenSupplier");
  }

  private static X509Certificate loadLeafCertificate(String path)
      throws IOException, CertificateException {
    byte[] leafCertBytes = Files.readAllBytes(Paths.get(path));
    return parseCertificate(leafCertBytes);
  }

  @VisibleForTesting
  static X509Certificate parseCertificate(byte[] certData) throws CertificateException {
    if (certData == null || certData.length == 0) {
      throw new IllegalArgumentException(
          "Invalid certificate data: Certificate file is empty or null.");
    }

    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      InputStream certificateStream = new ByteArrayInputStream(certData);
      return (X509Certificate) certificateFactory.generateCertificate(certificateStream);
    } catch (CertificateException e) {
      // Catch the original exception to add context about the operation being performed.
      // This helps pinpoint the failure point during debugging.
      throw new CertificateException("Failed to parse X.509 certificate data.", e);
    }
  }

  private static String encodeCert(X509Certificate certificate)
      throws CertificateEncodingException {
    return Base64.getEncoder().encodeToString(certificate.getEncoded());
  }

  /**
   * Retrieves the X509 subject token. This method loads the leaf certificate specified by the
   * {@code credentialSource.credentialLocation}. The subject token is constructed as a JSON array
   * containing the base64-encoded (DER format) leaf certificate. This JSON array serves as the
   * subject token for mTLS authentication.
   *
   * @param context The external account supplier context. This parameter is currently not used in
   *     this implementation.
   * @return The JSON string representation of the base64-encoded leaf certificate in a JSON array.
   * @throws IOException If an I/O error occurs while reading the certificate file.
   */
  @Override
  public String getSubjectToken(ExternalAccountSupplierContext context) throws IOException {
    try {
      // credentialSource.credentialLocation is expected to be non-null here,
      // set during IdentityPoolCredentials construction for certificate type.
      X509Certificate leafCert = loadLeafCertificate(credentialSource.getCredentialLocation());
      String encodedLeafCert = encodeCert(leafCert);

      java.util.List<String> certChain = new java.util.ArrayList<>();
      certChain.add(encodedLeafCert);

      return OAuth2Utils.JSON_FACTORY.toString(certChain);
    } catch (CertificateException e) {
      // Catch CertificateException to provide a more specific error message including
      // the path of the file that failed to parse, and re-throw as IOException
      // as expected by the getSubjectToken method signature for I/O related issues.
      throw new IOException(
          "Failed to parse certificate(s) from: " + credentialSource.getCredentialLocation(), e);
    }
  }
}
