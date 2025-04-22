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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Provider for retrieving subject tokens for {@link IdentityPoolCredentials} by reading an X.509
 * certificate from the filesystem. The certificate file (e.g., PEM or DER encoded) is read, the
 * leaf certificate is base64-encoded (DER format), wrapped in a JSON array, and used as the subject
 * token for STS exchange.
 */
public class CertificateIdentityPoolSubjectTokenSupplier
    implements IdentityPoolSubjectTokenSupplier {

  private static final Gson GSON = new Gson();
  private final IdentityPoolCredentialSource credentialSource;

  CertificateIdentityPoolSubjectTokenSupplier(IdentityPoolCredentialSource credentialSource) {
    this.credentialSource = checkNotNull(credentialSource, "credentialSource cannot be null");
    // This check ensures that the credential source was intended for certificate usage.
    // IdentityPoolCredentials logic should guarantee credentialLocation is set in this case.
    checkNotNull(
        credentialSource.certificateConfig,
        "credentialSource.certificateConfig cannot be null when creating"
            + " CertificateIdentityPoolSubjectTokenSupplier");
  }

  private static X509Certificate loadLeafCertificate(String path)
      throws IOException, CertificateException {
    byte[] leafCertBytes;
    try {
      // IdentityPoolCredentials should have already validated the path exists via X509Provider.
      leafCertBytes = Files.readAllBytes(Paths.get(path));
    } catch (InvalidPathException e) {
      throw new IOException("Invalid certificate file path provided: " + path, e);
    }
    // Files.readAllBytes throws IOException for other read errors.
    return parseCertificate(leafCertBytes);
  }

  private static X509Certificate parseCertificate(byte[] certData) throws CertificateException {
    if (certData == null || certData.length == 0) {
      throw new IllegalArgumentException("Invalid certificate data: empty or null input");
    }

    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      InputStream certificateStream = new ByteArrayInputStream(certData);
      return (X509Certificate) certificateFactory.generateCertificate(certificateStream);
    } catch (CertificateException e) {
      throw new CertificateException("Failed to parse X.509 certificate data.", e);
    }
  }

  private static String encodeCert(X509Certificate certificate)
      throws CertificateEncodingException {
    return Base64.getEncoder().encodeToString(certificate.getEncoded());
  }

  @Override
  public String getSubjectToken(ExternalAccountSupplierContext context) throws IOException {
    try {
      // credentialSource.credentialLocation is expected to be non-null here,
      // set during IdentityPoolCredentials construction for certificate type.
      X509Certificate leafCert = loadLeafCertificate(credentialSource.credentialLocation);
      String encodedCert = encodeCert(leafCert);

      JsonArray certChain = new JsonArray();
      certChain.add(new JsonPrimitive(encodedCert));

      return GSON.toJson(certChain);
    } catch (CertificateException e) {
      throw new IOException(
          "Failed to parse certificate from: " + credentialSource.credentialLocation, e);
    }
  }
}
