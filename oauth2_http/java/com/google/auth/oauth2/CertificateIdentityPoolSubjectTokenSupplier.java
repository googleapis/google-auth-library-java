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
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
   * {@code credentialSource.credentialLocation}. If a trust chain path is configured in the {@code
   * credentialSource.certificateConfig}, it also loads and includes the trust chain certificates.
   * The subject token is constructed as a JSON array containing the base64-encoded (DER format)
   * leaf certificate, followed by the base64-encoded (DER format) certificates in the trust chain.
   * This JSON array serves as the subject token for mTLS authentication.
   *
   * @param context The external account supplier context. This parameter is currently not used in
   *     this implementation.
   * @return The JSON string representation of the base64-encoded certificate chain (leaf
   *     certificate followed by the trust chain, if present).
   * @throws IOException If an I/O error occurs while reading the certificate file(s).
   */
  @Override
  public String getSubjectToken(ExternalAccountSupplierContext context) throws IOException {
    String leafCertPath = credentialSource.getCredentialLocation();
    String trustChainPath = null;
    if (credentialSource.getCertificateConfig() != null) {
      trustChainPath = credentialSource.getCertificateConfig().getTrustChainPath();
    }

    try {
      // Load the leaf certificate.
      X509Certificate leafCert = loadLeafCertificate(leafCertPath);
      String encodedLeafCert = encodeCert(leafCert);

      // Add the leaf certificate first.
      java.util.List<String> certChain = new java.util.ArrayList<>();
      certChain.add(encodedLeafCert);

      // Read the trust chain.
      List<X509Certificate> trustChainCerts = readTrustChain(trustChainPath);

      // Process the trust chain certificates read from the file.
      if (!trustChainCerts.isEmpty()) {
        // Check the first certificate in the trust chain file.
        X509Certificate firstTrustCert = trustChainCerts.get(0);
        String encodedFirstTrustCert = encodeCert(firstTrustCert);

        // Add the first certificate only if it is not the same as the leaf certificate.
        if (!encodedFirstTrustCert.equals(encodedLeafCert)) {
          certChain.add(encodedFirstTrustCert);
        }

        // Iterate over the remaining certificates in the trust chain.
        for (int i = 1; i < trustChainCerts.size(); i++) {
          X509Certificate currentCert = trustChainCerts.get(i);
          String encodedCurrentCert = encodeCert(currentCert);

          // Throw an error if the current certificate is the same as the leaf certificate.
          if (encodedCurrentCert.equals(encodedLeafCert)) {
            throw new IllegalArgumentException(
                "The leaf certificate should only appear at the beginning of the trust chain file, or be omitted entirely.");
          }

          // Add the current certificate to the chain.
          certChain.add(encodedCurrentCert);
        }
      }

      return OAuth2Utils.JSON_FACTORY.toString(certChain);
    }
    // The following catch blocks handle specific exceptions that can occur during
    // certificate loading and parsing. These exceptions are wrapped in a new IOException,
    // as declared by this method's signature.
    catch (NoSuchFileException e) {
      // Handles the case where the leaf certificate file itself cannot be found.
      throw new IOException(String.format("Leaf certificate file not found: %s", leafCertPath), e);
    } catch (CertificateException e) {
      // Handles errors during the parsing of certificate data, which could stem from
      // issues in either the leaf certificate or the trust chain. The message includes
      // paths to both for comprehensive error reporting.
      throw new IOException(
          "Failed to read certificate file(s). Leaf path: "
              + leafCertPath
              + (trustChainPath != null ? "\nTrust chain path: " + trustChainPath : ""),
          e);
    }
  }

  /**
   * Reads a file containing PEM-encoded X509 certificates and returns a list of parsed
   * certificates. It splits the file content based on PEM headers and parses each certificate.
   * Returns an empty list if the trust chain path is empty.
   *
   * @param trustChainPath The path to the trust chain file.
   * @return A list of parsed X509 certificates.
   * @throws IOException If an error occurs while reading the file.
   * @throws CertificateException If an error occurs while parsing a certificate.
   */
  @VisibleForTesting
  static List<X509Certificate> readTrustChain(String trustChainPath)
      throws IOException, CertificateException {
    List<X509Certificate> certificateTrustChain = new ArrayList<>();

    // If no trust chain path is provided, return an empty list.
    if (trustChainPath == null || trustChainPath.isEmpty()) {
      return certificateTrustChain;
    }

    // initialize certificate factory to retrieve x509 certificates.
    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    // Read the trust chain file.
    byte[] trustChainData;
    try {
      trustChainData = Files.readAllBytes(Paths.get(trustChainPath));
    } catch (NoSuchFileException e) {
      throw new IOException("Trust chain file not found: " + trustChainPath, e);
    } catch (IOException e) {
      throw new IOException("Failed to read trust chain file: " + trustChainPath, e);
    }

    // Split the file content into PEM certificate blocks.
    String content = new String(trustChainData);
    Pattern pemCertPattern =
        Pattern.compile("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Pattern.DOTALL);
    Matcher matcher = pemCertPattern.matcher(content);

    while (matcher.find()) {
      String pemCertBlock = matcher.group(0);
      try (InputStream certStream = new ByteArrayInputStream(pemCertBlock.getBytes())) {
        // Parse the certificate data.
        Certificate cert = cf.generateCertificate(certStream);

        // Append the certificate to the trust chain.
        if (cert instanceof X509Certificate) {
          certificateTrustChain.add((X509Certificate) cert);
        } else {
          throw new CertificateException(
              "Found non-X.509 certificate in trust chain file: " + trustChainPath);
        }
      } catch (CertificateException e) {
        // If parsing an individual PEM block fails, re-throw with more context.
        throw new CertificateException(
            "Error loading PEM certificates from the trust chain file: "
                + trustChainPath
                + " - "
                + e.getMessage(),
            e);
      }
    }

    if (trustChainData.length > 0 && certificateTrustChain.isEmpty()) {
      throw new CertificateException(
          "Trust chain file was not empty but no PEM certificates were found: " + trustChainPath);
    }

    return certificateTrustChain;
  }
}
