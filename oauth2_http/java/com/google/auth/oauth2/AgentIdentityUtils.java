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

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/** Internal utility class for handling Agent Identity certificate-bound access tokens. */
final class AgentIdentityUtils {
  private static final Logger LOGGER = Logger.getLogger(AgentIdentityUtils.class.getName());

  static final String GOOGLE_API_CERTIFICATE_CONFIG = "GOOGLE_API_CERTIFICATE_CONFIG";
  static final String GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES =
      "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES";

  private static final List<Pattern> AGENT_IDENTITY_SPIFFE_PATTERNS =
      ImmutableList.of(
          Pattern.compile("^agents\\.global\\.org-\\d+\\.system\\.id\\.goog$"),
          Pattern.compile("^agents\\.global\\.proj-\\d+\\.system\\.id\\.goog$"));

  // Polling configuration
  static long TOTAL_TIMEOUT_MS = 30000; // 30 seconds
  static long FAST_POLL_DURATION_MS = 5000; // 5 seconds
  static long FAST_POLL_INTERVAL_MS = 100; // 0.1 seconds
  static long SLOW_POLL_INTERVAL_MS = 500; // 0.5 seconds

  private static final int SAN_URI_TYPE = 6;
  private static final String SPIFFE_SCHEME_PREFIX = "spiffe://";

  // Interface to allow mocking System.getenv for tests without exposing it publicly.
  interface EnvReader {
    String getEnv(String name);
  }

  private static EnvReader envReader = System::getenv;

  private AgentIdentityUtils() {}

  /**
   * Gets the Agent Identity certificate if available and enabled.
   *
   * @return The X509Certificate if found and Agent Identities are enabled, null otherwise.
   * @throws IOException If there is an error reading the certificate file after retries.
   */
  static X509Certificate getAgentIdentityCertificate() throws IOException {
    if (isOptedOut()) {
      return null;
    }

    String certConfigPath = envReader.getEnv(GOOGLE_API_CERTIFICATE_CONFIG);
    if (Strings.isNullOrEmpty(certConfigPath)) {
      return null;
    }

    String certPath = getCertificatePathWithRetry(certConfigPath);
    return parseCertificate(certPath);
  }

  /** Checks if the user has opted out of Agent Token sharing. */
  private static boolean isOptedOut() {
    String optOut = envReader.getEnv(GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES);
    return optOut != null && "false".equalsIgnoreCase(optOut);
  }

  /** Polls for the certificate config file and the certificate file it references. */
  private static String getCertificatePathWithRetry(String certConfigPath) throws IOException {
    long startTime = System.currentTimeMillis();
    boolean warned = false;

    while (true) {
      try {
        if (Files.exists(Paths.get(certConfigPath))) {
          String certPath = extractCertPathFromConfig(certConfigPath);
          if (!Strings.isNullOrEmpty(certPath) && Files.exists(Paths.get(certPath))) {
            return certPath;
          }
        }
      } catch (Exception e) {
        // Ignore exceptions during polling and retry
        LOGGER.log(Level.FINE, "Error while polling for certificate files", e);
      }

      long elapsedTime = System.currentTimeMillis() - startTime;
      if (elapsedTime >= TOTAL_TIMEOUT_MS) {
        throw new IOException(
            "Certificate config or certificate file not found after multiple retries. "
                + "Token binding protection is failing. You can turn off this protection by setting "
                + GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES
                + " to false to fall back to unbound tokens.");
      }

      if (!warned) {
        LOGGER.warning(
            String.format(
                "Certificate config file not found at %s (from %s environment variable). "
                    + "Retrying for up to %d seconds.",
                certConfigPath, GOOGLE_API_CERTIFICATE_CONFIG, TOTAL_TIMEOUT_MS / 1000));
        warned = true;
      }

      try {
        long sleepTime =
            elapsedTime < FAST_POLL_DURATION_MS ? FAST_POLL_INTERVAL_MS : SLOW_POLL_INTERVAL_MS;
        Thread.sleep(sleepTime);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while waiting for certificate files", e);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static String extractCertPathFromConfig(String certConfigPath) throws IOException {
    try (InputStream stream = new FileInputStream(certConfigPath)) {
      JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
      GenericJson config = parser.parseAndClose(stream, StandardCharsets.UTF_8, GenericJson.class);
      Map<String, Object> certConfigs = (Map<String, Object>) config.get("cert_configs");
      if (certConfigs != null) {
        Map<String, Object> workload = (Map<String, Object>) certConfigs.get("workload");
        if (workload != null) {
          return (String) workload.get("cert_path");
        }
      }
    }
    return null;
  }

  private static X509Certificate parseCertificate(String certPath) throws IOException {
    try (InputStream stream = new FileInputStream(certPath)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(stream);
    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to parse certificate", e);
    }
  }

  /** Checks if the certificate belongs to an Agent Identity by inspecting SANs. */
  static boolean shouldRequestBoundToken(X509Certificate cert) {
    try {
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans == null) {
        return false;
      }
      for (List<?> san : sans) {
        // SAN entry is a list where first element is the type (Integer) and second is value (mostly
        // String)
        if (san.size() >= 2
            && san.get(0) instanceof Integer
            && (Integer) san.get(0) == SAN_URI_TYPE) {
          Object value = san.get(1);
          if (value instanceof String) {
            String uri = (String) value;
            if (uri.startsWith(SPIFFE_SCHEME_PREFIX)) {
              // Extract trust domain: spiffe://<trust_domain>/...
              String withoutScheme = uri.substring(SPIFFE_SCHEME_PREFIX.length());
              int slashIndex = withoutScheme.indexOf('/');
              String trustDomain =
                  (slashIndex == -1) ? withoutScheme : withoutScheme.substring(0, slashIndex);

              for (Pattern pattern : AGENT_IDENTITY_SPIFFE_PATTERNS) {
                if (pattern.matcher(trustDomain).matches()) {
                  return true;
                }
              }
            }
          }
        }
      }
    } catch (CertificateParsingException e) {
      LOGGER.log(Level.WARNING, "Failed to parse Subject Alternative Names from certificate", e);
    }
    return false;
  }

  /** Calculates the SHA-256 fingerprint of the certificate, Base64Url encoded without padding. */
  static String calculateCertificateFingerprint(X509Certificate cert) throws IOException {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] der = cert.getEncoded();
      md.update(der);
      byte[] digest = md.digest();
      return BaseEncoding.base64Url().omitPadding().encode(digest);
    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to calculate certificate fingerprint", e);
    }
  }

  @VisibleForTesting
  static void setEnvReader(EnvReader reader) {
    envReader = reader;
  }
}
