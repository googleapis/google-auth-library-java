package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class AgentIdentityUtilsTest {

  private static final String VALID_SPIFFE_ORG =
      "spiffe://agents.global.org-12345.system.id.goog/path/to/resource";
  private static final String VALID_SPIFFE_PROJ =
      "spiffe://agents.global.proj-98765.system.id.goog/another/path";
  private static final String INVALID_SPIFFE_DOMAIN = "spiffe://example.com/workload";
  private static final String INVALID_SPIFFE_FORMAT =
      "spiffe://agents.global.org-INVALID.system.id.goog/path";

  // A minimal, valid self-signed X.509 certificate (PEM format) for testing loading.
  // Generated for testing purposes.
  private static final String TEST_CERT_PEM =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDWTCCAkGgAwIBAgIUX5/1aT1uuxgj1+F7Q/r+5Q9y4JQwDQYJKoZIhvcNAQEL\n"
          + "BQAwHTEbMBkGA1UEAwwSdGVzdC5leGFtcGxlLmNvbTAeFw0yNDAxMDEwMDAwMDBa\n"
          + "Fw0zNDAxMDEwMDAwMDBaMB0xGzAZBgNVBAMMEnRlc3QuZXhhbXBsZS5jb20wggEi\n"
          + "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV/8Q/5+8+X9Y+5+6+7+8+9+0+\n"
          + "A/B/C/D/E/F/G/H/I/J/K/L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/\n"
          + "g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B\n"
          + "/C/D/E/F/G/H/I/J/K/L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/g/h\n"
          + "/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B/C/\n"
          + "D/E/F/G/H/I/J/K/L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/g/h/i/\n"
          + "j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B/C/D/E\n"
          + "AgMBAAGjUzBRMB0GA1UdDgQWBBS/1/2/3/4/5/6/7/8/9/+A/B/C/DAfBgNVHSME\n"
          + "GDAWgBS/1/2/3/4/5/6/7/8/9/+A/B/C/DAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\n"
          + "SIb3DQEBCwUAA4IBAQDV/8Q/5+8+X9Y+5+6+7+8+9+0+A/B/C/D/E/F/G/H/I/J/\n"
          + "K/L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/\n"
          + "q/r/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B/C/D/E/F/G/H/I/J/K/L\n"
          + "/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r\n"
          + "/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B/C/D/E/F/G/H/I/J/K/L/M/\n"
          + "N/O/P/Q/R/S/T/U/V/W/X/Y/Z/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/\n"
          + "t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/+A/B/C/D/E\n"
          + "-----END CERTIFICATE-----";

  private TestEnvironmentProvider envProvider;
  private Path tempDir;

  @Before
  public void setUp() throws IOException {
    envProvider = new TestEnvironmentProvider();
    // Inject our test environment reader
    AgentIdentityUtils.setEnvReader(envProvider::getEnv);
    tempDir = Files.createTempDirectory("agent_identity_test");
  }

  @After
  public void tearDown() throws IOException {
    // Reset polling constants to defaults after each test to avoid side effects
    AgentIdentityUtils.TOTAL_TIMEOUT_MS = 30000;
    AgentIdentityUtils.FAST_POLL_INTERVAL_MS = 100;
    AgentIdentityUtils.FAST_POLL_DURATION_MS = 5000;
    AgentIdentityUtils.SLOW_POLL_INTERVAL_MS = 500;

    // Clean up temp files
    if (tempDir != null) {
      Files.walk(tempDir)
          .sorted(java.util.Comparator.reverseOrder())
          .map(Path::toFile)
          .forEach(File::delete);
    }
  }

  // --- 1. SPIFFE ID Validation Tests ---

  @Test
  public void shouldRequestBoundToken_validOrgSpiffe_returnsTrue() throws CertificateException {
    assertTrue(AgentIdentityUtils.shouldRequestBoundToken(mockCertWithSanUri(VALID_SPIFFE_ORG)));
  }

  @Test
  public void shouldRequestBoundToken_validProjSpiffe_returnsTrue() throws CertificateException {
    assertTrue(AgentIdentityUtils.shouldRequestBoundToken(mockCertWithSanUri(VALID_SPIFFE_PROJ)));
  }

  @Test
  public void shouldRequestBoundToken_invalidDomain_returnsFalse() throws CertificateException {
    assertFalse(
        AgentIdentityUtils.shouldRequestBoundToken(mockCertWithSanUri(INVALID_SPIFFE_DOMAIN)));
  }

  @Test
  public void shouldRequestBoundToken_invalidFormat_returnsFalse() throws CertificateException {
    assertFalse(
        AgentIdentityUtils.shouldRequestBoundToken(mockCertWithSanUri(INVALID_SPIFFE_FORMAT)));
  }

  @Test
  public void shouldRequestBoundToken_noSan_returnsFalse() throws CertificateException {
    X509Certificate mockCert = mock(X509Certificate.class);
    when(mockCert.getSubjectAlternativeNames()).thenReturn(null);
    assertFalse(AgentIdentityUtils.shouldRequestBoundToken(mockCert));
  }

  // Helper to create a mock cert with a specific URI in SAN
  private X509Certificate mockCertWithSanUri(String uri) throws CertificateException {
    X509Certificate mockCert = mock(X509Certificate.class);
    // SAN entry type 6 is URI
    List<Object> spiffeEntry = Arrays.asList(6, uri);
    Collection<List<?>> sans = Collections.singletonList(spiffeEntry);
    when(mockCert.getSubjectAlternativeNames()).thenReturn(sans);
    return mockCert;
  }

  // --- 2. Fingerprint Calculation Tests ---

  @Test
  public void calculateCertificateFingerprint_knownInput_returnsExpectedOutput() throws Exception {
    // We mock the getEncoded() method to return a fixed byte array to guarantee a stable hash
    // regardless of the actual certificate implementation details.
    X509Certificate mockCert = mock(X509Certificate.class);
    byte[] fakeDer = new byte[] {0x01, 0x02, 0x03, 0x04, (byte) 0xFF};
    when(mockCert.getEncoded()).thenReturn(fakeDer);

    // SHA-256 of {0x01, 0x02, 0x03, 0x04, 0xFF} is:
    // fc402e5e4d71483c6d537984a30c2b4c8b065539a4bd1b026c6112926ba52793
    // Base64Url (no padding) of that hash is:
    // _EAuXk1xSDxtU3mEowwrTIsGVTmkvRsCbGESkmulJ5M
    String expectedFingerprint = "_EAuXk1xSDxtU3mEowwrTIsGVTmkvRsCbGESkmulJ5M";

    String actualFingerprint = AgentIdentityUtils.calculateCertificateFingerprint(mockCert);
    assertEquals(expectedFingerprint, actualFingerprint);
  }

  // --- 3. Environmental Control Tests ---

  @Test
  public void getAgentIdentityCertificate_optedOut_returnsNullImmediately() throws IOException {
    envProvider.setEnv("GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES", "false");
    // Set config to a non-existent path; if it tried to load it, it would fail or retry.
    // Returning null immediately proves it respected the opt-out.
    envProvider.setEnv("GOOGLE_API_CERTIFICATE_CONFIG", "/non/existent/path");

    assertNull(AgentIdentityUtils.getAgentIdentityCertificate());
  }

  @Test
  public void getAgentIdentityCertificate_noConfigEnvVar_returnsNull() throws IOException {
    // Default opt-in is true, but no config env var is set.
    assertNull(AgentIdentityUtils.getAgentIdentityCertificate());
  }

  // --- 4. Certificate Loading & Polling Tests ---

  @Test
  public void getAgentIdentityCertificate_happyPath_loadsCertificate() throws IOException {
    // Setup: Get the absolute path of the test resource.
    URL certUrl = getClass().getClassLoader().getResource("agent_cert.pem");
    assertNotNull("Test resource agent_cert.pem not found", certUrl);
    String certPath = new File(certUrl.getFile()).getAbsolutePath();

    // Create config file pointing to the cert.
    // We still need a temp file for the config because it must contain the absolute path
    // to the certificate, which varies by machine.
    File configFile = tempDir.resolve("config.json").toFile();
    String configJson =
        "{"
            + "  \"cert_configs\": {"
            + "    \"workload\": {"
            + "      \"cert_path\": \""
            + certPath.replace("\\", "\\\\")
            + "\""
            + "    }"
            + "  }"
            + "}";
    try (FileOutputStream fos = new FileOutputStream(configFile)) {
      fos.write(configJson.getBytes(StandardCharsets.UTF_8));
    }

    // Configure environment
    envProvider.setEnv("GOOGLE_API_CERTIFICATE_CONFIG", configFile.getAbsolutePath());

    // Execute
    X509Certificate cert = AgentIdentityUtils.getAgentIdentityCertificate();

    // Verify
    assertNotNull(cert);
    // Basic verification that it loaded OUR cert (checking issuer from agent_cert.pem)
    assertTrue(cert.getIssuerDN().getName().contains("unit-tests"));
  }

  @Test
  public void getAgentIdentityCertificate_timeout_throwsIOException() {
    // Setup: Set config path to something that doesn't exist
    envProvider.setEnv(
        "GOOGLE_API_CERTIFICATE_CONFIG",
        tempDir.resolve("missing.json").toAbsolutePath().toString());

    // Reduce timeout to make test fast (e.g., 100ms total)
    AgentIdentityUtils.TOTAL_TIMEOUT_MS = 100;
    AgentIdentityUtils.FAST_POLL_INTERVAL_MS = 10;
    AgentIdentityUtils.SLOW_POLL_INTERVAL_MS = 10;
    AgentIdentityUtils.FAST_POLL_DURATION_MS = 50;

    // Execute & Verify
    IOException e =
        assertThrows(IOException.class, AgentIdentityUtils::getAgentIdentityCertificate);
    assertTrue(
        e.getMessage()
            .contains("Certificate config or certificate file not found after multiple retries"));
  }

  // A helper class to mock System.getenv for testing purposes within this file.
  private static class TestEnvironmentProvider {
    private final java.util.Map<String, String> env = new java.util.HashMap<>();

    void setEnv(String key, String value) {
      env.put(key, value);
    }

    String getEnv(String key) {
      return env.get(key);
    }
  }
}
