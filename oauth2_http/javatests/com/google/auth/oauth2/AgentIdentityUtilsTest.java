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
import java.util.concurrent.atomic.AtomicLong;
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

  private TestEnvironmentProvider envProvider;
  private Path tempDir;

  @Before
  public void setUp() throws IOException {
    envProvider = new TestEnvironmentProvider();
    AgentIdentityUtils.setEnvReader(envProvider::getEnv);
    tempDir = Files.createTempDirectory("agent_identity_test");
  }

  @After
  public void tearDown() throws IOException {
    // Reset the time service to default after each test
    AgentIdentityUtils.resetTimeService();

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
    URL certUrl = getClass().getClassLoader().getResource("x509_leaf_certificate.pem");
    assertNotNull("Test resource x509_leaf_certificate.pem not found", certUrl);
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
    // Basic verification that it loaded OUR cert
    assertTrue(cert.getIssuerDN().getName().contains("unit-tests"));
  }

  @Test
  public void getAgentIdentityCertificate_timeout_throwsIOException() {
    // Setup: Set config path to something that doesn't exist
    envProvider.setEnv(
        "GOOGLE_API_CERTIFICATE_CONFIG",
        tempDir.resolve("missing.json").toAbsolutePath().toString());

    // Use a fake time service that advances time rapidly when sleep is called.
    // This allows the 30s timeout loop to complete instantly in test execution time.
    AgentIdentityUtils.setTimeService(new FakeTimeService());

    // Execute & Verify
    IOException e =
        assertThrows(IOException.class, AgentIdentityUtils::getAgentIdentityCertificate);
    assertTrue(
        e.getMessage()
            .contains(
                "Unable to find Agent Identity certificate config or file for bound token request after multiple retries."));
  }

  // Fake time service that advances time when sleep is requested.
  private static class FakeTimeService implements AgentIdentityUtils.TimeService {
    private final AtomicLong currentTime = new AtomicLong(0);

    @Override
    public long currentTimeMillis() {
      return currentTime.get();
    }

    @Override
    public void sleep(long millis) throws InterruptedException {
      // Instead of actually sleeping, just advance the fake clock.
      currentTime.addAndGet(millis);
    }
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
