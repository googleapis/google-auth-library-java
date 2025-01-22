package com.google.auth.mtls;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class X509ProviderTest {

  static String TEST_CERT = "-----BEGIN CERTIFICATE-----\n"
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

  static String TEST_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n"
          + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL1SdY8jTUVU7O4/\n"
          + "XrZLYTw0ON1lV6MQRGajFDFCqD2Fd9tQGLW8Iftx9wfXe1zuaehJSgLcyCxazfyJ\n"
          + "oN3RiONBihBqWY6d3lQKqkgsRTNZkdFJWdzl/6CxhK9sojh2p0r3tydtv9iwq5fu\n"
          + "uWIvtODtT98EgphhncQAqkKoF3zVAgMBAAECgYB51B9cXe4yiGTzJ4pOKpHGySAy\n"
          + "sC1F/IjXt2eeD3PuKv4m/hL4l7kScpLx0+NJuQ4j8U2UK/kQOdrGANapB1ZbMZAK\n"
          + "/q0xmIUzdNIDiGSoTXGN2mEfdsEpQ/Xiv0lyhYBBPC/K4sYIpHccnhSRQUZlWLLY\n"
          + "lE5cFNKC9b7226mNvQJBAPt0hfCNIN0kUYOA9jdLtx7CE4ySGMPf5KPBuzPd8ty1\n"
          + "fxaFm9PB7B76VZQYmHcWy8rT5XjoLJHrmGW1ZvP+iDsCQQDAvnKoarPOGb5iJfkq\n"
          + "RrA4flf1TOlf+1+uqIOJ94959jkkJeb0gv/TshDnm6/bWn+1kJylQaKygCizwPwB\n"
          + "Z84vAkA0Duur4YvsPJijoQ9YY1SGCagCcjyuUKwFOxaGpmyhRPIKt56LOJqpzyno\n"
          + "fy8ReKa4VyYq4eZYT249oFCwMwIBAkAROPNF2UL3x5UbcAkznd1hLujtIlI4IV4L\n"
          + "XUNjsJtBap7we/KHJq11XRPlniO4lf2TW7iji5neGVWJulTKS1xBAkAerktk4Hsw\n"
          + "ErUaUG1s/d+Sgc8e/KMeBElV+NxGhcWEeZtfHMn/6VOlbzY82JyvC9OKC80A5CAE\n"
          + "VUV6b25kqrcu\n"
          + "-----END PRIVATE KEY-----";

  @Test
  public void X509Provider_FileDoesntExist_Throws() {
    String certConfigPath = "badfile.txt";
    X509Provider testProvider = new TestX509Provider(certConfigPath);
    String expectedErrorMessage = String.format("Error reading certificate configuration file value '%s': File does not exist.", certConfigPath);

    try {
      testProvider.getKeyStore();
      fail("No key stores expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.equals(expectedErrorMessage));
    }
  }

  @Test
  public void X509Provider_EmptyFile_Throws() {
    String certConfigPath = "certConfig.txt";
    InputStream certConfigStream = new ByteArrayInputStream("".getBytes());
    TestX509Provider testProvider = new TestX509Provider(certConfigPath);
    testProvider.addFile(certConfigPath, certConfigStream);
    String expectedErrorMessage = String.format("Error reading certificate configuration file value '%s': no JSON input found", certConfigPath);

    try {
      testProvider.getKeyStore();
      fail("No key store expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.equals(expectedErrorMessage));
    }
  }

  @Test
  public void X509Provider_EmptyCertFile_Throws() throws IOException {
    String certConfigPath = "certConfig.txt";
    String certPath = "cert.crt";
    String keyPath = "key.crt";
    InputStream certConfigStream = writeWorkloadCertificateConfigStream(certPath, keyPath);

    TestX509Provider testProvider = new TestX509Provider(certConfigPath);
    testProvider.addFile(certConfigPath, certConfigStream);
    testProvider.addFile(keyPath,  new ByteArrayInputStream(TEST_PRIVATE_KEY.getBytes()));
    String expectedErrorMessage = String.format("Error reading certificate configuration file value '%s': no JSON input found", certConfigPath);

    try {
      testProvider.getKeyStore();
      fail("No key store expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.equals(expectedErrorMessage));
    }
  }

  @Test
  public void X509Provider_Succeeds() throws IOException, KeyStoreException, CertificateException {
    String certConfigPath = "certConfig.txt";
    String certPath = "cert.crt";
    String keyPath = "key.crt";
    InputStream certConfigStream = writeWorkloadCertificateConfigStream(certPath, keyPath);

    TestX509Provider testProvider = new TestX509Provider(certConfigPath);
    testProvider.addFile(certConfigPath, certConfigStream);
    testProvider.addFile(certPath, new ByteArrayInputStream(TEST_CERT.getBytes()));
    testProvider.addFile(keyPath,  new ByteArrayInputStream(TEST_PRIVATE_KEY.getBytes()));

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Certificate expectedCert = cf.generateCertificate(new ByteArrayInputStream(TEST_CERT.getBytes()));

    // Assert that the store has the expected certificate and only the expected certificate.
    KeyStore store = testProvider.getKeyStore();
    assertTrue(store.size() == 1);
    assertTrue(store.getCertificateAlias(expectedCert) != null);
  }

  static InputStream writeWorkloadCertificateConfigStream(
      String certPath,
      String privateKeyPath)
      throws IOException {
    GenericJson json =
        writeWorkloadCertificateConfigJson(certPath, privateKeyPath);
    return TestUtils.jsonToInputStream(json);
  }

  static GenericJson writeWorkloadCertificateConfigJson(
      String certPath,
      String privateKeyPath) {
    GenericJson json = new GenericJson();
    json.put("version", 1);
    GenericJson certConfigs = new GenericJson();
    GenericJson workloadConfig = new GenericJson();
    if (certPath != null) {
      workloadConfig.put("cert_path", certPath);
    }
    if (privateKeyPath != null) {
      workloadConfig.put("key_path", privateKeyPath);
    }
    certConfigs.put("workload", workloadConfig);
    json.put("cert_configs", certConfigs);
    return json;
  }

  static class TestX509Provider extends X509Provider {
    private final Map<String, InputStream> files = new HashMap<>();

    TestX509Provider () {}

    TestX509Provider (String filePathOverride) {
      super(filePathOverride);
    }

    void addFile(String file, InputStream stream) {
      files.put(file, stream);
    }

    //@Override
    //String getEnv(String name) {
    //  return variables.get(name);
    //}

    //void setEnv(String name, String value) {
    //  variables.put(name, value);
    //}

    @Override
    boolean isFile(File file) {
      return files.containsKey(file.getPath());
    }

    @Override
    InputStream readStream(File file) throws FileNotFoundException {
      InputStream stream = files.get(file.getPath());
      if (stream == null) {
        throw new FileNotFoundException(file.getPath());
      }
      return stream;
    }
  }
}
