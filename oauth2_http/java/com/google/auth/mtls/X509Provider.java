package com.google.auth.mtls;

import com.google.api.client.util.SecurityUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.KeyStore;
import java.util.Locale;

public class X509Provider {
  static final String CERTIFICATE_CONFIGURATION_ENV_VARIABLE = "GOOGLE_API_CERTIFICATE_CONFIG";
  static final String WELL_KNOWN_CERTIFICATE_CONFIG_FILE = "certificate_config.json";
  static final String CLOUDSDK_CONFIG_DIRECTORY = "gcloud";

  private String certConfigPathOverride;

  public X509Provider(String certConfigPathOverride) {
    this.certConfigPathOverride = certConfigPathOverride;
  }

  public X509Provider() {
    super(null);
  }

  public KeyStore getKeyStore() throws IOException {

    WorkloadCertificateConfiguration workloadCertConfig = getWorkloadCertificateConfiguration();

    try {
      // Read the certificate and private key file paths into separate streams.
      File certFile = new File(workloadCertConfig.getCertPath());
      File privateKeyFile = new File(workloadCertConfig.getPrivateKeyPath());
      InputStream certStream = readStream(certFile);
      InputStream privateKeyStream = readStream(privateKeyFile);

      // Merge the two streams into a single stream.
      SequenceInputStream certAndPrivateKeyStream =
          new SequenceInputStream(certStream, privateKeyStream);

      // Build a key store using the combined stream.
      return SecurityUtils.createMtlsKeyStore(certAndPrivateKeyStream);
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  private WorkloadCertificateConfiguration getWorkloadCertificateConfiguration()
      throws IOException {
    File certConfig;
    if (this.certConfigPathOverride != null) {
      certConfig = new File(certConfigPathOverride);
    } else {
      String envCredentialsPath = getEnv(CERTIFICATE_CONFIGURATION_ENV_VARIABLE);
      if (envCredentialsPath != null && !envCredentialsPath.isEmpty()) {
        certConfig = new File(envCredentialsPath);
      } else {
        certConfig = getWellKnownCertificateConfigFile();
      }
    }
    InputStream certConfigStream = null;
    try {
      if (!isFile(certConfig)) {
        // Path will be put in the message from the catch block below
        throw new IOException("File does not exist.");
      }
      certConfigStream = readStream(certConfig);
      return WorkloadCertificateConfiguration.fromCertificateConfigurationStream(certConfigStream);
    } catch (Exception e) {
      // Although it is also the cause, the message of the caught exception can have very
      // important information for diagnosing errors, so include its message in the
      // outer exception message also.
      throw new IOException(
          String.format(
              "Error reading certificate configuration file value '%s': %s",
              certConfig.getPath(), e.getMessage()),
          e);
    } finally {
      if (certConfigStream != null) {
        certConfigStream.close();
      }
    }
  }

  /*
   * Start of methods to allow overriding in the test code to isolate from the environment.
   */
  boolean isFile(File file) {
    return file.isFile();
  }

  InputStream readStream(File file) throws FileNotFoundException {
    return new FileInputStream(file);
  }

  String getEnv(String name) {
    return System.getenv(name);
  }

  String getOsName() {
    return getProperty("os.name", "").toLowerCase(Locale.US);
  }

  String getProperty(String property, String def) {
    return System.getProperty(property, def);
  }
  /*
   * End of methods to allow overriding in the test code to isolate from the environment.
   */

  private File getWellKnownCertificateConfigFile() {
    File cloudConfigPath;
    String envPath = getEnv("CLOUDSDK_CONFIG");
    if (envPath != null) {
      cloudConfigPath = new File(envPath);
    } else if (getOsName().indexOf("windows") >= 0) {
      File appDataPath = new File(getEnv("APPDATA"));
      cloudConfigPath = new File(appDataPath, CLOUDSDK_CONFIG_DIRECTORY);
    } else {
      File configPath = new File(getProperty("user.home", ""), ".config");
      cloudConfigPath = new File(configPath, CLOUDSDK_CONFIG_DIRECTORY);
    }
    return new File(cloudConfigPath, WELL_KNOWN_CERTIFICATE_CONFIG_FILE);
  }
}
