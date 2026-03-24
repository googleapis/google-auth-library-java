package com.google.auth.mtls;

import com.google.auth.oauth2.EnvironmentProvider;
import com.google.auth.oauth2.PropertyProvider;
import com.google.common.base.Strings;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

/**
 * Utility class for mTLS related operations.
 *
 * <p>For internal use only.
 */
public class MtlsUtils {
  static final String CERTIFICATE_CONFIGURATION_ENV_VARIABLE = "GOOGLE_API_CERTIFICATE_CONFIG";
  static final String WELL_KNOWN_CERTIFICATE_CONFIG_FILE = "certificate_config.json";
  static final String CLOUDSDK_CONFIG_DIRECTORY = "gcloud";

  private MtlsUtils() {
    // Prevent instantiation for Utility class
  }

  /**
   * Returns the path to the client certificate file specified by the loaded workload certificate
   * configuration.
   *
   * @return The path to the certificate file.
   * @throws IOException if the certificate configuration cannot be found or loaded.
   */
  public static String getCertificatePath(
      EnvironmentProvider envProvider, PropertyProvider propProvider, String certConfigPathOverride)
      throws IOException {
    String certPath =
        getWorkloadCertificateConfiguration(envProvider, propProvider, certConfigPathOverride)
            .getCertPath();
    if (Strings.isNullOrEmpty(certPath)) {
      throw new CertificateSourceUnavailableException(
          "Certificate configuration loaded successfully, but does not contain a 'certificate_file' path.");
    }
    return certPath;
  }

  public static WorkloadCertificateConfiguration getWorkloadCertificateConfiguration(
      EnvironmentProvider envProvider, PropertyProvider propProvider, String certConfigPathOverride)
      throws IOException {
    File certConfig;
    if (certConfigPathOverride != null) {
      certConfig = new File(certConfigPathOverride);
    } else {
      String envCredentialsPath = envProvider.getEnv(CERTIFICATE_CONFIGURATION_ENV_VARIABLE);
      if (!Strings.isNullOrEmpty(envCredentialsPath)) {
        certConfig = new File(envCredentialsPath);
      } else {
        certConfig = getWellKnownCertificateConfigFile(envProvider, propProvider);
      }
    }

    if (!certConfig.isFile()) {
      throw new CertificateSourceUnavailableException("File does not exist.");
    }
    try (InputStream certConfigStream = new FileInputStream(certConfig)) {
      return WorkloadCertificateConfiguration.fromCertificateConfigurationStream(certConfigStream);
    }
  }

  private static File getWellKnownCertificateConfigFile(
      EnvironmentProvider envProvider, PropertyProvider propProvider) {
    File cloudConfigPath;
    String envPath = envProvider.getEnv("CLOUDSDK_CONFIG");
    if (envPath != null) {
      cloudConfigPath = new File(envPath);
    } else {
      String osName = propProvider.getProperty("os.name", "").toLowerCase(Locale.US);
      if (osName.indexOf("windows") >= 0) {
        File appDataPath = new File(envProvider.getEnv("APPDATA"));
        cloudConfigPath = new File(appDataPath, CLOUDSDK_CONFIG_DIRECTORY);
      } else {
        File configPath = new File(propProvider.getProperty("user.home", ""), ".config");
        cloudConfigPath = new File(configPath, CLOUDSDK_CONFIG_DIRECTORY);
      }
    }
    return new File(cloudConfigPath, WELL_KNOWN_CERTIFICATE_CONFIG_FILE);
  }
}
