/*
 * Copyright 2025, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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
    this(null);
  }

  /**
   * Finds the certificate configuration file, then builds a Keystore using the X.509 certificate
   * and private key pointed to by the configuration. This will check the following locations in
   * order.
   *
   * <ul>
   *   <li>The certificate config override path, if set.
   *   <li>The path pointed to by the "GOOGLE_API_CERTIFICATE_CONFIG" environment variable
   *   <li>The well known gcloud location for the certificate configuration file.
   * </ul>
   *
   * @return a KeyStore containing the X.509 certificate specified by the certificate configuration.
   * @throws IOException if there is an error retrieving the certificate configuration.
   */
  public KeyStore getKeyStore() throws IOException {

    WorkloadCertificateConfiguration workloadCertConfig = getWorkloadCertificateConfiguration();

    InputStream certStream = null;
    InputStream privateKeyStream = null;
    try {
      // Read the certificate and private key file paths into separate streams.
      File certFile = new File(workloadCertConfig.getCertPath());
      File privateKeyFile = new File(workloadCertConfig.getPrivateKeyPath());
      certStream = readStream(certFile);
      privateKeyStream = readStream(privateKeyFile);

      // Merge the two streams into a single stream.
      SequenceInputStream certAndPrivateKeyStream =
          new SequenceInputStream(certStream, privateKeyStream);

      // Build a key store using the combined stream.
      return SecurityUtils.createMtlsKeyStore(certAndPrivateKeyStream);
    } catch (Exception e) {
      throw new IOException(e);
    } finally {
      if (certStream != null) {
        certStream.close();
      }
      if (privateKeyStream != null) {
        privateKeyStream.close();
      }
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
