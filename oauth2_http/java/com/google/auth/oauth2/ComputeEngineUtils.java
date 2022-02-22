/*
 * Copyright 2022 Google LLC
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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ComputeEngineUtils {
  private static final Logger LOGGER = Logger.getLogger(ComputeEngineUtils.class.getName());
  private static final String WINDOWS_COMMAND = "powershell.exe";
  private static final String METADATA_FLAVOR = "Metadata-Flavor";
  private static final String GOOGLE = "Google";

  // Note: the explicit `timeout` and `tries` below is a workaround. The underlying
  // issue is that resolving an unknown host on some networks will take
  // 20-30 seconds; making this timeout short fixes the issue, but
  // could lead to false negatives in the event that we are on GCE, but
  // the metadata resolution was particularly slow. The latter case is
  // "unlikely" since the expected 4-nines time is about 0.5 seconds.
  // This allows us to limit the total ping maximum timeout to 1.5 seconds
  // for developer desktop scenarios.
  static final int MAX_COMPUTE_PING_TRIES = 3;
  static final int COMPUTE_PING_CONNECTION_TIMEOUT_MS = 500;
  static final String DEFAULT_METADATA_SERVER_URL = "http://metadata.google.internal";

  private ComputeEngineUtils() {}

  /** Returns {@code true} if currently running on Google Compute Environment (GCE). */
  public static synchronized boolean isOnGce(
      HttpTransportFactory transportFactory, DefaultCredentialsProvider provider) {
    boolean result = isRunningOnGce();

    if (!result) {
      result = pingComputeEngineMetadata(transportFactory, provider);
    }
    return result;
  }

  @VisibleForTesting
  static boolean checkProductNameOnLinux(BufferedReader reader) throws IOException {
    String name = reader.readLine().trim();
    return name.equals("Google") || name.equals("Google Compute Engine");
  }

  @VisibleForTesting
  static boolean checkBiosDataOnWindows(BufferedReader reader) throws IOException {
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.startsWith("Manufacturer")) {
        String name = line.substring(line.indexOf(':') + 1).trim();
        return name.equals("Google");
      }
    }
    return false;
  }

  private static boolean isRunningOnGce() {
    String osName = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    try {
      if (osName.startsWith("linux")) {
        // Checks GCE residency on Linux platform.
        return checkProductNameOnLinux(
            Files.newBufferedReader(Paths.get("/sys/class/dmi/id/product_name"), UTF_8));
      } else if (osName.startsWith("windows")) {
        // Checks GCE residency on Windows platform.
        Process p =
            new ProcessBuilder()
                .command(WINDOWS_COMMAND, "Get-WmiObject", "-Class", "Win32_BIOS")
                .start();
        return checkBiosDataOnWindows(
            new BufferedReader(new InputStreamReader(p.getInputStream(), UTF_8)));
      }
    } catch (IOException e) {
      return false;
    }
    // Platforms other than Linux and Windows are not supported.
    return false;
  }

  private static boolean pingComputeEngineMetadata(
      HttpTransportFactory transportFactory, DefaultCredentialsProvider provider) {

    GenericUrl tokenUrl = new GenericUrl(getMetadataServerUrl(provider));
    for (int i = 1; i <= MAX_COMPUTE_PING_TRIES; ++i) {
      try {
        HttpRequest request =
            transportFactory.create().createRequestFactory().buildGetRequest(tokenUrl);
        request.setConnectTimeout(COMPUTE_PING_CONNECTION_TIMEOUT_MS);
        request.getHeaders().set(METADATA_FLAVOR, GOOGLE);

        HttpResponse response = request.execute();
        try {
          // Internet providers can return a generic response to all requests, so it is necessary
          // to check that metadata header is present also.
          HttpHeaders headers = response.getHeaders();
          return OAuth2Utils.headersContainValue(headers, METADATA_FLAVOR, GOOGLE);
        } finally {
          response.disconnect();
        }
      } catch (SocketTimeoutException expected) {
        // Ignore logging timeouts which is the expected failure mode in non GCE environments.
      } catch (IOException e) {
        LOGGER.log(
            Level.FINE,
            "Encountered an unexpected exception when determining"
                + " if we are running on Google Compute Engine.",
            e);
      }
    }
    LOGGER.log(Level.FINE, "Failed to detect whether we are running on Google Compute Engine.");
    return false;
  }

  public static String getMetadataServerUrl(DefaultCredentialsProvider provider) {
    String metadataServerAddress =
        provider.getEnv(DefaultCredentialsProvider.GCE_METADATA_HOST_ENV_VAR);
    if (metadataServerAddress != null) {
      return "http://" + metadataServerAddress;
    }
    return DEFAULT_METADATA_SERVER_URL;
  }

  public static String getMetadataServerUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT);
  }

  public static String getTokenServerEncodedUrl(DefaultCredentialsProvider provider) {
    return getMetadataServerUrl(provider)
        + "/computeMetadata/v1/instance/service-accounts/default/token";
  }

  public static String getTokenServerEncodedUrl() {
    return getTokenServerEncodedUrl(DefaultCredentialsProvider.DEFAULT);
  }

  public static String getServiceAccountsUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT)
        + "/computeMetadata/v1/instance/service-accounts/?recursive=true";
  }

  public static String getIdentityDocumentUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT)
        + "/computeMetadata/v1/instance/service-accounts/default/identity";
  }
}
