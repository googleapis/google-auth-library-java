/*
 * Copyright 2023 Google LLC
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

import com.google.auth.CredentialTypeForMetrics;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

class MetricsUtils {
  static final String API_CLIENT_HEADER = "x-goog-api-client";
  private static final String authLibraryVersion = getAuthLibraryVersion();
  private static final String javaLanguageVersion = System.getProperty("java.version");

  /**
   * Gets the x-goog-api-client header value for the current Java language version and the auth
   * library version.
   *
   * @return the header value.
   */
  static String getLanguageAndAuthLibraryVersions() {
    return String.format("gl-java/%s auth/%s", javaLanguageVersion, authLibraryVersion);
  }

  private static String getAuthLibraryVersion() {
    // Attempt to read the library's version from a properties file generated during the build.
    // This value should be read and cached for later use.
    String version = "unknown-version";
    try (InputStream inputStream =
        MetricsUtils.class.getResourceAsStream(
            "/com/google/auth/oauth2/google-auth-library.properties")) {
      if (inputStream != null) {
        final Properties properties = new Properties();
        properties.load(inputStream);
        version = properties.getProperty("google-auth-library.version");
      }
    } catch (IOException e) {
      // Ignore.
    }
    return version;
  }

  public enum RequestType {
    ACCESS_TOKEN_REQUEST("at"),
    ID_TOKEN_REQUEST("it"),
    METADATA_SERVER_PIN("mds"),
    UNSPECIFIED("unspecified"),
    UNTRACKED("untracked");

    private String label;

    private RequestType(String label) {
      this.label = label;
    }

    public String getLabel() {
      return label;
    }
  }

  /**
   * Formulates metrics header string.
   *
   * <p>For UserCredentials access token or id token requests, no request type is specified, metric
   * header string takes format: “gl-java/JAVA_VERSION auth/LIB_VERSION cred-type/u”
   *
   * <p>For MDS pin, credentials type should not include in header, metric header string takes
   * format: “gl-java/JAVA_VERSION auth/LIB_VERSION auth-request-type/mds”
   *
   * <p>For ServiceAccountCredentials, ComputeEngineCredentials and ImpersonatedCredentials access
   * token or id token requests, metric header string takes format “gl-java/JAVA_VERSION
   * auth/LIB_VERSION auth-request-type/[it/at] cred-type/[mds/sa/imp]”
   *
   * @param requestType
   * @param credentialTypeForMetrics
   * @return
   */
  static String getGoogleCredentialsMetricsHeader(
      RequestType requestType, CredentialTypeForMetrics credentialTypeForMetrics) {
    // format for UserCredentials requests
    if (requestType == RequestType.UNSPECIFIED) {
      return String.format(
          "%s %s/%s",
          MetricsUtils.getLanguageAndAuthLibraryVersions(),
          "cred-type",
          credentialTypeForMetrics.getLabel());
    }
    // format for MDS pin
    if (credentialTypeForMetrics == CredentialTypeForMetrics.DO_NOT_SEND) {
      return String.format(
          "%s %s/%s",
          MetricsUtils.getLanguageAndAuthLibraryVersions(),
          "auth-request-type",
          requestType.getLabel());
    }
    return String.format(
        "%s %s/%s %s/%s",
        MetricsUtils.getLanguageAndAuthLibraryVersions(),
        "auth-request-type",
        requestType.getLabel(),
        "cred-type",
        credentialTypeForMetrics.getLabel());
  }
}
