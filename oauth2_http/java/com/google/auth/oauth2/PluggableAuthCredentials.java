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

import com.google.auth.oauth2.ExecutableHandler.ExecutableOptions;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * PluggableAuthCredentials enables the exchange of workload identity pool external credentials for
 * Google access tokens by retrieving 3rd party tokens through a user supplied executable. These
 * scripts/executables are completely independent of the Google Cloud Auth libraries. These
 * credentials plug into ADC and will call the specified executable to retrieve the 3rd party token
 * to be exchanged for a Google access token.
 *
 * <p>To use these credentials, the GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment variable
 * must be set to '1'. This is for security reasons.
 *
 * <p>Both OIDC and SAML are supported. The executable must adhere to a specific response format
 * defined below.
 *
 * <p>The executable must print out the 3rd party token to STDOUT in JSON format. When an
 * output_file is specified in the credential configuration, the executable must also handle writing
 * the JSON response to this file.
 *
 * <pre>
 * OIDC response sample:
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:id_token",
 *   "id_token": "HEADER.PAYLOAD.SIGNATURE",
 *   "expiration_time": 1620433341
 * }
 *
 * SAML2 response sample:
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:saml2",
 *   "saml_response": "...",
 *   "expiration_time": 1620433341
 * }
 *
 * Error response sample:
 * {
 *   "version": 1,
 *   "success": false,
 *   "code": "401",
 *   "message": "Error message."
 * }
 * </pre>
 *
 * <p>The `expiration_time` field in the JSON response is only required for successful responses
 * when an output file was specified in the credential configuration.
 *
 * <p>The auth libraries will populate certain environment variables that will be accessible by the
 * executable, such as: GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE, GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE,
 * GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE, GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL, and
 * GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE.
 *
 * <p>Please see this repositories README for a complete executable request/response specification.
 */
public class PluggableAuthCredentials extends ExternalAccountCredentials {

  /**
   * Encapsulates the credential source portion of the configuration for PluggableAuthCredentials.
   *
   * <p>Command is the only required field. If timeout_millis is not specified, the library will
   * default to a 30 second timeout.
   *
   * <pre>
   * Sample credential source for Pluggable Auth credentials:
   * {
   *   ...
   *   "credential_source": {
   *     "executable": {
   *       "command": "/path/to/get/credentials.sh --arg1=value1 --arg2=value2",
   *       "timeout_millis": 5000,
   *       "output_file": "/path/to/generated/cached/credentials"
   *     }
   *   }
   * }
   * </pre>
   */
  static class PluggableAuthCredentialSource extends CredentialSource {

    // The default timeout for waiting for the executable to finish (30 seconds).
    private static final int DEFAULT_EXECUTABLE_TIMEOUT_MS = 30 * 1000;
    // The minimum timeout for waiting for the executable to finish (5 seconds).
    private static final int MINIMUM_EXECUTABLE_TIMEOUT_MS = 5 * 1000;
    // The maximum timeout for waiting for the executable to finish (120 seconds).
    private static final int MAXIMUM_EXECUTABLE_TIMEOUT_MS = 120 * 1000;

    private static final String COMMAND_KEY = "command";
    private static final String TIMEOUT_MILLIS_KEY = "timeout_millis";
    private static final String OUTPUT_FILE_KEY = "output_file";

    // Required. The command used to retrieve the 3rd party token.
    private final String executableCommand;

    // Optional. Set to the default timeout when not provided.
    private final int executableTimeoutMs;

    // Optional. Provided when the 3rd party executable caches the response at the specified
    // location.
    @Nullable private final String outputFilePath;

    PluggableAuthCredentialSource(Map<String, Object> credentialSourceMap) {
      super(credentialSourceMap);

      if (!credentialSourceMap.containsKey(EXECUTABLE_SOURCE_KEY)) {
        throw new IllegalArgumentException(
            "Invalid credential source for PluggableAuth credentials.");
      }

      Map<String, Object> executable =
          (Map<String, Object>) credentialSourceMap.get(EXECUTABLE_SOURCE_KEY);

      // Command is the only required field.
      if (!executable.containsKey(COMMAND_KEY)) {
        throw new IllegalArgumentException(
            "The PluggableAuthCredentialSource is missing the required 'command' field.");
      }

      // Parse the executable timeout.
      if (executable.containsKey(TIMEOUT_MILLIS_KEY)) {
        Object timeout = executable.get(TIMEOUT_MILLIS_KEY);
        if (timeout instanceof BigDecimal) {
          executableTimeoutMs = ((BigDecimal) timeout).intValue();
        } else if (executable.get(TIMEOUT_MILLIS_KEY) instanceof Integer) {
          executableTimeoutMs = (int) timeout;
        } else {
          executableTimeoutMs = Integer.parseInt((String) timeout);
        }
      } else {
        executableTimeoutMs = DEFAULT_EXECUTABLE_TIMEOUT_MS;
      }

      // Provided timeout must be between 5s and 120s.
      if (executableTimeoutMs < MINIMUM_EXECUTABLE_TIMEOUT_MS
          || executableTimeoutMs > MAXIMUM_EXECUTABLE_TIMEOUT_MS) {
        throw new IllegalArgumentException(
            String.format(
                "The executable timeout must be between %s and %s milliseconds.",
                MINIMUM_EXECUTABLE_TIMEOUT_MS, MAXIMUM_EXECUTABLE_TIMEOUT_MS));
      }

      executableCommand = (String) executable.get(COMMAND_KEY);
      outputFilePath = (String) executable.get(OUTPUT_FILE_KEY);
    }

    String getCommand() {
      return executableCommand;
    }

    int getTimeoutMs() {
      return executableTimeoutMs;
    }

    @Nullable
    String getOutputFilePath() {
      return outputFilePath;
    }
  }

  private final PluggableAuthCredentialSource config;

  private final ExecutableHandler handler;

  /** Internal constructor. See {@link Builder}. */
  PluggableAuthCredentials(Builder builder) {
    super(builder);
    this.config = (PluggableAuthCredentialSource) builder.credentialSource;

    if (builder.handler != null) {
      handler = builder.handler;
    } else {
      handler = new PluggableAuthHandler(getEnvironmentProvider());
    }

    // Re-initialize impersonated credentials as the handler hasn't been set yet when
    // this is called in the base class.
    overrideImpersonatedCredentials(buildImpersonatedCredentials());
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    String credential = retrieveSubjectToken();
    StsTokenExchangeRequest.Builder stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(credential, getSubjectTokenType())
            .setAudience(getAudience());

    Collection<String> scopes = getScopes();
    if (scopes != null && !scopes.isEmpty()) {
      stsTokenExchangeRequest.setScopes(new ArrayList<>(scopes));
    }
    return exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest.build());
  }

  /**
   * Returns the 3rd party subject token by calling the executable specified in the credential
   * source.
   *
   * @throws IOException if an error occurs with the executable execution.
   */
  @Override
  public String retrieveSubjectToken() throws IOException {
    String executableCommand = config.getCommand();
    String outputFilePath = config.getOutputFilePath();
    int executableTimeoutMs = config.getTimeoutMs();

    Map<String, String> envMap = new HashMap<>();
    envMap.put("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE", getAudience());
    envMap.put("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE", getSubjectTokenType());
    // Always set to 0 for Workload Identity Federation.
    envMap.put("GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE", "0");
    if (getServiceAccountEmail() != null) {
      envMap.put("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL", getServiceAccountEmail());
    }
    if (outputFilePath != null && !outputFilePath.isEmpty()) {
      envMap.put("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE", outputFilePath);
    }

    ExecutableOptions options =
        new ExecutableOptions() {
          @Override
          public String getExecutableCommand() {
            return executableCommand;
          }

          @Override
          public Map<String, String> getEnvironmentMap() {
            return envMap;
          }

          @Override
          public int getExecutableTimeoutMs() {
            return executableTimeoutMs;
          }

          @Nullable
          @Override
          public String getOutputFilePath() {
            return outputFilePath;
          }
        };

    // Delegate handling of the executable to the handler.
    return this.handler.retrieveTokenFromExecutable(options);
  }

  /** Clones the PluggableAuthCredentials with the specified scopes. */
  @Override
  public PluggableAuthCredentials createScoped(Collection<String> newScopes) {
    return new PluggableAuthCredentials(
        (PluggableAuthCredentials.Builder) newBuilder(this).setScopes(newScopes));
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static Builder newBuilder(PluggableAuthCredentials pluggableAuthCredentials) {
    return new Builder(pluggableAuthCredentials);
  }

  @VisibleForTesting
  @Nullable
  ExecutableHandler getExecutableHandler() {
    return this.handler;
  }

  public static class Builder extends ExternalAccountCredentials.Builder {

    private ExecutableHandler handler;

    Builder() {}

    Builder(PluggableAuthCredentials credentials) {
      super(credentials);
      this.handler = credentials.handler;
    }

    public Builder setExecutableHandler(ExecutableHandler handler) {
      this.handler = handler;
      return this;
    }

    @Override
    public PluggableAuthCredentials build() {
      return new PluggableAuthCredentials(this);
    }
  }
}
