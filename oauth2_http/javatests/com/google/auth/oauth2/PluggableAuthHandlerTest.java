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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.api.client.json.GenericJson;
import com.google.auth.oauth2.ExecutableHandler.ExecutableOptions;
import com.google.auth.oauth2.PluggableAuthHandler.InternalProcessBuilder;
import com.google.common.collect.ImmutableMap;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests for {@link PluggableAuthHandler}. */
@RunWith(MockitoJUnitRunner.class)
class PluggableAuthHandlerTest {
  private static final String TOKEN_TYPE_OIDC = "urn:ietf:params:oauth:token-type:id_token";
  private static final String TOKEN_TYPE_SAML = "urn:ietf:params:oauth:token-type:saml2";
  private static final String ID_TOKEN = "header.payload.signature";
  private static final String SAML_RESPONSE = "samlResponse";

  private static final int EXECUTABLE_SUPPORTED_MAX_VERSION = 1;
  private static final int EXPIRATION_DURATION = 3600;
  private static final int EXIT_CODE_SUCCESS = 0;
  private static final int EXIT_CODE_FAIL = 1;

  private static final ExecutableOptions DEFAULT_OPTIONS =
      new ExecutableOptions() {
        @Override
        public String getExecutableCommand() {
          return "/path/to/executable";
        }

        @Override
        public Map<String, String> getEnvironmentMap() {
          return ImmutableMap.of("optionKey1", "optionValue1", "optionValue2", "optionValue2");
        }

        @Override
        public int getExecutableTimeoutMs() {
          return 30000;
        }

        @Nullable
        @Override
        public String getOutputFilePath() {
          return null;
        }
      };

  @Test
  void retrieveTokenFromExecutable_oidcResponse() throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    Map<String, String> currentEnv = new HashMap<>();
    currentEnv.put("currentEnvKey1", "currentEnvValue1");
    currentEnv.put("currentEnvKey2", "currentEnvValue2");

    // Expected environment mappings.
    HashMap<String, String> expectedMap = new HashMap<>();
    expectedMap.putAll(DEFAULT_OPTIONS.getEnvironmentMap());
    expectedMap.putAll(currentEnv);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildOidcResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            currentEnv, mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    String token = handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS);

    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    assertEquals(ID_TOKEN, token);

    // Current env map should include the mappings from options.
    assertEquals(4, currentEnv.size());
    assertEquals(expectedMap, currentEnv);
  }

  @Test
  void retrieveTokenFromExecutable_samlResponse() throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    Map<String, String> currentEnv = new HashMap<>();
    currentEnv.put("currentEnvKey1", "currentEnvValue1");
    currentEnv.put("currentEnvKey2", "currentEnvValue2");

    // Expected environment mappings.
    HashMap<String, String> expectedMap = new HashMap<>();
    expectedMap.putAll(DEFAULT_OPTIONS.getEnvironmentMap());
    expectedMap.putAll(currentEnv);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // SAML response.
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildSamlResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            currentEnv, mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    String token = handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS);

    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    assertEquals(SAML_RESPONSE, token);

    // Current env map should include the mappings from options.
    assertEquals(4, currentEnv.size());
    assertEquals(expectedMap, currentEnv);
  }

  @Test
  void retrieveTokenFromExecutable_errorResponse_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // Error response.
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildErrorResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class,
            () -> handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS));

    assertEquals("401", e.getErrorCode());
    assertEquals("Caller not authorized.", e.getErrorDescription());
  }

  @Test
  void retrieveTokenFromExecutable_withOutputFile_usesCachedResponse()
      throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Build output_file.
    File file = File.createTempFile("output_file", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(buildOidcResponse().toString().getBytes(StandardCharsets.UTF_8)),
        file.getAbsolutePath());

    // Options with output file specified.
    ExecutableOptions options =
        new ExecutableOptions() {
          @Override
          public String getExecutableCommand() {
            return "/path/to/executable";
          }

          @Override
          public Map<String, String> getEnvironmentMap() {
            return ImmutableMap.of();
          }

          @Override
          public int getExecutableTimeoutMs() {
            return 30000;
          }

          @Override
          public String getOutputFilePath() {
            return file.getAbsolutePath();
          }
        };

    // Mock executable handling that does nothing since we are using the output file.
    Process mockProcess = Mockito.mock(Process.class);
    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(new HashMap<>(), mockProcess, options.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    String token = handler.retrieveTokenFromExecutable(options);

    // Validate executable not invoked.
    verify(mockProcess, times(0)).destroyForcibly();
    verify(mockProcess, times(0))
        .waitFor(eq(Long.valueOf(options.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));

    assertEquals(ID_TOKEN, token);
  }

  @Test
  void retrieveTokenFromExecutable_withInvalidOutputFile_throws()
      throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Build output_file.
    File file = File.createTempFile("output_file", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream("Bad response.".getBytes(StandardCharsets.UTF_8)),
        file.getAbsolutePath());

    // Options with output file specified.
    ExecutableOptions options =
        new ExecutableOptions() {
          @Override
          public String getExecutableCommand() {
            return "/path/to/executable";
          }

          @Override
          public Map<String, String> getEnvironmentMap() {
            return ImmutableMap.of();
          }

          @Override
          public int getExecutableTimeoutMs() {
            return 30000;
          }

          @Override
          public String getOutputFilePath() {
            return file.getAbsolutePath();
          }
        };

    // Mock executable handling that does nothing since we are using the output file.
    Process mockProcess = Mockito.mock(Process.class);
    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(new HashMap<>(), mockProcess, options.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class, () -> handler.retrieveTokenFromExecutable(options));

    assertEquals("INVALID_OUTPUT_FILE", e.getErrorCode());
  }

  @Test
  void retrieveTokenFromExecutable_expiredOutputFileResponse_callsExecutable()
      throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Build output_file.
    File file = File.createTempFile("output_file", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    // Create an expired response.
    GenericJson json = buildOidcResponse();
    json.put("expiration_time", Instant.now().getEpochSecond() - 1);

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(json.toString().getBytes(StandardCharsets.UTF_8)),
        file.getAbsolutePath());

    // Options with output file specified.
    ExecutableOptions options =
        new ExecutableOptions() {
          @Override
          public String getExecutableCommand() {
            return "/path/to/executable";
          }

          @Override
          public Map<String, String> getEnvironmentMap() {
            return ImmutableMap.of();
          }

          @Override
          public int getExecutableTimeoutMs() {
            return 30000;
          }

          @Override
          public String getOutputFilePath() {
            return file.getAbsolutePath();
          }
        };

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildOidcResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(new HashMap<>(), mockProcess, options.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    String token = handler.retrieveTokenFromExecutable(options);

    // Validate that the executable was called.
    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(eq(Long.valueOf(options.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));

    assertEquals(ID_TOKEN, token);
  }

  @Test
  void retrieveTokenFromExecutable_expiredResponse_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Create expired response.
    GenericJson json = buildOidcResponse();
    json.put("expiration_time", Instant.now().getEpochSecond() - 1);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);
    when(mockProcess.getInputStream())
        .thenReturn(new ByteArrayInputStream(json.toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class,
            () -> handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS));

    assertEquals("INVALID_RESPONSE", e.getErrorCode());
    assertEquals("The executable response is expired.", e.getErrorDescription());
  }

  @Test
  void retrieveTokenFromExecutable_invalidVersion_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // SAML response.
    GenericJson json = buildSamlResponse();
    // Only version `1` is supported.
    json.put("version", 2);
    when(mockProcess.getInputStream())
        .thenReturn(new ByteArrayInputStream(json.toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call retrieveTokenFromExecutable().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class,
            () -> handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS));

    assertEquals("UNSUPPORTED_VERSION", e.getErrorCode());
    assertEquals(
        "The version of the executable response is not supported. "
            + String.format(
                "The maximum version currently supported is %s.", EXECUTABLE_SUPPORTED_MAX_VERSION),
        e.getErrorDescription());
  }

  @Test
  void retrieveTokenFromExecutable_allowExecutablesDisabled_throws() {
    // In order to use Pluggable Auth, GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES must be set to 1.
    // If set to 0, a runtime exception should be thrown.
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "0");

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider);

    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class,
            () -> handler.retrieveTokenFromExecutable(DEFAULT_OPTIONS));

    assertEquals("PLUGGABLE_AUTH_DISABLED", e.getErrorCode());
    assertEquals(
        "Pluggable Auth executables need to be explicitly allowed to run by "
            + "setting the GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment variable to 1.",
        e.getErrorDescription());
  }

  @Test
  void getExecutableResponse_oidcResponse() throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    Map<String, String> currentEnv = new HashMap<>();
    currentEnv.put("currentEnvKey1", "currentEnvValue1");
    currentEnv.put("currentEnvKey2", "currentEnvValue2");

    // Expected environment mappings.
    HashMap<String, String> expectedMap = new HashMap<>();
    expectedMap.putAll(DEFAULT_OPTIONS.getEnvironmentMap());
    expectedMap.putAll(currentEnv);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // OIDC response.
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildOidcResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            currentEnv, mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    ExecutableResponse response = handler.getExecutableResponse(DEFAULT_OPTIONS);

    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    assertEquals(EXECUTABLE_SUPPORTED_MAX_VERSION, response.getVersion());
    assertTrue(response.isSuccessful());
    assertEquals(TOKEN_TYPE_OIDC, response.getTokenType());
    assertEquals(ID_TOKEN, response.getSubjectToken());
    assertEquals(
        Instant.now().getEpochSecond() + EXPIRATION_DURATION, response.getExpirationTime());
    // Current env map should include the mappings from options.
    assertEquals(4, currentEnv.size());
    assertEquals(expectedMap, currentEnv);
  }

  @Test
  void getExecutableResponse_samlResponse() throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    Map<String, String> currentEnv = new HashMap<>();
    currentEnv.put("currentEnvKey1", "currentEnvValue1");
    currentEnv.put("currentEnvKey2", "currentEnvValue2");

    // Expected environment mappings.
    HashMap<String, String> expectedMap = new HashMap<>();
    expectedMap.putAll(DEFAULT_OPTIONS.getEnvironmentMap());
    expectedMap.putAll(currentEnv);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // SAML response.
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildSamlResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            currentEnv, mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);
    ExecutableResponse response = handler.getExecutableResponse(DEFAULT_OPTIONS);

    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    assertEquals(EXECUTABLE_SUPPORTED_MAX_VERSION, response.getVersion());
    assertTrue(response.isSuccessful());
    assertEquals(TOKEN_TYPE_SAML, response.getTokenType());
    assertEquals(SAML_RESPONSE, response.getSubjectToken());
    assertEquals(
        Instant.now().getEpochSecond() + EXPIRATION_DURATION, response.getExpirationTime());

    // Current env map should include the mappings from options.
    assertEquals(4, currentEnv.size());
    assertEquals(expectedMap, currentEnv);

    verify(mockProcess, times(1)).destroy();
  }

  @Test
  void getExecutableResponse_errorResponse() throws IOException, InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    Map<String, String> currentEnv = new HashMap<>();
    currentEnv.put("currentEnvKey1", "currentEnvValue1");
    currentEnv.put("currentEnvKey2", "currentEnvValue2");

    // Expected environment mappings.
    HashMap<String, String> expectedMap = new HashMap<>();
    expectedMap.putAll(DEFAULT_OPTIONS.getEnvironmentMap());
    expectedMap.putAll(currentEnv);

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);

    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // Error response.
    when(mockProcess.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                buildErrorResponse().toString().getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            currentEnv, mockProcess, DEFAULT_OPTIONS.getExecutableCommand());
    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call getExecutableResponse().
    ExecutableResponse response = handler.getExecutableResponse(DEFAULT_OPTIONS);

    verify(mockProcess, times(1)).destroy();
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    assertEquals(EXECUTABLE_SUPPORTED_MAX_VERSION, response.getVersion());
    assertFalse(response.isSuccessful());
    assertEquals("401", response.getErrorCode());
    assertEquals("Caller not authorized.", response.getErrorMessage());

    // Current env map should include the mappings from options.
    assertEquals(4, currentEnv.size());
    assertEquals(expectedMap, currentEnv);
  }

  @Test
  void getExecutableResponse_timeoutExceeded_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(false);

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());
    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call getExecutableResponse().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class, () -> handler.getExecutableResponse(DEFAULT_OPTIONS));

    assertEquals("TIMEOUT_EXCEEDED", e.getErrorCode());
    assertEquals(
        "The executable failed to finish within the timeout specified.", e.getErrorDescription());
    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    verify(mockProcess, times(1)).destroy();
  }

  @Test
  void getExecutableResponse_nonZeroExitCode_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_FAIL);

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call getExecutableResponse().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class, () -> handler.getExecutableResponse(DEFAULT_OPTIONS));

    assertEquals("EXIT_CODE", e.getErrorCode());
    assertEquals(
        String.format("The executable failed with exit code %s.", EXIT_CODE_FAIL),
        e.getErrorDescription());

    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    verify(mockProcess, times(1)).destroy();
  }

  @Test
  void getExecutableResponse_processInterrupted_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenThrow(new InterruptedException());

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call getExecutableResponse().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class, () -> handler.getExecutableResponse(DEFAULT_OPTIONS));

    assertEquals("INTERRUPTED", e.getErrorCode());
    assertEquals(
        String.format("The execution was interrupted: %s.", new InterruptedException()),
        e.getErrorDescription());

    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    verify(mockProcess, times(1)).destroy();
  }

  @Test
  void getExecutableResponse_invalidResponse_throws() throws InterruptedException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider.setEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1");

    // Mock executable handling.
    Process mockProcess = Mockito.mock(Process.class);
    when(mockProcess.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    when(mockProcess.exitValue()).thenReturn(EXIT_CODE_SUCCESS);

    // Mock bad executable response.
    String badResponse = "badResponse";
    when(mockProcess.getInputStream())
        .thenReturn(new ByteArrayInputStream(badResponse.getBytes(StandardCharsets.UTF_8)));

    InternalProcessBuilder processBuilder =
        buildInternalProcessBuilder(
            new HashMap<>(), mockProcess, DEFAULT_OPTIONS.getExecutableCommand());

    PluggableAuthHandler handler = new PluggableAuthHandler(environmentProvider, processBuilder);

    // Call getExecutableResponse().
    PluggableAuthException e =
        assertThrows(
            PluggableAuthException.class, () -> handler.getExecutableResponse(DEFAULT_OPTIONS));

    assertEquals("INVALID_RESPONSE", e.getErrorCode());
    assertEquals(
        String.format("The executable returned an invalid response: %s.", badResponse),
        e.getErrorDescription());

    verify(mockProcess, times(1))
        .waitFor(
            eq(Long.valueOf(DEFAULT_OPTIONS.getExecutableTimeoutMs())), eq(TimeUnit.MILLISECONDS));
    verify(mockProcess, times(1)).destroy();
  }

  private static GenericJson buildOidcResponse() {
    GenericJson json = new GenericJson();
    json.setFactory(OAuth2Utils.JSON_FACTORY);
    json.put("version", EXECUTABLE_SUPPORTED_MAX_VERSION);
    json.put("success", true);
    json.put("token_type", TOKEN_TYPE_OIDC);
    json.put("id_token", ID_TOKEN);
    json.put("expiration_time", Instant.now().getEpochSecond() + EXPIRATION_DURATION);
    return json;
  }

  private static GenericJson buildSamlResponse() {
    GenericJson json = new GenericJson();
    json.setFactory(OAuth2Utils.JSON_FACTORY);
    json.put("version", EXECUTABLE_SUPPORTED_MAX_VERSION);
    json.put("success", true);
    json.put("token_type", TOKEN_TYPE_SAML);
    json.put("saml_response", SAML_RESPONSE);
    json.put("expiration_time", Instant.now().getEpochSecond() + EXPIRATION_DURATION);
    return json;
  }

  private static GenericJson buildErrorResponse() {
    GenericJson json = new GenericJson();
    json.setFactory(OAuth2Utils.JSON_FACTORY);
    json.put("version", EXECUTABLE_SUPPORTED_MAX_VERSION);
    json.put("success", false);
    json.put("code", "401");
    json.put("message", "Caller not authorized.");
    return json;
  }

  private static InternalProcessBuilder buildInternalProcessBuilder(
      Map<String, String> currentEnv, Process process, String command) {
    return new InternalProcessBuilder() {

      @Override
      Map<String, String> environment() {
        return currentEnv;
      }

      @Override
      InternalProcessBuilder redirectErrorStream(boolean redirectErrorStream) {
        return this;
      }

      @Override
      Process start() {
        return process;
      }
    };
  }
}
