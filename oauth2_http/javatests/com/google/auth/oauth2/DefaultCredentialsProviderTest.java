/*
 * Copyright 2015, Google Inc. All rights reserved.
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

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ComputeEngineCredentialsTest.MockMetadataServerTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Paths;
import java.security.AccessControlException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link DefaultCredentialsProvider}. */
@RunWith(JUnit4.class)
public class DefaultCredentialsProviderTest {

  private static final String USER_CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String USER_CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String GCLOUDSDK_CLIENT_ID =
      "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private static final String SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private static final String SA_PRIVATE_KEY_PKCS8 =
      ServiceAccountCredentialsTest.PRIVATE_KEY_PKCS8;
  private static final Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  private static final String QUOTA_PROJECT = "sample-quota-project-id";

  static class MockRequestCountingTransportFactory implements HttpTransportFactory {

    MockRequestCountingTransport transport = new MockRequestCountingTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getDefaultCredentials_noCredentials_throws() throws Exception {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_noCredentialsSandbox_throwsNonSecurity() throws Exception {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setFileSandbox(true);

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_envValidSandbox_throwsNonSecurity() throws Exception {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setFileSandbox(true);
    String userPath = tempFilePath("user.json");
    testProvider.addFile(userPath, userStream);
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, userPath);

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_noCredentials_singleGceTestRequest() {
    MockRequestCountingTransportFactory transportFactory =
        new MockRequestCountingTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException expected) {
      // Expected
    }
    assertEquals(
        transportFactory.transport.getRequestCount(),
        ComputeEngineCredentials.MAX_COMPUTE_PING_TRIES);
    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException expected) {
      // Expected
    }
    assertEquals(
        transportFactory.transport.getRequestCount(),
        ComputeEngineCredentials.MAX_COMPUTE_PING_TRIES);
  }

  @Test
  public void getDefaultCredentials_caches() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    GoogleCredentials firstCall = testProvider.getDefaultCredentials(transportFactory);
    GoogleCredentials secondCall = testProvider.getDefaultCredentials(transportFactory);

    assertNotNull(firstCall);
    assertSame(firstCall, secondCall);
  }

  @Test
  public void getDefaultCredentials_appEngineClassWithoutRuntime_NotFoundError() {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(
        DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS, MockOffAppEngineSystemProperty.class);
    testProvider.setProperty("isOnGAEStandard7", "true");

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected when not on App Engine.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_appEngineRuntimeWithoutClass_throwsHelpfulLoadError() {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(
        DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS, MockAppEngineSystemProperty.class);
    testProvider.setProperty("isOnGAEStandard7", "true");

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("Credential expected to fail to load if credential class not present.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertFalse(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
      assertTrue(message.contains("Check that the App Engine SDK is deployed."));
    }
  }

  @Test
  public void getDefaultCredentials_appEngineSkipWorks_retrievesCloudShellCredential()
      throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(
        DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS, MockOffAppEngineSystemProperty.class);
    testProvider.setEnv(DefaultCredentialsProvider.CLOUD_SHELL_ENV_VAR, "9090");
    testProvider.setEnv(DefaultCredentialsProvider.SKIP_APP_ENGINE_ENV_VAR, "true");
    testProvider.setProperty("isOnGAEStanadard7", "true");
    GoogleCredentials credentials = testProvider.getDefaultCredentials(transportFactory);
    assertNotNull(credentials);
    assertTrue(credentials instanceof CloudShellCredentials);
  }

  @Test
  public void getDefaultCredentials_compute_providesToken() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(ACCESS_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transportFactory);

    assertNotNull(defaultCredentials);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getDefaultCredentials_cloudshell() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CLOUD_SHELL_ENV_VAR, "4");

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transportFactory);

    assertTrue(defaultCredentials instanceof CloudShellCredentials);
    assertEquals(((CloudShellCredentials) defaultCredentials).getAuthPort(), 4);
  }

  @Test
  public void getDefaultCredentials_cloudshell_withComputCredentialsPresent() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(ACCESS_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CLOUD_SHELL_ENV_VAR, "4");

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transportFactory);

    assertTrue(defaultCredentials instanceof CloudShellCredentials);
    assertEquals(((CloudShellCredentials) defaultCredentials).getAuthPort(), 4);
  }

  @Test
  public void getDefaultCredentials_envMissingFile_throws() {
    final String invalidPath = "/invalid/path";
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, invalidPath);

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("Non existent credential should throw exception");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR));
      assertTrue(message.contains(invalidPath));
    }
  }

  @Test
  public void getDefaultCredentials_envServiceAccount_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    String serviceAccountPath = tempFilePath("service_account.json");
    testProvider.addFile(serviceAccountPath, serviceAccountStream);
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, serviceAccountPath);

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transportFactory);

    assertNotNull(defaultCredentials);
    defaultCredentials = defaultCredentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getDefaultCredentials_envUser_providesToken() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    String userPath = tempFilePath("user.json");
    testProvider.addFile(userPath, userStream);
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, userPath);

    testUserProvidesToken(testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_envNoGceCheck_noGceRequest() throws IOException {
    MockRequestCountingTransportFactory transportFactory =
        new MockRequestCountingTransportFactory();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.NO_GCE_CHECK_ENV_VAR, "true");

    try {
      testProvider.getDefaultCredentials(transportFactory);
      fail("No credential expected.");
    } catch (IOException expected) {
      // Expected
    }
    assertEquals(transportFactory.transport.getRequestCount(), 0);
  }

  @Test
  public void getDefaultCredentials_envGceMetadataHost_setsMetadataServerUrl() {
    String testUrl = "192.0.2.0";
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.GCE_METADATA_HOST_ENV_VAR, testUrl);
    assertEquals(ComputeEngineCredentials.getMetadataServerUrl(testProvider), "http://" + testUrl);
  }

  @Test
  public void getDefaultCredentials_envGceMetadataHost_setsTokenServerUrl() {
    String testUrl = "192.0.2.0";
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.GCE_METADATA_HOST_ENV_VAR, testUrl);
    assertEquals(
        ComputeEngineCredentials.getTokenServerEncodedUrl(testProvider),
        "http://" + testUrl + "/computeMetadata/v1/instance/service-accounts/default/token");
  }

  @Test
  public void getDefaultCredentials_wellKnownFileEnv_providesToken() throws IOException {
    File cloudConfigDir = getTempDirectory();
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv("CLOUDSDK_CONFIG", cloudConfigDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);

    testUserProvidesToken(testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_wellKnownFileNonWindows_providesToken() throws IOException {
    File homeDir = getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setProperty("os.name", "linux");
    testProvider.setProperty("user.home", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);

    testUserProvidesToken(testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_wellKnownFileWindows_providesToken() throws IOException {
    File homeDir = getTempDirectory();
    File cloudConfigDir = new File(homeDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setProperty("os.name", "windows");
    testProvider.setEnv("APPDATA", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);

    testUserProvidesToken(testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_envAndWellKnownFile_envPrecedence() throws IOException {
    final String refreshTokenEnv = "2/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
    final String accessTokenEnv = "2/MkSJoj1xsli0AccessToken_NKPY2";
    final String refreshTokenWkf = "3/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
    final String accessTokenWkf = "3/MkSJoj1xsli0AccessToken_NKPY2";
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    InputStream envStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, refreshTokenEnv, QUOTA_PROJECT);
    String envPath = tempFilePath("env.json");
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, envPath);
    testProvider.addFile(envPath, envStream);

    File homeDir = getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream wkfStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, refreshTokenWkf, QUOTA_PROJECT);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    testProvider.setProperty("os.name", "linux");
    testProvider.setProperty("user.home", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), wkfStream);

    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(USER_CLIENT_ID, USER_CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(refreshTokenWkf, accessTokenWkf);
    transportFactory.transport.addRefreshToken(refreshTokenEnv, accessTokenEnv);

    testUserProvidesToken(testProvider, transportFactory, accessTokenEnv);
  }

  private String tempFilePath(String filename) {
    return Paths.get(System.getProperty("java.io.tmpdir"), filename).toString();
  }

  private class LogHandler extends Handler {
    LogRecord lastRecord;

    public void publish(LogRecord record) {
      lastRecord = record;
    }

    public LogRecord getRecord() {
      return lastRecord;
    }

    public void close() {}

    public void flush() {}
  }

  @Test
  public void getDefaultCredentials_wellKnownFile_logsGcloudWarning() throws IOException {
    LogRecord message = getCredentialsAndReturnLogMessage(false);
    assertNotNull(message);
    assertEquals(Level.WARNING, message.getLevel());
    assertTrue(message.getMessage().contains("end user credentials from Google Cloud SDK"));
  }

  @Test
  public void getDefaultCredentials_wellKnownFile_suppressGcloudWarning() throws IOException {
    LogRecord message = getCredentialsAndReturnLogMessage(true);
    assertNull(message);
  }

  private LogRecord getCredentialsAndReturnLogMessage(boolean suppressWarning) throws IOException {
    Logger logger = Logger.getLogger(DefaultCredentialsProvider.class.getName());
    LogHandler handler = new LogHandler();
    logger.addHandler(handler);

    File homeDir = getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            GCLOUDSDK_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(
        DefaultCredentialsProvider.SUPPRESS_GCLOUD_CREDS_WARNING_ENV_VAR,
        Boolean.toString(suppressWarning));
    testProvider.setProperty("os.name", "linux");
    testProvider.setProperty("user.home", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);
    testUserProvidesToken(testProvider, GCLOUDSDK_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
    return handler.getRecord();
  }

  private static File getTempDirectory() {
    return new File(System.getProperty("java.io.tmpdir"));
  }

  private void testUserProvidesToken(
      TestDefaultCredentialsProvider testProvider,
      String clientId,
      String clientSecret,
      String refreshToken)
      throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(clientId, clientSecret);
    transportFactory.transport.addRefreshToken(refreshToken, ACCESS_TOKEN);
    testUserProvidesToken(testProvider, transportFactory, ACCESS_TOKEN);
  }

  private void testUserProvidesToken(
      TestDefaultCredentialsProvider testProvider,
      HttpTransportFactory transportFactory,
      String accessToken)
      throws IOException {
    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transportFactory);

    assertNotNull(defaultCredentials);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken);
  }

  public static class MockAppEngineCredentials extends GoogleCredentials {
    private static final long serialVersionUID = 2695173591854484322L;

    public MockAppEngineCredentials(Collection<String> scopes) {}

    @Override
    public AccessToken refreshAccessToken() throws IOException {
      return null;
    }
  }

  /*
   * App Engine is detected by calling SystemProperty.environment.value() via Reflection.
   * The following mock types simulate the shape and behavior of that call sequence.
   */

  private static class MockAppEngineSystemProperty {

    @SuppressWarnings("unused")
    public static final MockEnvironment environment =
        new MockEnvironment(MockEnvironmentEnum.Production);
  }

  private static class MockOffAppEngineSystemProperty {

    @SuppressWarnings("unused")
    public static final MockEnvironment environment = new MockEnvironment(null);
  }

  private enum MockEnvironmentEnum {
    Production,
    Development;
  }

  public static class MockEnvironment {

    private MockEnvironmentEnum innerValue;

    MockEnvironment(MockEnvironmentEnum value) {
      this.innerValue = value;
    }

    public MockEnvironmentEnum value() {
      return innerValue;
    }
  }

  /*
   * End of types simulating SystemProperty.environment.value() to detect App Engine.
   */

  private static class MockRequestCountingTransport extends MockHttpTransport {
    int requestCount = 0;

    MockRequestCountingTransport() {}

    int getRequestCount() {
      return requestCount;
    }

    @Override
    public LowLevelHttpRequest buildRequest(String method, String url) {
      return new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          requestCount++;
          throw new IOException("MockRequestCountingTransport request failed.");
        }
      };
    }
  }

  private static class TestDefaultCredentialsProvider extends DefaultCredentialsProvider {

    private final Map<String, Class<?>> types = new HashMap<>();
    private final Map<String, String> variables = new HashMap<>();
    private final Map<String, String> properties = new HashMap<>();
    private final Map<String, InputStream> files = new HashMap<>();
    private boolean fileSandbox = false;

    TestDefaultCredentialsProvider() {}

    void addFile(String file, InputStream stream) {
      files.put(file, stream);
    }

    void addType(String className, Class<?> type) {
      types.put(className, type);
    }

    @Override
    String getEnv(String name) {
      return variables.get(name);
    }

    void setEnv(String name, String value) {
      variables.put(name, value);
    }

    @Override
    String getProperty(String property, String def) {
      String value = properties.get(property);
      return value == null ? def : value;
    }

    void setProperty(String property, String value) {
      properties.put(property, value);
    }

    @Override
    Class<?> forName(String className) throws ClassNotFoundException {
      Class<?> lookup = types.get(className);
      if (lookup != null) {
        return lookup;
      }
      throw new ClassNotFoundException("TestDefaultCredentialProvider: Class not found.");
    }

    @Override
    protected boolean isOnGAEStandard7() {
      return getProperty("isOnGAEStandard7", "false").equals("true");
    }

    @Override
    boolean isFile(File file) {
      if (fileSandbox) {
        throw new AccessControlException("No file permission.");
      }
      return files.containsKey(file.getAbsolutePath());
    }

    @Override
    InputStream readStream(File file) throws FileNotFoundException {
      if (fileSandbox) {
        throw new AccessControlException("No file permission.");
      }
      InputStream stream = files.get(file.getAbsolutePath());
      if (stream == null) {
        throw new FileNotFoundException(file.getAbsolutePath());
      }
      return stream;
    }

    void setFileSandbox(boolean fileSandbox) {
      this.fileSandbox = fileSandbox;
    }
  }
}
