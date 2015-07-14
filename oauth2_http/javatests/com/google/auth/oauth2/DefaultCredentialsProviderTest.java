package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.auth.TestUtils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.URI;
import java.security.AccessControlException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

/**
 * Test case for {@link DefaultCredentialsProvider}.
 */
@RunWith(JUnit4.class)
public class DefaultCredentialsProviderTest {

  private static final String USER_CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String USER_CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private final static String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private final static String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private final static String SA_PRIVATE_KEY_ID =
      "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private final static String SA_PRIVATE_KEY_PKCS8
      = ServiceAccountCredentialsTest.SA_PRIVATE_KEY_PKCS8;
  private static final Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test
  public void getDefaultCredentials_noCredentials_throws() throws Exception {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_noCredentialsSandbox_throwsNonSecurity() throws Exception {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setFileSandbox(true);

    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_envValidSandbox_throwsNonSecurity() throws Exception {
    HttpTransport transport = new MockHttpTransport();
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setFileSandbox(true);
    String userPath = "/user.json";
    testProvider.addFile(userPath, userStream);
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, userPath);
    
    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }
  
  @Test
  public void getDefaultCredentials_noCredentials_singleGceTestRequest() {
    MockRequestCountingTransport transport = new MockRequestCountingTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected.");
    } catch (IOException expected) {
    }
    assertEquals(1, transport.getRequestCount());
    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected.");
    } catch (IOException expected) {
    }
    assertEquals(1, transport.getRequestCount());
  }

  @Test
  public void getDefaultCredentials_caches() throws IOException {
    HttpTransport transport = new MockMetadataServerTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    GoogleCredentials firstCall = testProvider.getDefaultCredentials(transport);
    GoogleCredentials secondCall = testProvider.getDefaultCredentials(transport);

    assertNotNull(firstCall);
    assertSame(firstCall, secondCall);
  }

  @Test
  public void getDefaultCredentials_appEngine_deployed() throws IOException  {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(DefaultCredentialsProvider.APP_ENGINE_CREDENTIAL_CLASS,
        MockAppEngineCredentials.class);
    testProvider.addType(DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS,
        MockAppEngineSystemProperty.class);

    GoogleCredentials defaultCredential = testProvider.getDefaultCredentials(transport);

    assertNotNull(defaultCredential);
    assertTrue(defaultCredential instanceof MockAppEngineCredentials);
  }

  @Test
  public void getDefaultCredentials_appEngineClassWithoutRuntime_NotFoundError() {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(DefaultCredentialsProvider.APP_ENGINE_CREDENTIAL_CLASS,
        MockAppEngineCredentials.class);
    testProvider.addType(DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS,
        MockOffAppEngineSystemProperty.class);

    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected when not on App Engine.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
    }
  }

  @Test
  public void getDefaultCredentials_appEngineRuntimeWithoutClass_throwsHelpfulLoadError() {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.addType(DefaultCredentialsProvider.APP_ENGINE_SIGNAL_CLASS,
        MockAppEngineSystemProperty.class);

    try {
      testProvider.getDefaultCredentials(transport);
      fail("Credential expected to fail to load if credential class not present.");
    } catch (IOException e) {
      String message = e.getMessage();
      assertFalse(message.contains(DefaultCredentialsProvider.HELP_PERMALINK));
      assertTrue(message.contains(DefaultCredentialsProvider.APP_ENGINE_CREDENTIAL_CLASS));
    }
  }

  @Test
  public void getDefaultCredentials_appEngine_singleClassLoadAttempt() {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected for default test provider.");
    } catch (IOException expected) {
    }
    assertEquals(1, testProvider.getForNameCallCount());
    // Try a second time.
    try {
      testProvider.getDefaultCredentials(transport);
      fail("No credential expected for default test provider.");
    } catch (IOException expected) {
    }
    assertEquals(1, testProvider.getForNameCallCount());
  }

  @Test
  public void getDefaultCredentials_compute_providesToken() throws IOException {
    MockMetadataServerTransport transport = new MockMetadataServerTransport();
    transport.setAccessToken(ACCESS_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transport);

    assertNotNull(defaultCredentials);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getDefaultCredentials_cloudshell() throws IOException {
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CLOUD_SHELL_ENV_VAR, "4");
    
    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transport);

    assertTrue(defaultCredentials instanceof CloudShellCredentials);
    assertEquals(((CloudShellCredentials) defaultCredentials).getAuthPort(), 4);
  }

  @Test
  public void getDefaultCredentials_cloudshell_withComputCredentialsPresent() throws IOException {
    MockMetadataServerTransport transport = new MockMetadataServerTransport();
    transport.setAccessToken(ACCESS_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CLOUD_SHELL_ENV_VAR, "4");

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transport);

    assertTrue(defaultCredentials instanceof CloudShellCredentials);
    assertEquals(((CloudShellCredentials) defaultCredentials).getAuthPort(), 4);
  }

  @Test
  public void getDefaultCredentials_envMissingFile_throws() {
    final String invalidPath = "/invalid/path";
    HttpTransport transport = new MockHttpTransport();
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, invalidPath);

    try {
      testProvider.getDefaultCredentials(transport);
      fail("Non existent credential should throw exception");
    } catch (IOException e) {
      String message = e.getMessage();
      assertTrue(message.contains(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR));
      assertTrue(message.contains(invalidPath));
    }
  }

  @Test
  public void getDefaultCredentials_envServiceAccount_providesToken() throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    String serviceAccountPath = "/service_account.json";
    testProvider.addFile(serviceAccountPath, serviceAccountStream);
    testProvider.setEnv(
        DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, serviceAccountPath);

    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transport);

    assertNotNull(defaultCredentials);
    defaultCredentials = defaultCredentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getDefaultCredentials_envUser_providesToken() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    String userPath = "/user.json";
    testProvider.addFile(userPath, userStream);
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, userPath);

    testUserProvidesToken(
        testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_wellKnownFileNonWindows_providesToken() throws IOException {
    File homeDir = getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setProperty("os.name", "linux");
    testProvider.setProperty("user.home", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);

    testUserProvidesToken(
        testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_wellKnownFileWindows_providesToken() throws IOException {
    File homeDir = getTempDirectory();
    File cloudConfigDir = new File(homeDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();
    testProvider.setProperty("os.name", "windows");
    testProvider.setEnv("APPDATA", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), userStream);

    testUserProvidesToken(
        testProvider, USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);
  }

  @Test
  public void getDefaultCredentials_envAndWellKnownFile_envPrecedence() throws IOException {
    final String refreshTokenEnv = "2/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
    final String accessTokenEnv = "2/MkSJoj1xsli0AccessToken_NKPY2";
    final String refreshTokenWkf = "3/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
    final String accessTokenWkf = "3/MkSJoj1xsli0AccessToken_NKPY2";
    TestDefaultCredentialsProvider testProvider = new TestDefaultCredentialsProvider();

    InputStream envStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, refreshTokenEnv);
    String envPath = "/env.json";
    testProvider.setEnv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR, envPath);
    testProvider.addFile(envPath, envStream);

    File homeDir = getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    InputStream wkfStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, refreshTokenWkf);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    testProvider.setProperty("os.name", "linux");
    testProvider.setProperty("user.home", homeDir.getAbsolutePath());
    testProvider.addFile(wellKnownFile.getAbsolutePath(), wkfStream);

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(USER_CLIENT_ID, USER_CLIENT_SECRET);
    transport.addRefreshToken(refreshTokenWkf, accessTokenWkf);
    transport.addRefreshToken(refreshTokenEnv, accessTokenEnv);

    testUserProvidesToken(testProvider, transport, accessTokenEnv);
  }

  private static File getTempDirectory() {
    return new File(System.getProperty("java.io.tmpdir"));
  }

  private void testUserProvidesToken(TestDefaultCredentialsProvider testProvider, String clientId,
      String clientSecret, String refreshToken) throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(clientId, clientSecret);
    transport.addRefreshToken(refreshToken, ACCESS_TOKEN);
    testUserProvidesToken(testProvider, transport, ACCESS_TOKEN);
  }

  private void testUserProvidesToken(TestDefaultCredentialsProvider testProvider,
      HttpTransport transport, String accessToken) throws IOException {
    GoogleCredentials defaultCredentials = testProvider.getDefaultCredentials(transport);

    assertNotNull(defaultCredentials);
    Map<String, List<String>> metadata = defaultCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken);
  }

  public static class MockAppEngineCredentials extends GoogleCredentials {
    @SuppressWarnings("unused")
    public MockAppEngineCredentials(Collection<String> scopes) {
    }

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

    MockRequestCountingTransport() {
    }

    int getRequestCount() {
      return requestCount;
    }

    @Override
    public LowLevelHttpRequest buildRequest(String method, String url) {
      MockLowLevelHttpRequest request = new MockLowLevelHttpRequest(url) {
        @Override
        public LowLevelHttpResponse execute() throws IOException {
          requestCount++;
          throw new IOException("MockRequestCountingTransport request failed.");
        }
      };
      return request;
    }
  }

  private static class TestDefaultCredentialsProvider extends DefaultCredentialsProvider {

    private final Map<String, Class<?>> types = new HashMap<String, Class<?>>();
    private final Map<String, String> variables = new HashMap<String, String>();
    private final Map<String, String> properties = new HashMap<String, String>();
    private final Map<String, InputStream> files = new HashMap<String, InputStream>();
    private boolean fileSandbox = false;
    private int forNameCallCount = 0;

    TestDefaultCredentialsProvider () {
    }

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
      forNameCallCount++;
      Class<?> lookup = types.get(className);
      if (lookup != null) {
        return lookup;
      }
      throw new ClassNotFoundException("TestDefaultCredentialProvider: Class not found.");
    }

    int getForNameCallCount() {
      return forNameCallCount;
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
