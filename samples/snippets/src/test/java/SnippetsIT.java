/*
 * Copyright 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import com.auth0.jwk.JwkException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SnippetsIT {

  private static final String PROJECT_ID = System.getenv("GOOGLE_CLOUD_PROJECT");
  private static final String CREDENTIALS = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
  private ByteArrayOutputStream stdOut;

  // Check if the required environment variables are set.
  public static void requireEnvVar(String envVarName) {
    assertWithMessage(String.format("Missing environment variable '%s' ", envVarName))
        .that(System.getenv(envVarName)).isNotEmpty();
  }

  @BeforeClass
  public static void setup() throws IOException {
    final PrintStream out = System.out;
    ByteArrayOutputStream stdOut = new ByteArrayOutputStream();
    System.setOut(new PrintStream(stdOut));
    requireEnvVar("GOOGLE_APPLICATION_CREDENTIALS");
    requireEnvVar("GOOGLE_CLOUD_PROJECT");

    stdOut.close();
    System.setOut(out);
  }

  @AfterClass
  public static void cleanup() {
  }

  @Before
  public void beforeEach() {
    stdOut = new ByteArrayOutputStream();
    System.setOut(new PrintStream(stdOut));
  }

  @After
  public void afterEach() {
    stdOut = null;
    System.setOut(null);
  }

  @Test
  public void testIdTokenFromServiceAccount() throws GeneralSecurityException, IOException {
    IdTokenFromServiceAccount.getIdTokenFromServiceAccount(
        CREDENTIALS,
        "https://www.googleapis.com/auth/pubsub",
        "pubsub.googleapis.com");
    assertThat(stdOut.toString()).contains("Id token verified.");
  }

  @Test
  public void testIdTokenFromServiceAccountRest()
      throws GeneralSecurityException, IOException, ExecutionException, InterruptedException {
    IdTokenFromServiceAccountREST.getIdTokenFromServiceAccountREST(
        CREDENTIALS,
        "https://www.googleapis.com/auth/pubsub",
        "pubsub.googleapis.com");
    assertThat(stdOut.toString()).contains("Id token verified.");
  }

  @Test
  public void testVerifyNonGoogleIdToken()
      throws GeneralSecurityException, IOException, JwkException {
    VerifyNonGoogleIdToken.verifyNonGoogleIdToken(
        CREDENTIALS,
        "https://www.googleapis.com/auth/pubsub",
        "pubsub.googleapis.com",
        "https://www.googleapis.com/oauth2/v3/certs");
    assertThat(stdOut.toString()).contains("Id token verified.");
  }

  @Test
  public void testIdTokenFromMetadataServer() throws GeneralSecurityException, IOException {
    IdTokenFromMetadataServer.getIdTokenFromMetadataServer("pubsub.googleapis.com");
    assertThat(stdOut.toString()).contains("Id token verified.");
  }

  @Test
  public void testAuthenticateImplicitWithAdc() throws IOException {
    AuthenticateImplicitWithAdc.authenticateImplicitWithAdc(PROJECT_ID);
    assertThat(stdOut.toString()).contains("Listing instances complete");
  }

  @Test
  public void testAuthenticateExplicit() throws IOException {
    AuthenticateExplicit.authenticateExplicit(
        PROJECT_ID,
        CREDENTIALS,
        "https://www.googleapis.com/auth/devstorage.full_control");
    assertThat(stdOut.toString()).contains("Authentication complete.");
  }

  @Test
  public void testAuthWithCredentialsFromMetadataServer() {
    AuthWithCredentialsFromMetadataServer.authWithCredentialsFromMetadataServer(PROJECT_ID);
    assertThat(stdOut.toString()).contains("Authentication complete.");
  }

}
