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

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.iamcredentials.v1.IAMCredentials;
import com.google.api.services.iamcredentials.v1.IAMCredentials.Projects.ServiceAccounts.GenerateIdToken;
import com.google.api.services.iamcredentials.v1.model.GenerateIdTokenRequest;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class IdTokenFromImpersonatedCredentials {

  public static void main(String[] args) throws IOException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.

    // Your Google Cloud project id.
    String projectId = "your-google-cloud-project-id";

    // Path to the service account json credential file.
    String jsonCredentialPath = "path-to-json-credential-file";

    // Provide the scopes that you might need to request to access Google APIs,
    // depending on the level of access you need.
    // Example: The following scope lets you view and manage Pub/Sub topics and subscriptions.
    // For more information, see: https://developers.google.com/identity/protocols/oauth2/scopes
    String scope = "https://www.googleapis.com/auth/pubsub";

    // The service name for which the id token is requested. Service name refers to the
    // logical identifier of an API service, such as "pubsub.googleapis.com".
    String targetAudience = "pubsub.googleapis.com";

    // The service account name of the limited-privilege account for whom the credential is created.
    String impersonatedServiceAccount = "name@project.service.gserviceaccount.com";

    getIdTokenFromImpersonatedCredentials(
        projectId, jsonCredentialPath, impersonatedServiceAccount, scope, targetAudience);
  }

  public static void getIdTokenFromImpersonatedCredentials(
      String projectId,
      String jsonCredentialPath,
      String impersonatedServiceAccount,
      String scope,
      String targetAudience)
      throws GeneralSecurityException, IOException {

    // Initialize the IAMCredentials service with the source credential and scope.
    IAMCredentials service = null;
    try {
      service = initService(jsonCredentialPath, scope);
    } catch (IOException | GeneralSecurityException e) {
      System.out.println("Unable to initialize service: \n" + e);
      return;
    }

    // delegates: The chained list of delegates required to grant the final accessToken.
    //
    // If set, the sequence of identities must have "Service Account Token Creator" capability
    // granted to the preceding identity.
    // For example, if set to [serviceAccountB, serviceAccountC], the source credential must have
    // the Token Creator role on serviceAccountB. serviceAccountB must have the Token Creator on
    // serviceAccountC. Finally, C must have Token Creator on impersonatedServiceAccount.
    //
    // If left unset, source credential must have that role on impersonatedServiceAccount.
    List<String> delegates = null;

    // Set the target audience and Token options.
    GenerateIdTokenRequest idTokenRequest =
        new GenerateIdTokenRequest()
            .setAudience(targetAudience)
            .setDelegates(delegates)
            // Setting this will include email in the id token.
            .setIncludeEmail(Boolean.TRUE);

    // Generate the id token for the impersonated service account, using the generateIdToken()
    // from IAMCredentials class.
    GenerateIdToken idToken =
        service
            .projects()
            .serviceAccounts()
            .generateIdToken(
                String.format(
                    "projects/%s/serviceAccounts/%s", projectId, impersonatedServiceAccount),
                idTokenRequest);

    // Verify the obtained id token. This is done at the receiving end of the OIDC endpoint.
    boolean isVerified = verifyGoogleIdToken(idToken.getAccessToken(), targetAudience);
    if (isVerified) {
      System.out.println("Id token verified.");
      return;
    }
    System.out.println("Unable to verify id token.");
  }

  private static IAMCredentials initService(String jsonCredentialPath, String scope)
      throws GeneralSecurityException, IOException {
    GoogleCredentials credential =
        GoogleCredentials.fromStream(new FileInputStream(jsonCredentialPath))
            .createScoped(Arrays.asList(scope));

    // Initialize the IAMCredentials service.
    return new IAMCredentials.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            GsonFactory.getDefaultInstance(),
            new HttpCredentialsAdapter(credential))
        .setApplicationName("service-accounts")
        .build();
  }

  // Verifies the obtained Google id token.
  private static boolean verifyGoogleIdToken(String idTokenString, String audience)
      throws GeneralSecurityException, IOException {
    // Initialize the Google id token verifier and set the audience.
    GoogleIdTokenVerifier verifier =
        new GoogleIdTokenVerifier.Builder(
                GoogleNetHttpTransport.newTrustedTransport(), GsonFactory.getDefaultInstance())
            .setAudience(Collections.singletonList(audience))
            .build();

    // Verify the id token.
    GoogleIdToken idToken = verifier.verify(idTokenString);
    if (idToken != null) {
      Payload payload = idToken.getPayload();
      // Get the user id.
      String userId = payload.getSubject();
      System.out.println("User ID: " + userId);

      // Optionally, if "INCLUDE_EMAIL" was set in the "IdTokenProvider.Option", check if the
      // email was verified.
      boolean emailVerified = payload.getEmailVerified();
      System.out.printf("Email verified: %s", emailVerified);
      return true;
    }
    return false;
  }
}
