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

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.iamcredentials.v1.IAMCredentials;
import com.google.api.services.iamcredentials.v1.IAMCredentials.Projects.ServiceAccounts.GenerateIdToken;
import com.google.api.services.iamcredentials.v1.model.GenerateIdTokenRequest;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class IdTokenFromImpersonatedCredentials_IAM {

  public static void main(String[] args)
      throws IOException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.

    // Your Google Cloud project id.
    String projectId = "your-google-cloud-project-id";

    // Provide the scopes that you might need to request to access Google APIs,
    // depending on the level of access you need.
    // The best practice is to use the cloud-wide scope and use IAM to narrow the permissions.
    // https://cloud.google.com/docs/authentication#authorization_for_services
    // For more information, see: https://developers.google.com/identity/protocols/oauth2/scopes
    String scope = "https://www.googleapis.com/auth/cloud-platform";

    // The service name for which the id token is requested. Service name refers to the
    // logical identifier of an API service, such as "pubsub.googleapis.com".
    String targetAudience = "iap.googleapis.com";

    // The service account name of the limited-privilege account for whom the credential is created.
    String impersonatedServiceAccount =
        "name@project.service.gserviceaccount.com";

    getIdTokenUsingIAM(projectId, impersonatedServiceAccount, scope, targetAudience);
  }

  // Use a service account (SA1) to impersonate as another service account (SA2) and obtain id token
  // for the impersonated account using the IAM library.
  // To obtain token for SA2, SA1 should have the "roles/iam.serviceAccountTokenCreator" permission
  // on SA2.
  public static void getIdTokenUsingIAM(String projectId, String impersonatedServiceAccount,
      String scope, String targetAudience)
      throws IOException {

    // Initialize the IAMCredentials service with the source credential and scope.
    IAMCredentials service = null;
    try {
      service = initService(scope);
    } catch (IOException | GeneralSecurityException e) {
      System.out.println("Unable to initialize service: \n" + e);
      return;
    }

    // Set the target audience and Token options.
    GenerateIdTokenRequest idTokenRequest = new GenerateIdTokenRequest()
        .setAudience(targetAudience)
        // Setting this will include email in the id token.
        .setIncludeEmail(Boolean.TRUE);

    // Generate the id token for the impersonated service account, using the generateIdToken()
    // from IAMCredentials class.
    GenerateIdToken idToken = service
        .projects()
        .serviceAccounts()
        .generateIdToken(
            String.format("projects/%s/serviceAccounts/%s", projectId, impersonatedServiceAccount),
            idTokenRequest);

    System.out.printf("Generated ID token: %s", idToken.getAccessToken());
  }

  // Initialize the IAM service.
  private static IAMCredentials initService(String scope)
      throws GeneralSecurityException, IOException {
    // Construct the GoogleCredentials object which obtains the default configuration from your
    // working environment.
    GoogleCredentials credential = GoogleCredentials.getApplicationDefault().createScoped(scope);

    // Initialize the IAMCredentials service.
    return new IAMCredentials.Builder(
        GoogleNetHttpTransport.newTrustedTransport(),
        GsonFactory.getDefaultInstance(),
        new HttpCredentialsAdapter(credential))
        .setApplicationName("service-accounts")
        .build();
  }

}
