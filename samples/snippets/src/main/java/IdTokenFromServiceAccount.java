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

import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenProvider.Option;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class IdTokenFromServiceAccount {

  public static void main(String[] args)
      throws IOException, ExecutionException, InterruptedException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.
    //  Using Service account key is discouraged. Please consider alternate approaches first.
    // Path to the service account json credential file.
    String jsonCredentialPath = "path-to-json-credential-file";

    // Provide the scopes that you might need to request to access Google APIs,
    // depending on the level of access you need.
    // For more information, see: https://developers.google.com/identity/protocols/oauth2/scopes
    // The best practice is to use the cloud-wide scope and use IAM to narrow the permissions.
    // https://cloud.google.com/docs/authentication#authorization_for_services
    String scope = "https://www.googleapis.com/auth/cloud-platform";

    // The service name for which the id token is requested. Service name refers to the
    // logical identifier of an API service, such as "pubsub.googleapis.com".
    String targetAudience = "iap.googleapis.com";

    getIdTokenFromServiceAccount(jsonCredentialPath, scope, targetAudience);
  }

  public static void getIdTokenFromServiceAccount(String jsonCredentialPath, String scope,
      String targetAudience)
      throws IOException {

    // Initialize the Service Account Credentials class with the path to the json file.
    ServiceAccountCredentials serviceAccountCredentials = ServiceAccountCredentials.fromStream(
        new FileInputStream(jsonCredentialPath));
    // Restrict the scope of the service account.
    serviceAccountCredentials = (ServiceAccountCredentials) serviceAccountCredentials.createScoped(
        Arrays.asList(scope));

    // Obtain the id token by providing the target audience.
    // tokenOption: Enum of various credential-specific options to apply to the token. Applicable
    // only for credentials obtained through Compute Engine or Impersonation.
    List<Option> tokenOption = Arrays.asList();
    IdToken idToken = serviceAccountCredentials.idTokenWithAudience(
        targetAudience,
        tokenOption);

    // The following method can also be used to generate the ID token.
    // IdTokenCredentials idTokenCredentials = IdTokenCredentials.newBuilder()
    //     .setIdTokenProvider(serviceAccountCredentials)
    //     .setTargetAudience(targetAudience)
    //     .build();

    System.out.printf("Generated ID token %s", idToken.getTokenValue());
  }
}