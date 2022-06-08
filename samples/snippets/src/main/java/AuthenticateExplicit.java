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

import com.google.api.gax.paging.Page;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.common.collect.Lists;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class AuthenticateExplicit {

  public static void main(String[] args) throws IOException, GeneralSecurityException {
    // TODO(Developer):
    //  1. Replace the below variable.
    //  2. Make sure you have the necessary permission to list storage buckets
    // "storage.buckets.list"
    String projectId = "your-google-cloud-project-id";

    // Path to the service account json credential file.
    String jsonCredentialPath = "path-to-json-credential-file";

    // Provide the scopes that you might need to request to access Google APIs,
    // depending on the level of access you need.
    // Example: The following scope lets you view and manage Pub/Sub topics and subscriptions.
    // For more information, see: https://developers.google.com/identity/protocols/oauth2/scopes
    String scope = "https://www.googleapis.com/auth/devstorage.full_control";

    authenticateExplicit(projectId, jsonCredentialPath, scope);
  }

  // Authenticating using Client libraries can be done in one of the following ways:
  // 1. Implicit authentication with ADC (Application Default Credentials)
  // 2. Explicit authentication by specifying the service account
  // 3. Authentication with service account credentials obtained from metadata server, like,
  // Compute Engine or App Engine etc.,
  // 4. Bring your own (BYO) access token
  // 5. Using API keys (for libraries that support)
  //
  // In this snippet, we demonstrate "Explicit authentication by specifying the service account".
  public static void authenticateExplicit(String project, String jsonCredentialPath, String scope)
      throws IOException {

    // This snippet demonstrates how to initialize Cloud Storage and list buckets.
    // Note that the credentials are explicitly specified when constructing the client.
    Storage storage = initService(project, jsonCredentialPath, scope);

    System.out.println("Buckets:");
    Page<Bucket> buckets = storage.list();
    for (Bucket bucket : buckets.iterateAll()) {
      System.out.println(bucket.toString());
    }
    System.out.println("Authentication complete.");
  }

  // Initialize the Storage client by explicitly setting the Service account to use.
  private static Storage initService(String projectId, String jsonCredentialPath, String scope)
      throws IOException {
    // Construct the GoogleCredentials object which accepts the service account json file and
    // scope as the input parameters.
    GoogleCredentials credentials =
        GoogleCredentials.fromStream(new FileInputStream(jsonCredentialPath))
            .createScoped(Lists.newArrayList(scope));

    // Construct the Storage client.
    // Note that, here we explicitly specify the service account to use.
    return StorageOptions.newBuilder()
        .setCredentials(credentials)
        .setProjectId(projectId)
        .build()
        .getService();
  }
}
