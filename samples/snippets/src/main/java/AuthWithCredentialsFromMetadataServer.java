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
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class AuthWithCredentialsFromMetadataServer {

  public static void main(String[] args) throws IOException, GeneralSecurityException {
    // TODO(Developer):
    //  1. Replace the below variable.
    //  2. Make sure you have the necessary permission to list storage buckets "storage.buckets.list"
    String projectId = "your-google-cloud-project-id";

    authWithCredentialsFromMetadataServer(projectId);
  }

  // Authenticating using Client libraries can be done in one of the following ways:
  // 1. Implicit authentication with ADC (Application Default Credentials)
  // 2. Explicit authentication by specifying the service account
  // 3. Authentication with service account credentials obtained from a metadata server, like,
  // Compute Engine or App Engine etc.,
  // 4. Bring your own (BYO) access token
  // 5. Using API keys (for libraries that support)
  //
  // In this snippet, we demonstrate "Authentication with service account credentials
  // obtained from a metadata server".
  public static void authWithCredentialsFromMetadataServer(String project) {

    // This snippet demonstrates how to initialize Cloud Storage and list buckets.
    // Note that the credentials are requested from the ComputeEngine metadata server.
    Storage storage = initService(project);

    System.out.println("Buckets:");
    Page<Bucket> buckets = storage.list();
    for (Bucket bucket : buckets.iterateAll()) {
      System.out.println(bucket.toString());
    }
    System.out.println("Authentication complete.");
  }

  // Initialize the Storage client by getting the Service account credentials
  // from a Metadata server.
  private static Storage initService(String projectId) {
    // Explicitly request the service account credentials from the ComputeEngine metadata server.
    GoogleCredentials credentials = ComputeEngineCredentials.create();

    // Alternately, if executing within AppEngine, you can get credentials as follows:
    // GoogleCredentials credentials = AppEngineCredentials.getApplicationDefault();

    // Construct the Storage client.
    // Note that, here we explicitly specify the service account to use.
    return StorageOptions.newBuilder()
        .setCredentials(credentials)
        .setProjectId(projectId)
        .build()
        .getService();
  }
}
