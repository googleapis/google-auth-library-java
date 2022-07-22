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

// [START auth_cloud_explicit_adc]

import com.google.api.gax.paging.Page;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class AuthenticateExplicit {

  public static void main(String[] args) throws IOException, GeneralSecurityException {
    // TODO(Developer):
    //  1. Replace the project variable below.
    //  2. Make sure you have the necessary permission to list storage buckets "storage.buckets.list"

    String projectId = "your-google-cloud-project-id";

    // If you are authenticating to a Cloud API, you do not need to specify a scope;
    // use Application Default Credentials as described in
    // https://cloud.google.com/docs/authentication/external/set-up-adc.
    // If you need to provide a scope, specify it here.
    // For more information on scopes to use,
    // see: https://developers.google.com/identity/protocols/oauth2/scopes
    String scope = "https://www.googleapis.com/auth/PRODUCT_NAME";

    authenticateExplicit(projectId, scope);
  }

  // List storage buckets by authenticating with ADC.
  public static void authenticateExplicit(String project, String scope)
      throws IOException {

    // Initialize the storage client.
    Storage storage = initService(project, scope);

    System.out.println("Buckets:");
    Page<Bucket> buckets = storage.list();
    for (Bucket bucket : buckets.iterateAll()) {
      System.out.println(bucket.toString());
    }
    System.out.println("Authentication complete.");
  }

  // Initialize the Storage client using ADC (Application Default Credentials).
  private static Storage initService(String projectId, String scope)
      throws IOException {
    // Construct the GoogleCredentials object which obtains the default configuration from your
    // working environment.
    GoogleCredentials credentials = GoogleCredentials.getApplicationDefault().createScoped(scope);

    // Construct the Storage client.
    return StorageOptions.newBuilder()
        .setCredentials(credentials)
        .setProjectId(projectId)
        .build()
        .getService();
  }
}
// [END auth_cloud_explicit_adc]