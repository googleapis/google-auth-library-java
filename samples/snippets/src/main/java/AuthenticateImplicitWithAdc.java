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

// [START auth_cloud_implicit_adc]

import com.google.cloud.compute.v1.Instance;
import com.google.cloud.compute.v1.InstancesClient;
import java.io.IOException;

public class AuthenticateImplicitWithAdc {

  public static void main(String[] args) throws IOException {
    // TODO(Developer):
    //  1. Before running this sample,
    //  set up ADC as described in https://cloud.google.com/docs/authentication/external/set-up-adc
    //  2. Replace the project variable below.
    //  3. Make sure that the user account or service account that you are using
    //  has the required permissions. For this sample, you must have "compute.instances.list".
    String projectId = "your-google-cloud-project-id";
    authenticateImplicitWithAdc(projectId);
  }

  // When interacting with Google Cloud Client libraries, the library can auto-detect the
  // credentials to use.
  public static void authenticateImplicitWithAdc(String project) throws IOException {

    String zone = "us-central1-a";
    // This snippet demonstrates how to list instances.
    // *NOTE*: Replace the client created below with the client required for your application.
    // Note that the credentials are not specified when constructing the client.
    // Hence, the client library will look for credentials using ADC.
    //
    // Initialize client that will be used to send requests. This client only needs to be created
    // once, and can be reused for multiple requests. After completing all of your requests, call
    // the `instancesClient.close()` method on the client to safely
    // clean up any remaining background resources.
    try (InstancesClient instancesClient = InstancesClient.create()) {
      // Set the project and zone to retrieve instances present in the zone.
      System.out.printf("Listing instances from %s in %s:", project, zone);
      for (Instance zoneInstance : instancesClient.list(project, zone).iterateAll()) {
        System.out.println(zoneInstance.getName());
      }
      System.out.println("####### Listing instances complete #######");
    }
  }
}
// [END auth_cloud_implicit_adc]
