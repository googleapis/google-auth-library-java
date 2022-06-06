import com.google.cloud.compute.v1.Instance;
import com.google.cloud.compute.v1.InstancesClient;
import java.io.IOException;

public class ApplicationDefaultCredentialsImplicit {

  public static void main(String[] args) throws IOException {
    // TODO(Developer):
    //  1. Set the following environment variable before running the code.
    //  APPLICATION_DEFAULT_CREDENTIALS="path-to-the-service-account-json-credential-file"
    //  2. Replace the below variable.
    //  3. Make sure you have the necessary permission "compute.instances.list"
    String projectId = "your-google-cloud-project-id";
    authenticateImplicitWithAdc(projectId);
  }

  // ADC - Application Default Credentials
  // When interacting with Google Cloud Client libraries, the library can auto-detect the
  // credentials to use, if the "APPLICATION_DEFAULT_CREDENTIALS" is set.
  // This APPLICATION_DEFAULT_CREDENTIALS is an environment variable/ configuration.
  // This configuration can be made available to the code in various ways depending upon where the
  // code is executed.
  // Examples:
  // 1. If running your code in local development environment, just set the following environment
  // variable:
  //      APPLICATION_DEFAULT_CREDENTIALS="path-to-the-service-account-json-file"  OR
  // You can also set the ADC with gcloud if you have the gcloud installed:
  //      gcloud auth application-default login
  //
  // 2. When you use a Google Cloud cloud-based development environment such as Cloud Shell or
  // Cloud Code, the tool uses the credentials you provided when you logged in,
  // and manages any authorizations required.
  //
  // For more environments, see: https://cloud.devsite.corp.google.com/docs/authentication/provide-credentials-adc
  //
  // ADC detection is independent of the client library and language and works with all Cloud Client
  // libraries.
  public static void authenticateImplicitWithAdc(String project) throws IOException {

    String zone = "us-central1-a";
    // This snippet demonstrates how to initialize Cloud Compute Engine and list instances.
    // Note that the credentials are not specified when constructing the client.
    // Hence, the client library will look for credentials via the
    // environment variable GOOGLE_APPLICATION_CREDENTIALS.
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
