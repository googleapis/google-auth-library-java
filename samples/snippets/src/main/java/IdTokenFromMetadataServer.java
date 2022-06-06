import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider.Option;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;

public class IdTokenFromMetadataServer {

  public static void main(String[] args)
      throws IOException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.

    // The service name for which the id token is requested. Service name refers to the
    // logical identifier of an API service, such as "pubsub.googleapis.com".
    String targetAudience = "pubsub.googleapis.com";

    getIdTokenFromMetadataServer(targetAudience);
  }

  // Every VM stores its metadata on a metadata server. You can query for default VM metadata,
  // such as the VM's host name, instance ID, and service account information programmatically
  // from within a VM.
  // Here, we query the service account information from the Metadata server exposed by the
  // ComputeEngine and use that information to obtain an id token.
  // Appengine 2nd Generation, Cloud Run or even Kubernetes engine's also expose a
  // metadata server.
  // For AppEngine, see: https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata#identifying_which_metadata_endpoint_to_use
  // For CloudRun container instance, see: https://cloud.google.com/run/docs/container-contract#metadata-server
  public static void getIdTokenFromMetadataServer(String targetAudience)
      throws GeneralSecurityException, IOException {

    // Optionally, you can also set scopes in computeEngineCredentials.
    ComputeEngineCredentials computeEngineCredentials = ComputeEngineCredentials.create();

    IdTokenCredentials idTokenCredentials = IdTokenCredentials.newBuilder()
        .setIdTokenProvider(computeEngineCredentials)
        .setTargetAudience(targetAudience)
        // Setting the id token options.
        .setOptions(Arrays.asList(Option.FORMAT_FULL, Option.LICENSES_TRUE))
        .build();

    // Make a http request with the idTokenCredentials to obtain the access token.
    // stsEndpoint: The Security Token Service exchanges Google or third-party credentials for a
    // short-lived access token to Google Cloud resources.
    // https://cloud.google.com/iam/docs/reference/sts/rest
    String stsEndpoint = "https://sts.googleapis.com/v1/token";
    makeAuthenticatedRequest(idTokenCredentials, stsEndpoint);

    // Verify the obtained id token. This is done at the receiving end of the OIDC endpoint.
    boolean isVerified = verifyGoogleIdToken(idTokenCredentials.getAccessToken().getTokenValue(),
        targetAudience);
    if (isVerified) {
      System.out.println("Id token verified.");
      return;
    }
    System.out.println("Unable to verify id token.");
  }

  // Makes a simple http get call.
  public static void makeAuthenticatedRequest(IdTokenCredentials idTokenCredentials, String url)
      throws IOException {
    GenericUrl genericUrl = new GenericUrl(url);
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(idTokenCredentials);
    HttpTransport transport = new NetHttpTransport();
    HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response = request.execute();
    System.out.println(response.parseAsString());
  }

  // Verifies the obtained Google id token.
  public static boolean verifyGoogleIdToken(String idTokenString, String audience)
      throws GeneralSecurityException, IOException {
    // Initialize the Google id token verifier and set the audience.
    GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
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
