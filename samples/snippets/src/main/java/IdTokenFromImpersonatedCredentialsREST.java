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
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider.Option;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class IdTokenFromImpersonatedCredentialsREST {

  public static void main(String[] args)
      throws IOException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.
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
    String impersonatedServiceAccount =
        "name@project.service.gserviceaccount.com";

    getIdTokenFromImpersonatedCredentials(jsonCredentialPath, impersonatedServiceAccount, scope,
        targetAudience);
  }

  // Use a service account (SA1) to impersonate as another service account (SA2) and obtain id token
  // for the impersonated account.
  // To obtain token for SA2, SA1 should have the "roles/iam.serviceAccountTokenCreator" permission
  // on SA2.
  public static void getIdTokenFromImpersonatedCredentials(String jsonCredentialPath,
      String impersonatedServiceAccount, String scope,
      String targetAudience) throws IOException, GeneralSecurityException {
    // Initialize the Service Account Credentials class with the path to the json file.
    // The caller who issues a request for the short-lived credentials.
    ServiceAccountCredentials serviceAccountCredentials = ServiceAccountCredentials.fromStream(
        new FileInputStream(jsonCredentialPath));
    // Restrict the scope of the service account.
    serviceAccountCredentials = (ServiceAccountCredentials) serviceAccountCredentials.createScoped(
        Arrays.asList("https://www.googleapis.com/auth/cloud-platform"));

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

    // Create the impersonated credential.
    ImpersonatedCredentials impersonatedCredentials = ImpersonatedCredentials.create(
        serviceAccountCredentials,
        impersonatedServiceAccount,
        delegates,
        Arrays.asList(scope),
        300);

    // Set the impersonated credential, target audience and token options.
    IdTokenCredentials idTokenCredentials = IdTokenCredentials.newBuilder()
        .setIdTokenProvider(impersonatedCredentials)
        .setTargetAudience(targetAudience)
        // Setting this will include email in the id token.
        .setOptions(Arrays.asList(Option.INCLUDE_EMAIL))
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
