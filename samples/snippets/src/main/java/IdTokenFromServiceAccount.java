import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenProvider.Option;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class IdTokenFromServiceAccount {

  public static void main(String[] args)
      throws IOException, ExecutionException, InterruptedException, GeneralSecurityException {
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

    getIdTokenFromServiceAccount(jsonCredentialPath, scope, targetAudience);
  }

  public static void getIdTokenFromServiceAccount(String jsonCredentialPath, String scope,
      String targetAudience)
      throws IOException, GeneralSecurityException {

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

    // Verify the obtained id token. This is done at the receiving end of the OIDC endpoint.
    boolean isVerified = verifyGoogleIdToken(idToken.getTokenValue(), targetAudience);
    if (isVerified) {
      System.out.println("Id token verified.");
      return;
    }
    System.out.println("Unable to verify id token.");
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
      // String email = payload.getEmail();
      // boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
      return true;
    }
    return false;
  }

}

//
// Iam service =
//     new Iam.Builder(
//         GoogleNetHttpTransport.newTrustedTransport(),
//         GsonFactory.getDefaultInstance(),
//         new HttpCredentialsAdapter(googleCredentials))
//         .setApplicationName("service-accounts")
//         .build();
//
// try {
//   ServiceAccount serviceAccount = new ServiceAccount();
//   serviceAccount.setDisplayName("serviceaccdummy");
//   CreateServiceAccountRequest request = new CreateServiceAccountRequest();
//   request.setAccountId("serviceAccountName");
//   request.setServiceAccount(serviceAccount);
//
//   serviceAccount =
//       service.projects().serviceAccounts().create("projects/" + projectId, request).execute();
//
//   System.out.println("Created service account: " + serviceAccount.getEmail());
//
//
// GenerateIdToken iamCredentials = new IAMCredentials(
//     GoogleNetHttpTransport.newTrustedTransport(),
//     GsonFactory.getDefaultInstance(),
//     new HttpCredentialsAdapter(googleCredentialsProvider)
// ).projects().serviceAccounts().generateIdToken(String.format("projects/%s/serviceAccounts/%s", projectId, serviceAccount),
//     new GenerateIdTokenRequest().setAudience("https://www.googleapis.com/auth/cloud-platform"));
//
// System.out.println(iamCredentials);
//
// } catch (IOException e) {
//   System.out.println("Unable to create service account: \n" + e.toString());
// }
