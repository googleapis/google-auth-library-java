import java.util.Arrays;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

public class ServiceAccount {
public static void main(String[] args) throws Exception {
  // String bucketName = "byoid-test-gcs-bucket";
   String bucketName = "oidc-test";
  String url = "https://storage.googleapis.com/storage/v1/b/" + bucketName;

  GoogleCredentials googleCredentials = GoogleCredentials.getApplicationDefault();
  // Add scopes to the credentials. This will force the use of the OAuth2 access token flow
  // instead of the self-signed JWT flow.
  String[] scopes = new String[] { "https://www.googleapis.com/auth/cloud-platform" };

  googleCredentials = googleCredentials.createScoped(Arrays.asList(scopes));
  System.out.println(googleCredentials.getClass().getSimpleName());

  HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(googleCredentials);
  HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory(credentialsAdapter);
  HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

  JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
  request.setParser(parser);

  HttpResponse response = request.execute();
  System.out.println(String.format("Success: %s", response.parseAsString()));
}
    
}
