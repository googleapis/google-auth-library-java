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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.IdTokenProvider.Option;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class IdTokenFromMetadataServer {

  public static void main(String[] args)
      throws IOException, GeneralSecurityException {
    // TODO(Developer): Replace the below variables before running the code.

    // The url or target audience to obtain the ID token for.
    String url = "http://www.abc.com";

    getIdTokenFromMetadataServer(url);
  }

  // Use the Google Cloud metadata server in the Cloud Run (or AppEngine or Kubernetes etc.,)
  // environment to create an identity token and add it to the HTTP request as part of an
  // Authorization header.
  public static void getIdTokenFromMetadataServer(String url)
      throws IOException {
    // Construct the GoogleCredentials object which obtains the default configuration from your
    // working environment.
    // Optionally, you can also set scopes.
    GoogleCredentials googleCredentials = GoogleCredentials.getApplicationDefault();

    IdTokenCredentials idTokenCredentials = IdTokenCredentials.newBuilder()
        .setIdTokenProvider((IdTokenProvider) googleCredentials)
        .setTargetAudience(url)
        // Setting the ID token options.
        .setOptions(Arrays.asList(Option.FORMAT_FULL, Option.LICENSES_TRUE))
        .build();

    // Get the ID token.
    System.out.printf("Generated ID token: %s", idTokenCredentials.refreshAccessToken().getTokenValue());

    // Make an authenticated HTTP request with the idTokenCredentials.
    makeAuthenticatedRequest(idTokenCredentials, url);
  }

  // Create a new HTTP request authenticated by a JSON Web Tokens (JWT)
  // retrieved from Application Default Credentials.
  private static void makeAuthenticatedRequest(IdTokenCredentials idTokenCredentials, String url)
      throws IOException {
    GenericUrl genericUrl = new GenericUrl(url);
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(idTokenCredentials);
    HttpTransport transport = new NetHttpTransport();
    HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response = request.execute();
    System.out.println(response.parseAsString());
  }
}
