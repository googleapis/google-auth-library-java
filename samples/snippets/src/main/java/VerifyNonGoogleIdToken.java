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

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenProvider.Option;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class VerifyNonGoogleIdToken {

  public static void main(String[] args)
      throws IOException, ExecutionException, InterruptedException, GeneralSecurityException,
          JwkException {
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

    // To verify non-google tokens, get the Json Web Key endpoint (jwk).
    // OpenID Connect allows the use of a "Discovery document," a JSON document found at a
    // well-known location containing key-value pairs which provide details about the
    // OpenID Connect provider's configuration.
    // For more information on validating the jwt, see:
    // https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
    //
    // Here, we validate Google's token using Google's OpenID Connect service (jwkUrl).
    // For more information on jwk,see:
    // https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets
    String jwkUrl = "https://www.googleapis.com/oauth2/v3/certs";

    verifyNonGoogleIdToken(jsonCredentialPath, targetAudience, scope, jwkUrl);
  }

  // Verify a non-google id token. Here, we are using the Google's jwk. The procedure is the same
  // even if the jwk is from a different provider.
  public static void verifyNonGoogleIdToken(
      String jsonCredentialPath, String targetAudience, String scope, String jwkUrl)
      throws IOException, JwkException, GeneralSecurityException {
    // Create an id token from the given service account.
    // Since we are using Google's jwk, we are creating an id token from a Google service account.
    // If a different provider is used, then generate an id token accordingly.
    String idToken =
        getIdTokenFromServiceAccount(jsonCredentialPath, scope, targetAudience).getTokenValue();

    // Start verification.
    DecodedJWT jwt = JWT.decode(idToken);

    // Check if the token has expired.
    if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
      System.out.println("Token already expired..");
      return;
    }

    // Construct the jwkProvider from the provided jwkURL.
    JwkProvider jwkProvider = new UrlJwkProvider(new URL(jwkUrl));
    // Get the jwk from the provided key id.
    Jwk jwk = jwkProvider.get(jwt.getKeyId());
    // Retrieve the public key and use that to create an instance of the Algorithm.
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
    // Create the verifier with the algorithm and target audience.
    JWTVerifier jwtVerifier = JWT.require(algorithm).withAudience(targetAudience).build();

    boolean isVerified = true;
    try {
      // Verify the obtained id token. This is done at the receiving end of the OIDC endpoint.
      jwt = jwtVerifier.verify(idToken);
    } catch (JWTVerificationException e) {
      System.out.println("Could not verify Signature: " + e.getMessage());
      isVerified = false;
    }

    if (isVerified) {
      System.out.println("Id token verified.");
      return;
    }
    System.out.println("Unable to verify id token.");
  }

  // Get an id token from a Google service account.
  private static IdToken getIdTokenFromServiceAccount(
      String jsonCredentialPath, String scope, String targetAudience)
      throws IOException, GeneralSecurityException, JwkException {

    // Initialize the Service Account Credentials class with the path to the json file.
    ServiceAccountCredentials serviceAccountCredentials =
        ServiceAccountCredentials.fromStream(new FileInputStream(jsonCredentialPath));
    // Restrict the scope of the service account.
    serviceAccountCredentials =
        (ServiceAccountCredentials) serviceAccountCredentials.createScoped(Arrays.asList(scope));

    // Obtain the id token by providing the target audience.
    // tokenOption: Enum of various credential-specific options to apply to the token. Applicable
    // only for credentials obtained through Compute Engine or Impersonation.
    List<Option> tokenOption = Arrays.asList();
    IdToken idToken = serviceAccountCredentials.idTokenWithAudience(targetAudience, tokenOption);

    return idToken;
  }
}
