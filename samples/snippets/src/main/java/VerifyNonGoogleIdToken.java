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

// [START auth_cloud_verify_non_google_idtoken]

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.concurrent.ExecutionException;

public class VerifyNonGoogleIdToken {

  public static void main(String[] args)
      throws IOException, ExecutionException, InterruptedException, GeneralSecurityException, JwkException {
    // TODO(Developer): Replace the below variables before running the code.
    // The non-Google ID token to verify.
    String idToken = "id-token";

    // The service name for which the id token is requested. Service name refers to the
    // logical identifier of an API service, such as "pubsub.googleapis.com".
    String targetAudience = "pubsub.googleapis.com";

    // To verify non-google tokens, get the Json Web Key endpoint (jwk).
    // OpenID Connect allows the use of a "Discovery document," a JSON document found at a
    // well-known location containing key-value pairs which provide details about the
    // OpenID Connect provider's configuration.
    // For more information on validating the jwt, see: https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
    //
    // Here, we validate Google's token using Google's OpenID Connect service (jwkUrl).
    // For more information on jwk,see: https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets
    String jwkUrl = "https://www.googleapis.com/oauth2/v3/certs";

    verifyNonGoogleIdToken(idToken, targetAudience, jwkUrl);
  }

  // Verify a non-google id token. Here, we are using the Google's jwk. The procedure is the same
  // even if the jwk is from a different provider.
  public static void verifyNonGoogleIdToken(String idToken, String targetAudience,
      String jwkUrl)
      throws IOException, JwkException {

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
    System.out.println("Unable to verify ID token.");
  }
}
// [END auth_cloud_verify_non_google_idtoken]