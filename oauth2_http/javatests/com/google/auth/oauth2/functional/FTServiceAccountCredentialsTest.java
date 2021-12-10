/*
 * Copyright 2021 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2.functional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.*;

import java.io.FileInputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

class FTServiceAccountCredentialsTest {
  private final String cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform";

  private final String cloudTasksUrl =
      "https://cloudtasks.googleapis.com/v2/projects/gcloud-devel/locations";
  private final String storageUrl =
      "https://storage.googleapis.com/storage/v1/b?project=gcloud-devel";
  private final String bigQueryUrl =
      "https://bigquery.googleapis.com/bigquery/v2/projects/gcloud-devel/datasets";
  private final String computeUrl =
      "https://compute.googleapis.com/compute/v1/projects/gcloud-devel/zones/us-central1-a/instances";

  @Test
  void NoScopeNoAudienceComputeTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(computeUrl);
    assertEquals(200, response.getStatusCode());
  }


  @Test
  void NoScopeNoAudienceOnePlatformTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(cloudTasksUrl);
    assertEquals(200, response.getStatusCode());
  }

  // TODO: add Storage case

  @Test
  void AudienceSetNoScopeTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();

    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider((IdTokenProvider) credentials)
            .setTargetAudience(cloudTasksUrl)
            .build();

    assertNull(tokenCredential.getIdToken());
    tokenCredential.refresh();
    IdToken idToken = tokenCredential.getIdToken();
    assertNotNull(idToken);
    assertTrue(idToken.getExpirationTime().getTime() > System.currentTimeMillis());
    JsonWebSignature jws =
        JsonWebSignature.parse(GsonFactory.getDefaultInstance(), idToken.getTokenValue());
    assertEquals(cloudTasksUrl, jws.getPayload().get("aud"));
    assertEquals("https://accounts.google.com", jws.getPayload().get("iss"));
  }

  @Test
  void ScopeSetNoAudienceStorageTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithScope(storageUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  void ScopeSetNoAudienceComputeTest() throws Exception {

    HttpResponse response = executeRequestWithCredentialsWithScope(computeUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  void ScopeSetNoAudienceBigQueryTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithScope(bigQueryUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  void ScopeSetNoAudienceOnePlatformTest() throws Exception {
    HttpResponse response =
        executeRequestWithCredentialsWithScope(cloudTasksUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  void WrongScopeComputeTest() throws Exception {
    executeRequestWrongScope(computeUrl);
  }

  @Test
  void WrongScopeStorageTest() throws Exception {
    executeRequestWrongScope(storageUrl);
  }

  @Test
  void WrongScopeBigQueryTest() throws Exception {
    executeRequestWrongScope(bigQueryUrl);
  }

  @Test
  void WrongScopeOnePlatformTest() throws Exception {
    executeRequestWrongScope(cloudTasksUrl);
  }

  @Test
  void TamperingTest() throws Exception {
      //GoogleCredentials credentials = ServiceAccountCredentials.fromStream(new FileInputStream("/Users/stim/Documents/keys/stellar-day-stim.json"));
      //GoogleCredentials credentials = ServiceAccountCredentials.fromStream(new FileInputStream("/Users/stim/Documents/keys/gcloud-devel-stim-test-5aede6a71838.json"));
    GoogleCredentials credentials = ServiceAccountCredentials.fromStream(new FileInputStream("/Users/stim/Documents/keys/GCP_sandbox.json"));
    String pkey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfDf4RVlqkP+O1YuTTIMhPfxH+z7q+AXjm1VaiDeARiRL/Ur13e1C/LnqYFzpR1thO0Lgf2O5k/K64DmwR9v5g62rh3kAwxLDwsW6vfxMbmvPCxPV4Iklx46WiGJFExdVSDJ8KdLnHBK5iDMauqFxA2U+0+ODn+tHby8VdK9p+OQOG+DSKYQqY8wnposetZEz7Bd2/fR64zlFUoYXymJKaC5F66x3UgEzfho3Rf0kQAqJEvhf6qsZsCDtojAkaUX8GOkbBIv8unlq6ONsl/xZs/7th+UG2rgxCij/0fVbwnYg1EiZtSKszyeCgEe8NlS5GMbWcqEGaupLgs56HI2wLAgMBAAECggEAEQG+gl0Q6RIZx3nRDNArCvED3BKbHZjrtAbosgA4zrcw7FMNBjsNybtvCVcmeby2uUqw/VrFNtAb4HtOS+d0kKlrbsZEZ9KINtxKAQLd6Kw7Vz6XHqbP4pkcS0ZENi3PHuxRjx0nBiQ2fy5tihxfbOGvl6Kq7bMQgGd77Xf1b11/D6s36pNnMZwDJzkpiw6JJgFn3rmW24vchmOPehYRz55yNoKCP0oBapp5+lO+C8kJJL5fE4LLdLGXbf5gcGExU8t6Y/MWEiywQOZxpdubibOhDO94Ag6OxKYqBAf8ehRjbuyEDOppwKY6el0aOQYj2KgrU9BmTcaM0AR8hw9CdQKBgQDU4niAE88iAh52oPtzXr0HA4tzFPKYE+f/D14JiecNzX5dJo3RJ4qg3THPtvl43jUvg4j8WgrqctpeD1X78z9E7vT0Mk6T5BCTpeUr5+Bnbq3BWYQcLqO8BGMb5Avo++fGF2N9F1ydYucpsGZFT6tAG9a1KvJZoOVKX5ztDQYudQKBgQC/RJK3hWieAhA5E7TyNcWkdLom24OeSzkjMIdGyt9MJhngzNJSQRIReTqxLahXRYuVSSlsllhnQMyJwm5i+dI2/HHnQ+ckIpP49gQiPDqnILDliTuzn2/TJg/0gqSXumjNcqPUoP9M4vzwrBCLNunqs8oUJ2nzg4KpiBLbETzgfwKBgCUWAvoE+WuqRNZTuxphIbsMEgoNVynJJfxYGAC/ZmIQL3hY1BHgupTFk/zkmldFFqzdVErqAMbRFVuXflozCQ2gN0onTWsUKxMdrmvUrFI4hMqPJqWmNl31wbJFKxH+eGUZA/rxy++bIDwx/88JTwMPFntfLPMSRX+MYpElWLNVAoGBAJT5LyFb+pkfWE1siQIiWbd250q+rSxMwMsk0CiWeQfRoVRTk/lXD2CmwM0hl72pwEddfbNDAsYhVW5zDxFuLYqAY6NSYyTk/cXqsFuN980WjFGr6uFD7JBUVBcI7nPzUA+9G9fQMilLnuFB03zrH5SbxmieLkrqAopTHwSbz4O3AoGAW6BkmEf9FmZZ3yVnUhoey9WsuNzIlIY1uMSsKYHQMu/rC+R2mZIcK5Bp+cw6LOK8mXVmx3y3Jzl3s6e922ej1WvlC7uWaz3UhjW+Xz/viSkxNj1SG/CJ9YC6o3UsDaasAHeta46i/nPBA4CSTDAJv8wbKxWjJB7iNVdpZx3qUrk=\n-----END PRIVATE KEY-----\n@";
    ServiceAccountCredentials serviceAccountCredentials =
            ServiceAccountCredentials.fromPkcs8(null, "1051310255110-compute@developer.gserviceaccount.com", pkey, null, null);
    //Storage storage = StorageOptions.newBuilder().setCredentials(serviceAccountCredentials)
      //      .setProjectId(projectId).build().getService();
      final String url =
            "https://storage.googleapis.com/storage/v1/b?project=api-6404308174320967819-640900";
      final String urlCompute =
            "https://compute.googleapis.com/compute/v1/projects/api-6404308174320967819-640900/zones/us-central1-a/instances";
      GenericUrl genericUrl = new GenericUrl(urlCompute);
      HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(serviceAccountCredentials);
      HttpTransport transport = new NetHttpTransport();
      HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
      HttpResponse resp = request.execute();
      assertEquals(200, resp.getStatusCode());
  }

  private void executeRequestWrongScope(String serviceUri) {
    String expectedMessage = "403 Forbidden";

    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                executeRequestWithCredentialsWithScope(
                    serviceUri, "https://www.googleapis.com/auth/adexchange.buyer"),
            "Should throw exception: " + expectedMessage);
    assertTrue(exception.getMessage().contains(expectedMessage));
  }

  private HttpResponse executeRequestWithCredentialsWithoutScope(String serviceUrl)
      throws IOException {
    GoogleCredentials credentials = ServiceAccountCredentials.fromStream(new FileInputStream("/Users/stim/Documents/keys/GCP_sandbox.json"));
    GenericUrl genericUrl = new GenericUrl(serviceUrl);
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpTransport transport = new NetHttpTransport();
    HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
    return request.execute();
  }

  private HttpResponse executeRequestWithCredentialsWithScope(String serviceUrl, String scope)
      throws IOException {

    final GoogleCredentials credentials =
        GoogleCredentials.getApplicationDefault().createScoped(scope);
    GenericUrl genericUrl = new GenericUrl(serviceUrl);
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpTransport transport = new NetHttpTransport();
    HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
    return request.execute();
  }
}
