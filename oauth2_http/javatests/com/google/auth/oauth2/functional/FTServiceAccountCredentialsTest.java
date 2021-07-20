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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.junit.Test;

public final class FTServiceAccountCredentialsTest {
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
  public void NoScopeNoAudienceComputeTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(computeUrl);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void NoScopeNoAudienceBigQueryTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(bigQueryUrl);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void NoScopeNoAudienceOnePlatformTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(cloudTasksUrl);
    assertEquals(200, response.getStatusCode());
  }

  // TODO: add Storage case

  @Test
  public void AudienceSetNoScopeTest() throws Exception {
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
  public void ScopeSetNoAudienceStorageTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithScope(storageUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void ScopeSetNoAudienceComputeTest() throws Exception {

    HttpResponse response = executeRequestWithCredentialsWithScope(computeUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void ScopeSetNoAudienceBigQueryTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithScope(bigQueryUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void ScopeSetNoAudienceOnePlatformTest() throws Exception {
    HttpResponse response =
        executeRequestWithCredentialsWithScope(cloudTasksUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  @Test
  public void WrongScopeComputeTest() throws Exception {
    executeRequestWrongScope(computeUrl);
  }

  @Test
  public void WrongScopeStorageTest() throws Exception {
    executeRequestWrongScope(storageUrl);
  }

  @Test
  public void WrongScopeBigQueryTest() throws Exception {
    executeRequestWrongScope(bigQueryUrl);
  }

  @Test
  public void WrongScopeOnePlatformTest() throws Exception {
    executeRequestWrongScope(cloudTasksUrl);
  }

  private void executeRequestWrongScope(String serviceUri)
      throws FileNotFoundException, IOException {
    String expectedMessage = "403 Forbidden";

    try {
      executeRequestWithCredentialsWithScope(
          serviceUri, "https://www.googleapis.com/auth/adexchange.buyer");
      fail("Should throw exception: " + expectedMessage);
    } catch (IOException expected) {
      assertTrue(expected.getMessage().contains(expectedMessage));
    }
  }

  private HttpResponse executeRequestWithCredentialsWithoutScope(String serviceUrl)
      throws IOException {
    final GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
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
