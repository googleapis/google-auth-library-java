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
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Clock;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.ServiceAccountCredentials;

import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.CodeSource;
import java.security.ProtectionDomain;

import org.junit.jupiter.api.Test;

class FTServiceAccountCredentialsTest {
  private final String cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform";

  private final String cloudTasksUrl =
      "https://cloudtasks.googleapis.com/v2/projects/gcloud-devel/locations";
  private final String storageUrl =
      "https://storage.googleapis.com/storage/v1/b?project=api-6404308174320967819-640900";
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
  void NoScopeNoAudienceBigQueryTest() throws Exception {
    HttpResponse response = executeRequestWithCredentialsWithoutScope(bigQueryUrl);
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
    System.out.println(extractVersion(com.google.auth.oauth2.ServiceAccountCredentials.class));
    System.out.println(extractVersion(org.apache.http.client.HttpClient.class));
    HttpResponse response = executeRequestWithCredentialsWithScope(storageUrl, cloudPlatformScope);
    assertEquals(200, response.getStatusCode());
  }

  
/**
 * Reads a library's version if the library contains a Maven pom.properties
 * file. You probably want to cache the output or write it to a constant.
 *
 * @param referenceClass any class from the library to check
 * @return an Optional containing the version String, if present
 */
public static Optional<String> extractVersion(
  final Class<?> referenceClass) {
  return Optional.ofNullable(referenceClass)
                 .map(cls -> unthrow(cls::getProtectionDomain))
                 .map(ProtectionDomain::getCodeSource)
                 .map(CodeSource::getLocation)
                 .map(url -> unthrow(url::openStream))
                 .map(is -> unthrow(() -> new JarInputStream(is)))
                 .map(jis -> readPomProperties(jis, referenceClass))
                 .map(props -> props.getProperty("version"));
}

/**
* Locate the pom.properties file in the Jar, if present, and return a
* Properties object representing the properties in that file.
*
* @param jarInputStream the jar stream to read from
* @param referenceClass the reference class, whose ClassLoader we'll be
* using
* @return the Properties object, if present, otherwise null
*/
private static Properties readPomProperties(
  final JarInputStream jarInputStream,
  final Class<?> referenceClass) {

  try {
      JarEntry jarEntry;
      while ((jarEntry = jarInputStream.getNextJarEntry()) != null) {
          String entryName = jarEntry.getName();
          if (entryName.startsWith("META-INF")
              && entryName.endsWith("pom.properties")) {

              Properties properties = new Properties();
              ClassLoader classLoader = referenceClass.getClassLoader();
              properties.load(classLoader.getResourceAsStream(entryName));
              return properties;
          }
      }
  } catch (IOException ignored) { }
  return null;
}

/**
* Wrap a Callable with code that returns null when an exception occurs, so
* it can be used in an Optional.map() chain.
*/
private static <T> T unthrow(final Callable<T> code) {
  try {
      return code.call();
  } catch (Exception ignored) { return null; }
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
