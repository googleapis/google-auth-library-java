package com.google.auth.oauth2.functional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import org.junit.Test;

public final class FTComputeEngineCredentialsTest {

  private final String cloudTasksUrl =
      "https://cloudtasks.googleapis.com/v2/projects/gcloud-devel/locations";
  private final String cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform";

  @Test
  public void RefreshCredentials() throws Exception {

    ComputeEngineCredentials credentials = ComputeEngineCredentials.create();

    AccessToken accessToken = credentials.refreshAccessToken();
    assertNotNull(accessToken);
    assertNotNull(credentials.getAccount());
    assertTrue(accessToken.getExpirationTime().getTime() > System.currentTimeMillis());
  }

  @Test
  public void DefaultCredentials() throws Exception {

    GoogleCredentials defaultCredential =
        GoogleCredentials.getApplicationDefault().createScoped(cloudPlatformScope);

    AccessToken accessToken = defaultCredential.refreshAccessToken();
    assertNotNull(accessToken);
    assertTrue(accessToken.getExpirationTime().getTime() > System.currentTimeMillis());
  }

  @Test
  public void IdTokenFromMetadata() throws Exception {

    ComputeEngineCredentials credentials = ComputeEngineCredentials.create();
    IdToken idToken = credentials.idTokenWithAudience(cloudTasksUrl, null);
    assertNotNull(idToken);
    assertTrue(idToken.getExpirationTime().getTime() > System.currentTimeMillis());
    JsonWebSignature jws =
        JsonWebSignature.parse(GsonFactory.getDefaultInstance(), idToken.getTokenValue());
    assertEquals(cloudTasksUrl, jws.getPayload().get("aud"));
    assertEquals("https://accounts.google.com", jws.getPayload().get("iss"));
  }

  @Test
  public void FetchIdToken() throws Exception {

    ComputeEngineCredentials credentials = ComputeEngineCredentials.create();

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
}
