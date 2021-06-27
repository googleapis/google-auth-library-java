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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.io.IOException;

import com.google.api.client.http.HttpResponse;
import com.google.auth.TestUtils;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import org.junit.Before;
import org.junit.Test;

public final class ServiceAccountTest {
    
@Test
  public void NoScopeNoAudienceTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("C:\\Users\\timur\\Documents\\Work\\keys\\gcloud-devel-stim-test-5aede6a71838.json"));
    // = GoogleCredentials.getApplicationDefault()
    //.createScoped("https://www.googleapis.com/auth/cloud-platform");
    
    //TODO remove authUri from the key, check that it works with default audience
    //TODO: check it is actually JWTCredential
    executeRequestWithCredentials(credentials, 200);
  }

  public void AudienceSetNoScopeTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("C:\\Users\\timur\\Documents\\Work\\keys\\gcloud-devel-stim-test-5aede6a71838.json"));
    // = GoogleCredentials.getApplicationDefault()
    //.createScoped("https://www.googleapis.com/auth/cloud-platform");
    
    executeRequestWithCredentials(credentials, 200);
  }

  public void ScopeSetNoAudienceTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("C:\\Users\\timur\\Documents\\Work\\keys\\gcloud-devel-stim-test-5aede6a71838.json"))
    // = GoogleCredentials.getApplicationDefault()
    .createScoped("https://www.googleapis.com/auth/cloud-platform");
    
    //TODO: check it is actually SACred
    executeRequestWithCredentials(credentials, 200);
  }

  public void WrongScopeTest() throws Exception {
    final GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("C:\\Users\\timur\\Documents\\Work\\keys\\gcloud-devel-stim-test-5aede6a71838.json"))
    // = GoogleCredentials.getApplicationDefault()
    .createScoped("some_scope");
    
    executeRequestWithCredentials(credentials, 200);
  }



  public void ScopeSetAudienceSetTest() {

  }

  private void executeRequestWithCredentials(GoogleCredentials credentials, int expectedStatusCode) throws IOException {
    HttpResponse response = TestUtils.executeRequestWithCredentials(TestUtils.computeUrl, credentials);
    assertEquals(expectedStatusCode, response.getStatusCode());

    response = TestUtils.executeRequestWithCredentials(TestUtils.bigQueryUrl, credentials);
    assertEquals(expectedStatusCode, response.getStatusCode());
    
    response = TestUtils.executeRequestWithCredentials(TestUtils.cloudTasksUrl, credentials);
    assertEquals(expectedStatusCode, response.getStatusCode());

    response = TestUtils.executeRequestWithCredentials(TestUtils.storageUrl, credentials);
    assertEquals(expectedStatusCode, response.getStatusCode());
  }
}
