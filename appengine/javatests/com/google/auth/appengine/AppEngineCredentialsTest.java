/*
 * Copyright 2015, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

package com.google.auth.appengine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertNotSame;

import com.google.auth.Credentials;
import com.google.auth.oauth2.GoogleCredentials;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for AppEngineCredentials
 */
@RunWith(JUnit4.class)
public class AppEngineCredentialsTest {
  
  private static final Collection<String> SCOPES =
      Collections.unmodifiableCollection(Arrays.asList("scope1", "scope2"));
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  
  @Test  
  public void constructor_usesAppIdentityService() throws IOException {
    final String expectedAccessToken = "ExpectedAccessToken";

    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setAccessTokenText(expectedAccessToken);
    Credentials credentials = new AppEngineCredentials(SCOPES, appIdentity);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    assertEquals(1, appIdentity.getGetAccessTokenCallCount());
    assertContainsBearerToken(metadata, expectedAccessToken);
  }

  @Test  
  public void createScoped_clonesWithScopes() throws IOException {
    final String expectedAccessToken = "ExpectedAccessToken";
    final Collection<String> emptyScopes = Collections.emptyList();

    MockAppIdentityService appIdentity = new MockAppIdentityService();
    appIdentity.setAccessTokenText(expectedAccessToken);

    GoogleCredentials credentials = new AppEngineCredentials(emptyScopes, appIdentity);
    
    assertTrue(credentials.createScopedRequired());
    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Should not be able to use credential without scopes.");
    } catch (Exception expected) {
    }
    assertEquals(0, appIdentity.getGetAccessTokenCallCount());

    GoogleCredentials scopedCredentials = credentials.createScoped(SCOPES);
    assertNotSame(credentials, scopedCredentials);
    
    Map<String, List<String>> metadata = scopedCredentials.getRequestMetadata(CALL_URI);

    assertEquals(1, appIdentity.getGetAccessTokenCallCount());
    assertContainsBearerToken(metadata, expectedAccessToken);
  }
  
  private static void assertContainsBearerToken(Map<String, List<String>> metadata, String token) {
    assertNotNull(metadata);
    assertNotNull(token);
    String expectedValue = "Bearer " + token;
    List<String> authorizations = metadata.get("Authorization");
    assertNotNull("Authorization headers not found", authorizations);
    boolean found = false;
    for (String authorization : authorizations) {
      if (expectedValue.equals(authorization)) {
        found = true;
        break;
      }
    }
    assertTrue("Bearer token not found", found);
  }
}
