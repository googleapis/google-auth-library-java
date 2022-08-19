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

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import java.io.IOException;
import java.io.InputStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for ClientId */
@RunWith(JUnit4.class)
public class ClientIdTest {
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";

  @Test
  public void constructor() {
    ClientId clientId =
        ClientId.newBuilder().setClientId(CLIENT_ID).setClientSecret(CLIENT_SECRET).build();

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertEquals(CLIENT_SECRET, clientId.getClientSecret());
  }

  @Test(expected = NullPointerException.class)
  public void constructor_nullClientId_throws() {
    ClientId.newBuilder().setClientSecret(CLIENT_SECRET).build();
  }

  @Test
  public void constructor_nullClientSecret() {
    ClientId clientId = ClientId.newBuilder().setClientId(CLIENT_ID).build();
    assertEquals(CLIENT_ID, clientId.getClientId());
    assertNull(clientId.getClientSecret());
  }

  @Test
  public void fromJson_web() throws IOException {
    GenericJson json = writeClientIdJson("web", CLIENT_ID, CLIENT_SECRET);

    ClientId clientId = ClientId.fromJson(json);

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertEquals(CLIENT_SECRET, clientId.getClientSecret());
  }

  @Test
  public void fromJson_installed() throws IOException {
    GenericJson json = writeClientIdJson("installed", CLIENT_ID, CLIENT_SECRET);

    ClientId clientId = ClientId.fromJson(json);

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertEquals(CLIENT_SECRET, clientId.getClientSecret());
  }

  @Test
  public void fromJson_installedNoSecret() throws IOException {
    GenericJson json = writeClientIdJson("installed", CLIENT_ID, null);

    ClientId clientId = ClientId.fromJson(json);

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertNull(clientId.getClientSecret());
  }

  @Test(expected = IOException.class)
  public void fromJson_invalidType_throws() throws IOException {
    GenericJson json = writeClientIdJson("invalid", CLIENT_ID, null);

    ClientId.fromJson(json);
  }

  @Test(expected = IOException.class)
  public void fromJson_noClientId_throws() throws IOException {
    GenericJson json = writeClientIdJson("web", null, null);

    ClientId.fromJson(json);
  }

  @Test(expected = IOException.class)
  public void fromJson_zeroLengthClientId_throws() throws IOException {
    GenericJson json = writeClientIdJson("web", "", null);

    ClientId.fromJson(json);
  }

  @Test
  public void fromResource() throws IOException {
    ClientId clientId = ClientId.fromResource(ClientIdTest.class, "/client_secret.json");

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertEquals(CLIENT_SECRET, clientId.getClientSecret());
  }

  @Test(expected = NullPointerException.class)
  public void fromResource_badResource() throws IOException {
    ClientId.fromResource(ClientIdTest.class, "invalid.json");
  }

  @Test
  public void fromStream() throws IOException {
    String text =
        "{"
            + "\"web\": {"
            + "\"client_id\" : \""
            + CLIENT_ID
            + "\","
            + "\"client_secret\" : \""
            + CLIENT_SECRET
            + "\""
            + "}"
            + "}";
    InputStream stream = TestUtils.stringToInputStream(text);

    ClientId clientId = ClientId.fromStream(stream);

    assertEquals(CLIENT_ID, clientId.getClientId());
    assertEquals(CLIENT_SECRET, clientId.getClientSecret());
  }

  @Test
  public void fromStream_invalidJson_doesNotThrow() throws IOException {
    String invalidJson =
        "{"
            + "\"web\": {"
            + "\"client_id\" : \""
            + CLIENT_ID
            + "\","
            + "\"client_secret\" : \""
            + CLIENT_SECRET
            + "\""
            + "}"; // No closing brace
    InputStream stream = TestUtils.stringToInputStream(invalidJson);

    ClientId.fromStream(stream);
  }

  private GenericJson writeClientIdJson(String type, String clientId, String clientSecret) {
    GenericJson json = new GenericJson();
    GenericJson details = new GenericJson();
    if (clientId != null) {
      details.put("client_id", clientId);
    }
    if (clientSecret != null) {
      details.put("client_secret", clientSecret);
    }
    json.put(type, details);
    return json;
  }
}
