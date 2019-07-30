/*
 * Copyright 2016, Google Inc. All rights reserved.
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Date;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for AccessToken */
@RunWith(JUnit4.class)
public class AccessTokenTest extends BaseSerializationTest {

  private static final String TOKEN = "AccessToken";
  private static final Date EXPIRATION_DATE = new Date();

  @Test
  public void constructor() {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    assertEquals(TOKEN, accessToken.getTokenValue());
    assertEquals(EXPIRATION_DATE, accessToken.getExpirationTime());
    assertEquals(EXPIRATION_DATE.getTime(), (long) accessToken.getExpirationTimeMillis());
  }

  @Test
  public void equals_true() throws IOException {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    AccessToken otherAccessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    assertTrue(accessToken.equals(otherAccessToken));
    assertTrue(otherAccessToken.equals(accessToken));
  }

  @Test
  public void equals_false_token() throws IOException {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    AccessToken otherAccessToken = new AccessToken("otherToken", EXPIRATION_DATE);
    assertFalse(accessToken.equals(otherAccessToken));
    assertFalse(otherAccessToken.equals(accessToken));
  }

  @Test
  public void equals_false_expirationDate() throws IOException {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    AccessToken otherAccessToken = new AccessToken(TOKEN, new Date(EXPIRATION_DATE.getTime() + 42));
    assertFalse(accessToken.equals(otherAccessToken));
    assertFalse(otherAccessToken.equals(accessToken));
  }

  @Test
  public void toString_containsFields() {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    String expectedToString =
        String.format(
            "AccessToken{tokenValue=%s, expirationTimeMillis=%d}",
            TOKEN, EXPIRATION_DATE.getTime());
    assertEquals(expectedToString, accessToken.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    AccessToken otherAccessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    assertEquals(accessToken.hashCode(), otherAccessToken.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    AccessToken accessToken = new AccessToken(TOKEN, EXPIRATION_DATE);
    AccessToken deserializedAccessToken = serializeAndDeserialize(accessToken);
    assertEquals(accessToken, deserializedAccessToken);
    assertEquals(accessToken.hashCode(), deserializedAccessToken.hashCode());
    assertEquals(accessToken.toString(), deserializedAccessToken.toString());
  }
}
