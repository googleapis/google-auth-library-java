/*
 * Copyright 2019, Google LLC
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

package com.google.auth.oauth2;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class JwtClaimsTest {

  @Test
  public void testMergeOverwritesFields() {
    JwtClaims claims1 =
        JwtClaims.newBuilder()
            .setAudience("audience-1")
            .setIssuer("issuer-1")
            .setSubject("subject-1")
            .build();
    JwtClaims claims2 =
        JwtClaims.newBuilder()
            .setAudience("audience-2")
            .setIssuer("issuer-2")
            .setSubject("subject-2")
            .build();
    JwtClaims merged = claims1.merge(claims2);

    assertEquals("audience-2", merged.getAudience());
    assertEquals("issuer-2", merged.getIssuer());
    assertEquals("subject-2", merged.getSubject());
  }

  @Test
  public void testMergeDefaultValues() {
    JwtClaims claims1 =
        JwtClaims.newBuilder()
            .setAudience("audience-1")
            .setIssuer("issuer-1")
            .setSubject("subject-1")
            .build();
    JwtClaims claims2 = JwtClaims.newBuilder().setAudience("audience-2").build();
    JwtClaims merged = claims1.merge(claims2);

    assertEquals("audience-2", merged.getAudience());
    assertEquals("issuer-1", merged.getIssuer());
    assertEquals("subject-1", merged.getSubject());
  }

  @Test
  public void testMergeNull() {
    JwtClaims claims1 = JwtClaims.newBuilder().build();
    JwtClaims claims2 = JwtClaims.newBuilder().build();
    JwtClaims merged = claims1.merge(claims2);

    assertNull(merged.getAudience());
    assertNull(merged.getIssuer());
    assertNull(merged.getSubject());
    assertNotNull(merged.getAdditionalClaims());
    assertTrue(merged.getAdditionalClaims().isEmpty());
  }

  @Test
  public void testEquals() {
    JwtClaims claims1 =
        JwtClaims.newBuilder()
            .setAudience("audience-1")
            .setIssuer("issuer-1")
            .setSubject("subject-1")
            .build();
    JwtClaims claims2 =
        JwtClaims.newBuilder()
            .setAudience("audience-1")
            .setIssuer("issuer-1")
            .setSubject("subject-1")
            .build();

    assertEquals(claims1, claims2);
  }

  @Test
  public void testAdditionalClaimsDefaults() {
    JwtClaims claims = JwtClaims.newBuilder().build();
    assertNotNull(claims.getAdditionalClaims());
    assertTrue(claims.getAdditionalClaims().isEmpty());
  }

  @Test
  public void testMergeAdditionalClaims() {
    JwtClaims claims1 =
        JwtClaims.newBuilder().setAdditionalClaims(Collections.singletonMap("foo", "bar")).build();
    JwtClaims claims2 =
        JwtClaims.newBuilder()
            .setAdditionalClaims(Collections.singletonMap("asdf", "qwer"))
            .build();
    JwtClaims merged = claims1.merge(claims2);

    assertNull(merged.getAudience());
    assertNull(merged.getIssuer());
    assertNull(merged.getSubject());
    Map<String, String> mergedAdditionalClaims = merged.getAdditionalClaims();
    assertNotNull(mergedAdditionalClaims);
    assertEquals(2, mergedAdditionalClaims.size());
    assertEquals("bar", mergedAdditionalClaims.get("foo"));
    assertEquals("qwer", mergedAdditionalClaims.get("asdf"));
  }
}
