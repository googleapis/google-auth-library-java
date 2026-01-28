/*
 * Copyright 2026, Google Inc. All rights reserved.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class AppEngineDeserializationSecurityTest {

  /** A class that does not implement HttpTransportFactory. */
  static class ArbitraryClass {}

  @Test
  void testArbitraryClassInstantiationPrevented() throws Exception {
    // 1. Create valid credentials
    AppEngineCredentials credentials =
        AppEngineCredentials.newBuilder().setScopes(Collections.singleton("scope")).build();

    // 2. Use reflection to set appIdentityServiceClassName to ArbitraryClass
    // as the setter must be of AppIdentityService
    Field classNameField =
        AppEngineCredentials.class.getDeclaredField("appIdentityServiceClassName");
    classNameField.setAccessible(true);
    classNameField.set(credentials, ArbitraryClass.class.getName());

    // 3. Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(credentials);
    oos.close();

    // 4. Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
    ObjectInputStream ois = new ObjectInputStream(bis);

    // 5. Assert that IOException is thrown (validation failure)
    assertThrows(IOException.class, ois::readObject);
  }

  @Test
  void testValidServiceDeserialization() throws Exception {
    // 1. Create valid credentials with MockAppIdentityService
    MockAppIdentityService mockService = new MockAppIdentityService();
    AppEngineCredentials credentials =
        AppEngineCredentials.newBuilder()
            .setScopes(Collections.singleton("scope"))
            .setAppIdentityService(mockService)
            .build();

    // 2. Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(credentials);
    oos.close();

    // 3. Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
    ObjectInputStream ois = new ObjectInputStream(bis);

    AppEngineCredentials deserialized = (AppEngineCredentials) ois.readObject();

    // 4. Verify deserialization success and field type
    assertNotNull(deserialized);
    Field serviceField = AppEngineCredentials.class.getDeclaredField("appIdentityService");
    serviceField.setAccessible(true);
    Object service = serviceField.get(deserialized);
    assertEquals(MockAppIdentityService.class, service.getClass());
  }

  @Test
  void testNonExistentClassDeserialization() throws Exception {
    // 1. Create valid credentials
    AppEngineCredentials credentials =
        AppEngineCredentials.newBuilder().setScopes(Collections.singleton("scope")).build();

    // 2. Use reflection to set appIdentityServiceClassName to non-existent class
    Field classNameField =
        AppEngineCredentials.class.getDeclaredField("appIdentityServiceClassName");
    classNameField.setAccessible(true);
    classNameField.set(credentials, "com.google.nonexistent.Class");

    // 3. Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(credentials);
    oos.close();

    // 4. Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
    ObjectInputStream ois = new ObjectInputStream(bis);

    // 5. Assert ClassNotFoundException
    assertThrows(ClassNotFoundException.class, ois::readObject);
  }
}
