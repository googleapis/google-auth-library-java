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

  static class ArbitraryClass {
    public ArbitraryClass() {}
  }

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
