package com.google.auth.oauth2;

import static org.junit.Assert.*;

import com.google.auth.oauth2.CredentialAccessBoundary.AccessBoundaryRule;
import com.google.auth.oauth2.CredentialAccessBoundary.AccessBoundaryRule.AvailabilityCondition;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link CredentialAccessBoundary} and encompassing classes. */
@RunWith(JUnit4.class)
public class CredentialAccessBoundaryTest {

  @Test
  public void credentialAccessBoundary() {
    AvailabilityCondition availabilityCondition =
        AvailabilityCondition.newBuilder().setExpression("expression").build();

    AccessBoundaryRule firstRule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("firstResource")
            .addAvailablePermission("firstPermission")
            .setAvailabilityCondition(availabilityCondition)
            .build();

    AccessBoundaryRule secondRule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("secondResource")
            .addAvailablePermission("secondPermission")
            .build();

    CredentialAccessBoundary credentialAccessBoundary =
        CredentialAccessBoundary.newBuilder()
            .setRules(Arrays.asList(firstRule, secondRule))
            .build();

    assertEquals(2, credentialAccessBoundary.getAccessBoundaryRules().size());
    assertEquals(firstRule, credentialAccessBoundary.getAccessBoundaryRules().get(0));
    assertEquals(secondRule, credentialAccessBoundary.getAccessBoundaryRules().get(1));
  }

  @Test
  public void credentialAccessBoundary_withoutRules_throws() {
    try {
      CredentialAccessBoundary.newBuilder().build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("At least one access boundary rule must be provided.", e.getMessage());
    }
  }

  @Test
  public void credentialAccessBoundary_ruleCountExceeded_throws() {
    AccessBoundaryRule rule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("resource")
            .addAvailablePermission("permission")
            .build();

    CredentialAccessBoundary.Builder builder = CredentialAccessBoundary.newBuilder();
    for (int i = 0; i <= 10; i++) {
      builder.addRule(rule);
    }

    try {
      builder.build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("The provided list has more than 10 access boundary rules.", e.getMessage());
    }
  }

  @Test
  public void credentialAccessBoundary_toJson() {
    AvailabilityCondition availabilityCondition =
        AvailabilityCondition.newBuilder().setExpression("expression").build();

    AccessBoundaryRule firstRule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("firstResource")
            .addAvailablePermission("firstPermission")
            .setAvailabilityCondition(availabilityCondition)
            .build();

    AccessBoundaryRule secondRule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("secondResource")
            .setAvailablePermissions(Arrays.asList("firstPermission", "secondPermission"))
            .build();

    CredentialAccessBoundary credentialAccessBoundary =
        CredentialAccessBoundary.newBuilder()
            .setRules(Arrays.asList(firstRule, secondRule))
            .build();

    String expectedJson =
        "{\"accessBoundary\":{\"accessBoundaryRules\":"
            + "[{\"availableResource\":\"firstResource\","
            + "\"availablePermissions\":[\"firstPermission\"],"
            + "\"availabilityCondition\":{\"expression\":\"expression\"}},"
            + "{\"availableResource\":\"secondResource\","
            + "\"availablePermissions\":[\"firstPermission\","
            + "\"secondPermission\"]}]}}";
    assertEquals(expectedJson, credentialAccessBoundary.toJson());
  }

  @Test
  public void accessBoundaryRule_allFields() {
    AvailabilityCondition availabilityCondition =
        AvailabilityCondition.newBuilder().setExpression("expression").build();

    AccessBoundaryRule rule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("resource")
            .addAvailablePermission("firstPermission")
            .addAvailablePermission("secondPermission")
            .setAvailabilityCondition(availabilityCondition)
            .build();

    assertEquals("resource", rule.getAvailableResource());
    assertEquals(2, rule.getAvailablePermissions().size());
    assertEquals("firstPermission", rule.getAvailablePermissions().get(0));
    assertEquals("secondPermission", rule.getAvailablePermissions().get(1));
    assertEquals(availabilityCondition, rule.getAvailabilityCondition());
  }

  @Test
  public void accessBoundaryRule_requiredFields() {
    AccessBoundaryRule rule =
        AccessBoundaryRule.newBuilder()
            .setAvailableResource("resource")
            .setAvailablePermissions(Collections.singletonList("firstPermission"))
            .build();

    assertEquals("resource", rule.getAvailableResource());
    assertEquals(1, rule.getAvailablePermissions().size());
    assertEquals("firstPermission", rule.getAvailablePermissions().get(0));
    assertNull(rule.getAvailabilityCondition());
  }

  @Test
  public void accessBoundaryRule_withoutAvailableResource_throws() {
    try {
      AccessBoundaryRule.newBuilder().addAvailablePermission("permission").build();
      fail("Should fail.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void accessBoundaryRule_withoutAvailablePermissions_throws() {
    try {
      AccessBoundaryRule.newBuilder().setAvailableResource("resource").build();
      fail("Should fail.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void accessBoundaryRule_withNullAvailablePermission_throws() {
    try {
      AccessBoundaryRule.newBuilder()
          .setAvailableResource("resource")
          .addAvailablePermission(null)
          .build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          "One of the provided available permissions is either null or empty.", e.getMessage());
    }
  }

  @Test
  public void accessBoundaryRule_withEmptyAvailablePermission_throws() {
    try {
      AccessBoundaryRule.newBuilder()
          .setAvailableResource("resource")
          .addAvailablePermission("")
          .build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          "One of the provided available permissions is either null or empty.", e.getMessage());
    }
  }

  @Test
  public void availabilityCondition_allFields() {
    AvailabilityCondition availabilityCondition =
        AvailabilityCondition.newBuilder()
            .setExpression("expression")
            .setTitle("title")
            .setDescription("description")
            .build();

    assertEquals("expression", availabilityCondition.getExpression());
    assertEquals("title", availabilityCondition.getTitle());
    assertEquals("description", availabilityCondition.getDescription());
  }

  @Test
  public void availabilityCondition_expressionOnly() {
    AvailabilityCondition availabilityCondition =
        AvailabilityCondition.newBuilder().setExpression("expression").build();

    assertEquals("expression", availabilityCondition.getExpression());
    assertNull(availabilityCondition.getTitle());
    assertNull(availabilityCondition.getDescription());
  }

  @Test
  public void availabilityCondition_nullExpression_throws() {
    try {
      AvailabilityCondition.newBuilder().setExpression(null).build();
      fail("Should fail.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }
}
