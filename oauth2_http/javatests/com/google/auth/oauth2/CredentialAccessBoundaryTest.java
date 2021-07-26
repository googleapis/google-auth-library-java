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

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.google.auth.oauth2.CredentialAccessBoundary.AccessBoundaryRule;
import com.google.auth.oauth2.CredentialAccessBoundary.AccessBoundaryRule.AvailabilityCondition;
import java.util.ArrayList;
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

    AccessBoundaryRule first = credentialAccessBoundary.getAccessBoundaryRules().get(0);
    assertEquals(firstRule, first);
    assertEquals("firstResource", first.getAvailableResource());
    assertEquals(1, first.getAvailablePermissions().size());
    assertEquals("firstPermission", first.getAvailablePermissions().get(0));
    assertEquals(availabilityCondition, first.getAvailabilityCondition());
    assertEquals("expression", first.getAvailabilityCondition().getExpression());
    assertNull(first.getAvailabilityCondition().getTitle());
    assertNull(first.getAvailabilityCondition().getDescription());

    AccessBoundaryRule second = credentialAccessBoundary.getAccessBoundaryRules().get(1);
    assertEquals(secondRule, second);
    assertEquals("secondResource", second.getAvailableResource());
    assertEquals(1, second.getAvailablePermissions().size());
    assertEquals("secondPermission", second.getAvailablePermissions().get(0));
    assertNull(second.getAvailabilityCondition());
  }

  @Test
  public void credentialAccessBoundary_nullRules_throws() {
    try {
      CredentialAccessBoundary.newBuilder().build();
      fail("Should fail.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void credentialAccessBoundary_withoutRules_throws() {
    try {
      CredentialAccessBoundary.newBuilder().setRules(new ArrayList<AccessBoundaryRule>()).build();
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
        AvailabilityCondition.newBuilder()
            .setExpression("expression")
            .setTitle("title")
            .setDescription("description")
            .build();

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
            + "\"availabilityCondition\":{\"expression\":\"expression\","
            + "\"title\":\"title\",\"description\":\"description\"}},"
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
  public void accessBoundaryRule_withEmptyAvailableResource_throws() {
    try {
      AccessBoundaryRule.newBuilder()
          .setAvailableResource("")
          .addAvailablePermission("permission")
          .build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("The provided availableResource is empty.", e.getMessage());
    }
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
  public void accessBoundaryRule_withEmptyAvailablePermissions_throws() {
    try {
      AccessBoundaryRule.newBuilder()
          .setAvailableResource("resource")
          .setAvailablePermissions(new ArrayList<String>())
          .build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("The list of provided availablePermissions is empty.", e.getMessage());
    }
  }

  @Test
  public void accessBoundaryRule_withNullAvailablePermissions_throws() {
    try {
      AccessBoundaryRule.newBuilder()
          .setAvailableResource("resource")
          .addAvailablePermission(null)
          .build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("One of the provided available permissions is null.", e.getMessage());
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
      assertEquals("One of the provided available permissions is empty.", e.getMessage());
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

  @Test
  public void availabilityCondition_emptyExpression_throws() {
    try {
      AvailabilityCondition.newBuilder().setExpression("").build();
      fail("Should fail.");
    } catch (IllegalArgumentException e) {
      assertEquals("The provided expression is empty.", e.getMessage());
    }
  }
}
