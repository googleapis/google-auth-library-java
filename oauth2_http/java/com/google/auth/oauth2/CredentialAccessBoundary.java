package com.google.auth.oauth2;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.api.client.json.GenericJson;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;

/** Defines an upper bound of permissions available for a GCP credential. */
final class CredentialAccessBoundary {

  private static final int RULES_SIZE_LIMIT = 10;

  private final List<AccessBoundaryRule> accessBoundaryRules;

  CredentialAccessBoundary(List<AccessBoundaryRule> accessBoundaryRules) {
    this.accessBoundaryRules = checkNotNull(accessBoundaryRules);
    if (accessBoundaryRules.isEmpty()) {
      throw new IllegalArgumentException("At least one access boundary rule must be provided.");
    }
    if (accessBoundaryRules.size() > RULES_SIZE_LIMIT) {
      throw new IllegalArgumentException(
          "The provided list has more than 10 access boundary rules.");
    }
  }

  /**
   * Internal method that returns the JSON string representation of the credential access boundary.
   */
  String toJson() {
    List<GenericJson> rules = new ArrayList<>();
    for (AccessBoundaryRule rule : accessBoundaryRules) {
      GenericJson ruleJson = new GenericJson();
      ruleJson.setFactory(OAuth2Utils.JSON_FACTORY);

      ruleJson.put("availableResource", rule.getAvailableResource());
      ruleJson.put("availablePermissions", rule.getAvailablePermissions());

      AccessBoundaryRule.AvailabilityCondition availabilityCondition =
          rule.getAvailabilityCondition();
      if (availabilityCondition != null) {
        GenericJson availabilityConditionJson = new GenericJson();
        availabilityConditionJson.setFactory(OAuth2Utils.JSON_FACTORY);

        availabilityConditionJson.put("expression", availabilityCondition.getExpression());
        if (availabilityCondition.getTitle() != null) {
          availabilityConditionJson.put("title", availabilityCondition.getTitle());
        }
        if (availabilityCondition.getDescription() != null) {
          availabilityConditionJson.put("description", availabilityCondition.getDescription());
        }

        ruleJson.put("availabilityCondition", availabilityConditionJson);
      }
      rules.add(ruleJson);
    }
    GenericJson accessBoundaryRulesJson = new GenericJson();
    accessBoundaryRulesJson.setFactory(OAuth2Utils.JSON_FACTORY);
    accessBoundaryRulesJson.put("accessBoundaryRules", rules);

    GenericJson json = new GenericJson();
    json.setFactory(OAuth2Utils.JSON_FACTORY);
    json.put("accessBoundary", accessBoundaryRulesJson);
    return json.toString();
  }

  public List<AccessBoundaryRule> getAccessBoundaryRules() {
    return accessBoundaryRules;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private List<AccessBoundaryRule> accessBoundaryRules;

    private Builder() {
      accessBoundaryRules = new ArrayList<>();
    }

    /**
     * Sets the list of {@link AccessBoundaryRule}'s.
     *
     * <p>This list must not exceed 10 rules.
     */
    public Builder setRules(List<AccessBoundaryRule> rule) {
      accessBoundaryRules = new ArrayList<>(checkNotNull(rule));
      return this;
    }

    public CredentialAccessBoundary.Builder addRule(AccessBoundaryRule rule) {
      accessBoundaryRules.add(checkNotNull(rule));
      return this;
    }

    public CredentialAccessBoundary build() {
      return new CredentialAccessBoundary(accessBoundaryRules);
    }
  }

  /** Defines an upper bound of permissions on a particular resource. */
  public static final class AccessBoundaryRule {

    private final String availableResource;
    private final List<String> availablePermissions;

    @Nullable private final AvailabilityCondition availabilityCondition;

    AccessBoundaryRule(
        String availableResource,
        List<String> availablePermissions,
        @Nullable AvailabilityCondition availabilityCondition) {
      this.availableResource = checkNotNull(availableResource);
      this.availablePermissions = new ArrayList<>(checkNotNull(availablePermissions));

      for (String permission : availablePermissions) {
        if (permission == null || permission.isEmpty()) {
          throw new IllegalArgumentException(
              "One of the provided available permissions is either null or empty.");
        }
      }

      this.availabilityCondition = availabilityCondition;
    }

    public String getAvailableResource() {
      return availableResource;
    }

    public List<String> getAvailablePermissions() {
      return availablePermissions;
    }

    @Nullable
    public AvailabilityCondition getAvailabilityCondition() {
      return availabilityCondition;
    }

    public static Builder newBuilder() {
      return new Builder();
    }

    public static class Builder {
      private String availableResource;
      private List<String> availablePermissions;

      @Nullable private AvailabilityCondition availabilityCondition;

      private Builder() {}

      /**
       * Sets the available resource, which is the full resource name of the GCP resource to allow
       * access to.
       */
      public Builder setAvailableResource(String availableResource) {
        this.availableResource = availableResource;
        return this;
      }

      /**
       * Sets the list of permissions that can be used on the resource. This should be a list of IAM
       * roles prefixed by inRole.
       *
       * <p>e.g. {"inRole:roles/storage.objectViewer"}.
       */
      public Builder setAvailablePermissions(List<String> availablePermissions) {
        this.availablePermissions = new ArrayList<>(checkNotNull(availablePermissions));
        return this;
      }

      /**
       * Adds a permission that can be used on the resource. This should be an IAM role prefixed by
       * inRole.
       *
       * <p>e.g. "inRole:roles/storage.objectViewer".
       */
      public Builder addAvailablePermission(String availableResource) {
        if (availablePermissions == null) {
          availablePermissions = new ArrayList<>();
        }
        availablePermissions.add(availableResource);
        return this;
      }

      /**
       * Sets the availability condition which is an IAM condition that defines constraints to apply
       * to the token expressed in CEL format.
       */
      public Builder setAvailabilityCondition(AvailabilityCondition availabilityCondition) {
        this.availabilityCondition = availabilityCondition;
        return this;
      }

      public AccessBoundaryRule build() {
        return new AccessBoundaryRule(
            availableResource, availablePermissions, availabilityCondition);
      }
    }

    /**
     * An optional condition that can be used as part of a {@link CredentialAccessBoundary} to
     * further restrict permissions.
     */
    public static final class AvailabilityCondition {
      private final String expression;

      @Nullable private final String title;
      @Nullable private final String description;

      AvailabilityCondition(
          String expression, @Nullable String title, @Nullable String description) {
        this.expression = checkNotNull(expression);
        this.title = title;
        this.description = description;
      }

      public String getExpression() {
        return expression;
      }

      @Nullable
      public String getTitle() {
        return title;
      }

      @Nullable
      public String getDescription() {
        return description;
      }

      public static Builder newBuilder() {
        return new Builder();
      }

      public static final class Builder {
        private String expression;

        @Nullable private String title;
        @Nullable private String description;

        private Builder() {}

        /** */
        public Builder setExpression(String expression) {
          this.expression = expression;
          return this;
        }

        public Builder setTitle(String title) {
          this.title = title;
          return this;
        }

        public Builder setDescription(String description) {
          this.description = description;
          return this;
        }

        public AvailabilityCondition build() {
          return new AvailabilityCondition(expression, title, description);
        }
      }
    }
  }
}
