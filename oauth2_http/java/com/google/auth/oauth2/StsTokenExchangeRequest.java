package com.google.auth.oauth2;


import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import javax.annotation.Nullable;

/**
 * Defines an OAuth 2.0 token exchange request. Based on
 * https://tools.ietf.org/html/rfc8693#section-2.1.
 */
public class StsTokenExchangeRequest {
  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

  private String subjectToken;
  private String subjectTokenType;

  @Nullable private ActingParty actingParty;
  @Nullable private List<String> scopes;
  @Nullable private String resource;
  @Nullable private String audience;
  @Nullable private String requestedTokenType;

  private StsTokenExchangeRequest(
      String subjectToken,
      String subjectTokenType,
      @Nullable ActingParty actingParty,
      @Nullable List<String> scopes,
      @Nullable String resource,
      @Nullable String audience,
      @Nullable String requestedTokenType) {
    this.subjectToken = checkNotNull(subjectToken);
    this.subjectTokenType = checkNotNull(subjectTokenType);
    this.actingParty = actingParty;
    this.scopes = scopes;
    this.resource = resource;
    this.audience = audience;
    this.requestedTokenType = requestedTokenType;
  }

  public static Builder newBuilder(String subjectToken, String subjectTokenType) {
    return new Builder(subjectToken, subjectTokenType);
  }

  public String getGrantType() {
    return GRANT_TYPE;
  }

  public String getSubjectToken() {
    return subjectToken;
  }

  public String getSubjectTokenType() {
    return subjectTokenType;
  }

  @Nullable
  public String getResource() {
    return resource;
  }

  @Nullable
  public String getAudience() {
    return audience;
  }

  @Nullable
  public String getRequestedTokenType() {
    return requestedTokenType;
  }

  @Nullable
  public List<String> getScopes() {
    return scopes;
  }

  @Nullable
  public ActingParty getActingParty() {
    return actingParty;
  }

  public boolean hasResource() {
    return resource != null && !resource.isEmpty();
  }

  public boolean hasAudience() {
    return audience != null && !audience.isEmpty();
  }

  public boolean hasRequestedTokenType() {
    return  requestedTokenType != null && !requestedTokenType.isEmpty();
  }

  public boolean hasScopes() {
    return  scopes != null && !scopes.isEmpty();
  }

  public boolean hasActingParty() {
    return actingParty != null;
  }

  public static class Builder {
    String subjectToken;
    String subjectTokenType;
    String resource;
    String audience;
    String requestedTokenType;
    List<String> scopes;
    ActingParty actingParty;

    private Builder(
        String subjectToken,
        String subjectTokenType) {
      this.subjectToken = subjectToken;
      this.subjectTokenType = subjectTokenType;
    }

    public StsTokenExchangeRequest.Builder setResource(String resource) {
      this.resource = resource;
      return this;
    }

    public StsTokenExchangeRequest.Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    public StsTokenExchangeRequest.Builder setRequestTokenType(String requestedTokenType) {
      this.requestedTokenType = requestedTokenType;
      return this;
    }

    public StsTokenExchangeRequest.Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public StsTokenExchangeRequest.Builder setActingParty(ActingParty actingParty) {
      this.actingParty = actingParty;
      return this;
    }

    public StsTokenExchangeRequest build() {
      return new StsTokenExchangeRequest(subjectToken, subjectTokenType, actingParty, scopes,
          resource, audience, requestedTokenType);
    }
  }

  static class ActingParty {
    private String actorToken;
    private String actorTokenType;

    public ActingParty(String actorToken, String actorTokenType) {
      this.actorToken = checkNotNull(actorToken);
      this.actorTokenType = checkNotNull(actorTokenType);
    }

    public String getActorToken() {
      return actorToken;
    }

    public String getActorTokenType() {
      return actorTokenType;
    }
  }
}

