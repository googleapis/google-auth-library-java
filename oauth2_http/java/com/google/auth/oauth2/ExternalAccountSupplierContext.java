package com.google.auth.oauth2;

import java.io.Serializable;

public class ExternalAccountSupplierContext implements Serializable {

  private static final long serialVersionUID = -7852130853542313494L;

  private final String audience;
  private final String subjectTokenType;

  public ExternalAccountSupplierContext(String audience, String subjectTokenType) {
    this.audience = audience;
    this.subjectTokenType = subjectTokenType;
  }

  public String getAudience() {
    return audience;
  }

  public String getSubjectTokenType() {
    return subjectTokenType;
  }
}
