package com.google.auth.oauth2;

import java.io.Serializable;

/** Context object to pass relevant variables from external account credentials to suppliers. */
public class ExternalAccountSupplierContext implements Serializable {

  private static final long serialVersionUID = -7852130853542313494L;

  private final String audience;
  private final String subjectTokenType;

  /**
   * Basic constructor for ExternalAccountSupplierContext.
   *
   * @param audience expected audience for the token exchange.
   * @param subjectTokenType expected token type for the token exchange.
   */
  public ExternalAccountSupplierContext(String audience, String subjectTokenType) {
    this.audience = audience;
    this.subjectTokenType = subjectTokenType;
  }

  /**
   * Gets the credentials expected audience.
   *
   * @return the audience.
   */
  public String getAudience() {
    return audience;
  }

  /**
   * Gets the credentials expected subject token type.
   *
   * @return the subject token type.
   */
  public String getSubjectTokenType() {
    return subjectTokenType;
  }
}
