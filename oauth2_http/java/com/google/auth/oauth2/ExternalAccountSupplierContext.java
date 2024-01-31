package com.google.auth.oauth2;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.Serializable;

/** Context object to pass relevant variables from external account credentials to suppliers. */
public class ExternalAccountSupplierContext implements Serializable {

  private static final long serialVersionUID = -7852130853542313494L;

  private final String audience;
  private final String subjectTokenType;

  /** Internal constructor. See {@link ExternalAccountSupplierContext.Builder}. */
  ExternalAccountSupplierContext(Builder builder) {
    this.audience = builder.audience;
    this.subjectTokenType = builder.subjectTokenType;
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

  public static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for external account supplier context. */
  public static class Builder {

    protected String audience;
    protected String subjectTokenType;

    public Builder() {}

    /**
     * Sets the Audience.
     *
     * @param audience the audience to set
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    /**
     * Sets the subject token type.
     *
     * @param subjectTokenType the subjectTokenType to set.
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setSubjectTokenType(String subjectTokenType) {
      this.subjectTokenType = subjectTokenType;
      return this;
    }

    public ExternalAccountSupplierContext build() {return new ExternalAccountSupplierContext(this);}
  }
}
