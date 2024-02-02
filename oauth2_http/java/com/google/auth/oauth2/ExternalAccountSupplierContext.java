package com.google.auth.oauth2;

import com.google.auth.oauth2.ExternalAccountCredentials.SubjectTokenTypes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.Serializable;

/**
 * Context object to pass relevant variables from external account credentials to suppliers. This
 * will be passed on any call made to {@link IdentityPoolSubjectTokenSupplier} or {@link
 * AwsSecurityCredentialsSupplier}.
 */
public class ExternalAccountSupplierContext implements Serializable {

  private static final long serialVersionUID = -7852130853542313494L;

  private final String audience;
  private final String subjectTokenType;

  /** Internal constructor. See {@link ExternalAccountSupplierContext.Builder}. */
  private ExternalAccountSupplierContext(Builder builder) {
    this.audience = builder.audience;
    this.subjectTokenType = builder.subjectTokenType;
  }

  /**
   * Returns the credentials' expected audience.
   *
   * @return the requested audience. For example:
   *     "//iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID".
   */
  public String getAudience() {
    return audience;
  }

  /**
   * Returns the credentials' expected Security Token Service subject token type based on the OAuth
   * 2.0 token exchange spec.
   *
   * <p>Expected values:
   *
   * <p>"urn:ietf:params:oauth:token-type:jwt" "urn:ietf:params:aws:token-type:aws4_request"
   * "urn:ietf:params:oauth:token-type:saml2" "urn:ietf:params:oauth:token-type:id_token"
   *
   * @return the requested subject token type. For example: "urn:ietf:params:oauth:token-type:jwt".
   */
  public String getSubjectTokenType() {
    return subjectTokenType;
  }

  static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for external account supplier context. */
  static class Builder {

    protected String audience;
    protected String subjectTokenType;

    /**
     * Sets the Audience.
     *
     * @param audience the audience to set
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    Builder setAudience(String audience) {
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
    Builder setSubjectTokenType(String subjectTokenType) {
      this.subjectTokenType = subjectTokenType;
      return this;
    }

    /**
     * Sets the subject token type.
     *
     * @param subjectTokenType the subjectTokenType to set.
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    Builder setSubjectTokenType(SubjectTokenTypes subjectTokenType) {
      this.subjectTokenType = subjectTokenType.value;
      return this;
    }

    ExternalAccountSupplierContext build() {
      return new ExternalAccountSupplierContext(this);
    }
  }
}
