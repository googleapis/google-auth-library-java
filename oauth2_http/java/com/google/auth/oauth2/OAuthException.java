package com.google.auth.oauth2;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import javax.annotation.Nullable;

class OAuthException extends IOException {
  private static final String FULL_MESSAGE_FORMAT = "Error code %s: %s - %s";
  private static final String ERROR_DESCRIPTION_FORMAT = "Error code %s: %s";
  private static final String BASE_MESSAGE_FORMAT = "Error code %s";

  private String errorCode;
  @Nullable private String errorDescription;
  @Nullable private String errorUri;

  public OAuthException(String errorCode,
      @Nullable String errorDescription,
      @Nullable String errorUri) {
    this.errorCode = checkNotNull(errorCode);
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;
  }

  @Override
  public String getMessage() {
    if (errorDescription != null && errorUri != null) {
      return String.format(FULL_MESSAGE_FORMAT, errorCode, errorDescription, errorUri);
    }
    if (errorDescription != null) {
      return String.format(ERROR_DESCRIPTION_FORMAT, errorCode, errorDescription);
    }
    return String.format(BASE_MESSAGE_FORMAT, errorCode);
  }

  public String getErrorCode() {
    return errorCode;
  }

  @Nullable
  public String getErrorDescription() {
    return errorDescription;
  }

  @Nullable
  public String getErrorUri() {
    return errorUri;
  }
}
