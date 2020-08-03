/*
 * Copyright 2020, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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
