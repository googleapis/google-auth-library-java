/*
 * Copyright 2020 Google LLC
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

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link OAuthException}. */
@RunWith(JUnit4.class)
public final class OAuthExceptionTest {
  private static final String FULL_MESSAGE_FORMAT = "Error code %s: %s - %s";
  private static final String ERROR_DESCRIPTION_FORMAT = "Error code %s: %s";
  private static final String BASE_MESSAGE_FORMAT = "Error code %s";

  private static final String ERROR_CODE = "errorCode";
  private static final String ERROR_DESCRIPTION = "errorDescription";
  private static final String ERROR_URI = "errorUri";

  @Test
  public void getMessage_fullFormat() {
    OAuthException e = new OAuthException(ERROR_CODE, ERROR_DESCRIPTION, ERROR_URI);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
    assertThat(e.getErrorUri()).isEqualTo(ERROR_URI);

    String expectedMessage =
        String.format(FULL_MESSAGE_FORMAT, ERROR_CODE, ERROR_DESCRIPTION, ERROR_URI);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }

  @Test
  public void getMessage_descriptionFormat() {
    OAuthException e = new OAuthException(ERROR_CODE, ERROR_DESCRIPTION, /* errorUri= */ null);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
    assertThat(e.getErrorUri()).isNull();

    String expectedMessage = String.format(ERROR_DESCRIPTION_FORMAT, ERROR_CODE, ERROR_DESCRIPTION);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }

  @Test
  public void getMessage_baseFormat() {
    OAuthException e =
        new OAuthException(ERROR_CODE, /* errorDescription= */ null, /* errorUri= */ null);

    assertThat(e.getErrorCode()).isEqualTo(ERROR_CODE);
    assertThat(e.getErrorDescription()).isNull();
    assertThat(e.getErrorUri()).isNull();

    String expectedMessage = String.format(BASE_MESSAGE_FORMAT, ERROR_CODE);
    assertThat(e.getMessage()).isEqualTo(expectedMessage);
  }
}
