/*
 * Copyright 2023 Google LLC
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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * The IdentityPool credential source. Dictates the retrieval method of the external credential,
 * which can either be through a metadata server or a local file.
 */
public class IdentityPoolCredentialSource extends CredentialSource {

  private static final long serialVersionUID = -745855247050085694L;
  IdentityPoolCredentialSourceType credentialSourceType;
  CredentialFormatType credentialFormatType;
  String credentialLocation;
  @Nullable String subjectTokenFieldName;
  @Nullable Map<String, String> headers;

  /**
   * The source of the 3P credential.
   *
   * <p>If this is a file based 3P credential, the credentials file can be retrieved using the
   * `file` key.
   *
   * <p>If this is URL-based 3p credential, the metadata server URL can be retrieved using the `url`
   * key.
   *
   * <p>The third party credential can be provided in different formats, such as text or JSON. The
   * format can be specified using the `format` header, which returns a map with keys `type` and
   * `subject_token_field_name`. If the `type` is json, the `subject_token_field_name` must be
   * provided. If no format is provided, we expect the token to be in the raw text format.
   *
   * <p>Optional headers can be present, and should be keyed by `headers`.
   */
  public IdentityPoolCredentialSource(Map<String, Object> credentialSourceMap) {
    super(credentialSourceMap);

    if (credentialSourceMap.containsKey("file") && credentialSourceMap.containsKey("url")) {
      throw new IllegalArgumentException(
          "Only one credential source type can be set, either file or url.");
    }

    if (credentialSourceMap.containsKey("file")) {
      credentialLocation = (String) credentialSourceMap.get("file");
      credentialSourceType = IdentityPoolCredentialSourceType.FILE;
    } else if (credentialSourceMap.containsKey("url")) {
      credentialLocation = (String) credentialSourceMap.get("url");
      credentialSourceType = IdentityPoolCredentialSourceType.URL;
    } else {
      throw new IllegalArgumentException(
          "Missing credential source file location or URL. At least one must be specified.");
    }

    Map<String, String> headersMap = (Map<String, String>) credentialSourceMap.get("headers");
    if (headersMap != null && !headersMap.isEmpty()) {
      headers = new HashMap<>();
      headers.putAll(headersMap);
    }

    // If the format is not provided, we expect the token to be in the raw text format.
    credentialFormatType = CredentialFormatType.TEXT;

    Map<String, String> formatMap = (Map<String, String>) credentialSourceMap.get("format");
    if (formatMap != null && formatMap.containsKey("type")) {
      String type = formatMap.get("type");

      if (type != null && "json".equals(type.toLowerCase(Locale.US))) {
        // For JSON, the subject_token field name must be provided.
        if (!formatMap.containsKey("subject_token_field_name")) {
          throw new IllegalArgumentException(
              "When specifying a JSON credential type, the subject_token_field_name must be set.");
        }
        credentialFormatType = CredentialFormatType.JSON;
        subjectTokenFieldName = formatMap.get("subject_token_field_name");
      } else if (type != null && "text".equals(type.toLowerCase(Locale.US))) {
        credentialFormatType = CredentialFormatType.TEXT;
      } else {
        throw new IllegalArgumentException(
            String.format("Invalid credential source format type: %s.", type));
      }
    }
  }

  boolean hasHeaders() {
    return headers != null && !headers.isEmpty();
  }

  enum IdentityPoolCredentialSourceType {
    FILE,
    URL
  }

  enum CredentialFormatType {
    TEXT,
    JSON
  }
}
