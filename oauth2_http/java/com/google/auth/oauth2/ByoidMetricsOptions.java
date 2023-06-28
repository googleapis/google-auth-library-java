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


class ByoidMetricsHandler implements java.io.Serializable {
  private static final String SOURCE_KEY = "source";
  private static final String IMPERSONATION_KEY = "sa-impersonation";
  private static final String CONFIG_LIFETIME_KEY = "config-lifetime";

  private final boolean configLifetime;
  private final boolean saImpersonation;
  private String source;

  ByoidMetricsHandler(boolean saImpersonation, boolean configLifetime, String source) {
    this.saImpersonation = saImpersonation;
    this.configLifetime = configLifetime;
    this.source = source;
  }

  String getByoidMetricsHeader() {
    return String.format(
        "%s %s %s/%s %s/%s %s/%s",
        MetricsUtils.API_CLIENT_HEADER,
        MetricsUtils.getAuthAndLibVersion(),
        SOURCE_KEY,
        this.source,
        IMPERSONATION_KEY,
        this.saImpersonation,
        CONFIG_LIFETIME_KEY,
        this.configLifetime);
  }

  void setSource(String source) {
    this.source = source;
  }
}
