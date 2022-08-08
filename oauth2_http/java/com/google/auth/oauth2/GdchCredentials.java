/*
 * Copyright 2022, Google Inc. All rights reserved.
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

/**
 * Credentials for GDCH (`Google Distributed Cloud Hosted`) for service
 *     account users.
 *     .. _Google Distributed Cloud Hosted:
 *         https://cloud.google.com/blog/topics/hybrid-cloud/\
 *             announcing-google-distributed-cloud-edge-and-hosted
 *     To create a GDCH service account credential, first create a JSON file of
 *     the following format::
 *         {
 *             "type": "gdch_service_account",
 *             "format_version": "1",
 *             "project": "<project name>",
 *             "private_key_id": "<key id>",
 *             "private_key": "-----BEGIN EC PRIVATE KEY-----\n<key bytes>\n-----END EC PRIVATE KEY-----\n",
 *             "name": "<service identity name>",
 *             "ca_cert_path": "<CA cert path>",
 *             "token_uri": "https://service-identity.<Domain>/authenticate"
 *         }
 *     The "format_version" field stands for the format of the JSON file. For now
 *     it is always "1". The `private_key_id` and `private_key` is used for signing.
 *     The `ca_cert_path` is used for token server TLS certificate verification.
 *     After the JSON file is created, set `GOOGLE_APPLICATION_CREDENTIALS` environment
 *     variable to the JSON file path, then use the following code to create the
 *     credential::
 *         import google.auth
 *         credential, _ = google.auth.default()
 *         credential = credential.with_gdch_audience("<the audience>")
 *     We can also create the credential directly::
 *         from google.oauth import gdch_credentials
 *         credential = gdch_credentials.ServiceAccountCredentials.from_service_account_file("<the json file path>")
 *         credential = credential.with_gdch_audience("<the audience>")
 *     The token is obtained in the following way. This class first creates a
 *     self signed JWT. It uses the `name` value as the `iss` and `sub` claim, and
 *     the `token_uri` as the `aud` claim, and signs the JWT with the `private_key`.
 *     It then sends the JWT to the `token_uri` to exchange a final token for
 *     `audience`.
 */
public class GdchCredentials extends GoogleCredentials {
  /**
   * Internal constructor
   *
   * @param builder A builder for {@link GdchCredentials} See {@link
   *     GdchCredentials.Builder}
   */
  GdchCredentials(GdchCredentials.Builder builder) {

  }

  public static class Builder extends GoogleCredentials.Builder {
    protected Builder() {}
  }
}
