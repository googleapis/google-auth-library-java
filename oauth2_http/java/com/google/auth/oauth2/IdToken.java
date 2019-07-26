/*
 * Copyright 2019, Google LLC
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
 *    * Neither the name of Google LLC. nor the names of its
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

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.common.base.MoreObjects;

/**
 * Represents a temporary IdToken and its JSONWebSingature object.
 */
public class IdToken extends AccessToken implements Serializable {

  private static final long serialVersionUID = -8514239465808977353L;

  private final JsonWebSignature jws;

  /**
   * @param tokenValue     String representation of the Id token.
   * @param jws            JsonWebSignature as object
   * @param audience       List of the Audiences the idToken was issued for.
   */
  public IdToken(String tokenValue, JsonWebSignature jws) {
    super(tokenValue, new Date(jws.getPayload().getExpirationTimeSeconds()));
    this.jws = jws;
  }

  /**
   * The JsonWebSignature as object
   *
   * @return returns com.google.api.client.json.webtoken.JsonWebSignature.
   */
  public JsonWebSignature getJsonWebSignature() {
    return jws;
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.getTokenValue(), jws);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).add("tokenValue", super.getTokenValue())
        .add("JsonWebSignature", jws).toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AccessToken)) {
      return false;
    }
    IdToken other = (IdToken) obj;
    return Objects.equals(super.getTokenValue(), other.getTokenValue())
        && Objects.equals(this.jws, other.jws);
  }
}
