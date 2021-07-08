/*
 * Copyright 2021 Google LLC
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Date;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link OAuth2CredentialsWithRefresh}. */
@RunWith(JUnit4.class)
public class OAuth2CredentialsWithRefreshTest {

  private static final AccessToken ACCESS_TOKEN = new AccessToken("accessToken", new Date());

  @Test
  public void builder() {
    OAuth2CredentialsWithRefresh.OAuth2RefreshHandler refreshHandler =
        new OAuth2CredentialsWithRefresh.OAuth2RefreshHandler() {
          @Override
          public AccessToken refreshAccessToken() {
            return null;
          }
        };
    OAuth2CredentialsWithRefresh credential =
        OAuth2CredentialsWithRefresh.newBuilder()
            .setAccessToken(ACCESS_TOKEN)
            .setRefreshHandler(refreshHandler)
            .build();

    assertEquals(ACCESS_TOKEN, credential.getAccessToken());
    assertEquals(refreshHandler, credential.getRefreshHandler());
  }

  @Test
  public void builder_noAccessToken() {
    OAuth2CredentialsWithRefresh.newBuilder()
        .setRefreshHandler(
            new OAuth2CredentialsWithRefresh.OAuth2RefreshHandler() {
              @Override
              public AccessToken refreshAccessToken() {
                return null;
              }
            })
        .build();
  }

  @Test
  public void builder_noRefreshHandler_throws() {
    try {
      OAuth2CredentialsWithRefresh.newBuilder().setAccessToken(ACCESS_TOKEN).build();
      fail("Should fail as a refresh handler must be provided.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void refreshAccessToken_delegateToRefreshHandler() throws IOException {
    final AccessToken refreshedToken = new AccessToken("refreshedAccessToken", new Date());
    OAuth2CredentialsWithRefresh credentials =
        OAuth2CredentialsWithRefresh.newBuilder()
            .setAccessToken(ACCESS_TOKEN)
            .setRefreshHandler(
                new OAuth2CredentialsWithRefresh.OAuth2RefreshHandler() {
                  @Override
                  public AccessToken refreshAccessToken() {
                    return refreshedToken;
                  }
                })
            .build();

    AccessToken accessToken = credentials.refreshAccessToken();

    assertEquals(refreshedToken, accessToken);
  }
}
