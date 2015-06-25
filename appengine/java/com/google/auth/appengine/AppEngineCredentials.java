/*
 * Copyright 2015, Google Inc. All rights reserved.
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

package com.google.auth.appengine;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.collect.ImmutableList;
import com.google.appengine.api.appidentity.AppIdentityService;
import com.google.appengine.api.appidentity.AppIdentityServiceFactory;

import java.io.IOException;
import java.util.Collection;

/**
 * OAuth2 credentials representing the built-in service account for Google App ENgine.
 *
 * <p>Fetches access tokens from the App Identity service.
 */
public class AppEngineCredentials extends GoogleCredentials {
  
  private final AppIdentityService appIdentityService;
  
  private final Collection<String> scopes;
  
  private final boolean scopesRequired;  
  
  public AppEngineCredentials(Collection<String> scopes) {
    this(scopes, null);
  }

  public AppEngineCredentials(Collection<String> scopes, AppIdentityService appIdentityService) {
    this.scopes = ImmutableList.copyOf(scopes);
    this.appIdentityService = appIdentityService != null ? appIdentityService 
        : AppIdentityServiceFactory.getAppIdentityService();
    scopesRequired = (scopes == null || scopes.isEmpty());
  }
  
  /**
   * Refresh the access token by getting it from the App Identity service
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (createScopedRequired()) {
      throw new IOException("AppEngineCredentials requires createScoped call before use.");
    }
    String accessToken = appIdentityService.getAccessToken(scopes).getAccessToken();
    return new AccessToken(accessToken, null);    
  }
  
  @Override
  public boolean createScopedRequired() {
    return scopesRequired;
  }

  @Override
  public GoogleCredentials createScoped(Collection<String> scopes) {
    return new AppEngineCredentials(scopes, appIdentityService);
  }    
}
