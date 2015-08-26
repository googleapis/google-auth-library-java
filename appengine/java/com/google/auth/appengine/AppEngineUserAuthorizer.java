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

import com.google.api.client.http.HttpTransport;
import com.google.auth.oauth2.ClientId;
import com.google.auth.oauth2.TokenStore;
import com.google.auth.servlet.WebUserAuthorizer;

import java.net.URI;
import java.util.Collection;

/**
 * Authorizes OAuth2 user consent flows (3LO) for Web Servlets with defaults for Google App Engine.
 */
public class AppEngineUserAuthorizer extends WebUserAuthorizer {

  /**
   * Constructor with common parameters.
   * 
   * @param clientId Client ID to identify the OAuth2 consent prompt.
   * @param scopes OAUth2 scopes defining the user consent.
   */  
  public AppEngineUserAuthorizer(ClientId clientId, Collection<String> scopes) {
    this(clientId, scopes, DataStoreTokenStore.getDefault(), null, null, null, null);
  }
    
  /**
   * Constructor with all parameters.
   * 
   * @param clientId Client ID to identify the OAuth2 consent prompt.
   * @param scopes OAUth2 scopes defining the user consent.
   * @param tokenStore Implementation of a component for long term storage of tokens.
   * @param callbackUri URI for implementation of the OAuth2 web callback.
   * @param transport HTTP transport implementation for OAuth2 API calls. 
   * @param tokenServerUri URI of the end point that provides tokens. 
   * @param userAuthUri URI of the Web UI for user consent.
   */
  public AppEngineUserAuthorizer(ClientId clientId, Collection<String> scopes, 
      TokenStore tokenStore, URI callbackUri, HttpTransport transport, URI tokenServerUri, URI userAuthUri) {
    super(clientId, scopes, tokenStore, callbackUri, transport, tokenServerUri, userAuthUri);
  }
}
