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

package com.google.auth.servlet;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.oauth2.UserCredentials;
import com.google.common.base.Preconditions;
import com.google.auth.oauth2.ClientId;
import com.google.auth.oauth2.TokenStore;
import com.google.auth.oauth2.UserAuthorizer;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Collection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Authorizes OAuth2 user consent flows (3LO) for Web Servlets.
 */
public class WebUserAuthorizer extends UserAuthorizer {
    
  private static final String CLASS_NAME = UserAuthorizer.class.getName();
  private static final String SESSION_KEY_ID = CLASS_NAME + ":id";
  private static final String SESSION_KEY_PASS_CODE = CLASS_NAME + ":passcode";  
  private static String CONTINUE_URL_FIELD = "continue_url";
  private static String SESSION_ID_FIELD = "session_id";
  private static String CODE_FIELD = "code";
  private static String STATE_FIELD = "state";
  private static String ERROR_FIELD = "error";
  private static String PARSE_STATE_ERROR_PREFIX = "Error parsing authorization callback state: ";  
  private static String PARSE_PASS_CODE_ERROR_PREFIX = "Error parsing code passing session state: ";  
  
  /**
   * Constructor with common parameters.
   * 
   * @param clientId Client ID to identify the OAuth2 consent prompt.
   * @param scopes OAUth2 scopes defining the user consent.
   * @param tokenStore Implementation of a component for long term storage of tokens.
   */
  public WebUserAuthorizer(ClientId clientId, Collection<String> scopes, TokenStore tokenStore) {
    this(clientId, scopes, tokenStore, null, null, null, null);
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
  public WebUserAuthorizer(ClientId clientId, Collection<String> scopes, TokenStore tokenStore,
      URI callbackUri, HttpTransport transport, URI tokenServerUri, URI userAuthUri) {
    super(clientId, scopes, tokenStore, callbackUri, transport, tokenServerUri, userAuthUri);
  }
  
  /**
   * Return an URL that performs the authorization consent prompt web UI.
   * 
   * <p>Uses the request to automatically navigate back to the original URL and uses session
   * state to ensure the OAuth2 callback is handled in the same session.
   * 
   * @param userId Application's identifier for the end user.
   * @param request Request of the HttpServlet initiating the authorization.
   * @return The URL that can be navigated or redirected to.
   */
  
  public URL getAuthorizationUrl(String userId, HttpServletRequest request) {
    Preconditions.checkNotNull(userId);
    Preconditions.checkNotNull(request);
    String sessionId = getSessionId(request.getSession());
    URL requestUrl = ServletUtils.getURL(request);

    GenericJson stateJson = new GenericJson();    
    stateJson.setFactory(ServletUtils.JSON_FACTORY);
    stateJson.put(CONTINUE_URL_FIELD, requestUrl.toString());
    stateJson.put(SESSION_ID_FIELD, sessionId);
    String stateText = stateJson.toString();
    String encodedState = ServletUtils.urlEncode(stateText);
    return getAuthorizationUrl(userId, encodedState, ServletUtils.getURI(request));
  }  
  
  /**
   * Attempts to retrieve credentials for the approved end user consent.
   * 
   * <p>Supports use of handleAuthCallbackPassCode which passes the authorization code in session
   * state, as used by the OAuth2CallbackServlet component.
   * 
   * @param userId Application's identifier for the end user.
   * @param request Request attempting to use
   * @return The loaded credentials or null if there are no valid approved credentials.
   * @throws IOException If there is error retrieving or loading the credentials or converting
   * the authorization code to tokens.
   */
  
  public UserCredentials getCredentials(String userId, HttpServletRequest request)
      throws IOException {
    Preconditions.checkNotNull(userId);
    Preconditions.checkNotNull(request);
    
    // First check if OAuth2 callback handler passed a code in session state.
    String passCodeRaw = (String) request.getSession().getAttribute(SESSION_KEY_PASS_CODE);
    if (passCodeRaw != null) {
      String sessionId = getSessionId(request.getSession());
      GenericJson passCodeJson = ServletUtils.parseJson(passCodeRaw);
      String code = ServletUtils.validateOptionalString(
          passCodeJson, CODE_FIELD, PARSE_PASS_CODE_ERROR_PREFIX);
      String passedSessionId = ServletUtils.validateOptionalString(
          passCodeJson, SESSION_ID_FIELD, PARSE_PASS_CODE_ERROR_PREFIX);
      String error = ServletUtils.validateOptionalString(
          passCodeJson, ERROR_FIELD, PARSE_PASS_CODE_ERROR_PREFIX);
      // Clear the passed code so that it is only attempted once
      request.getSession().setAttribute(SESSION_KEY_PASS_CODE, null);
      if (!sessionId.equals(passedSessionId)) {
        throw new IOException("Mismatched session id from passed authorization code.");
      }
      validateAuthCallbackFields(code, error);      
      return getAndStoreCredentialsFromCode(userId, code, ServletUtils.getURI(request));      
    }
    
    // Otherwise do the regular lookup using the token storage.
    return getCredentials(userId);
  }
  
  /**
   * Handles an OAuth2 callback request by converting the authorization code to OAuth2 tokens,
   * and returning the resulting credentials and return URL.
   * 
   * @param userId Application's identifier for the end user.
   * @param request Request of the OAuth2 callback handler.
   * @return AuthCallbackResult value including the credentials and return URL.
   * @throws IOException An error with authorization, handling authorization code or storing
   * credentials.
   */
  public AuthCallbackResult handleAuthCallback(String userId, HttpServletRequest request)
      throws IOException {
    Preconditions.checkNotNull(userId);
    Preconditions.checkNotNull(request);
    
    String code = request.getParameter(CODE_FIELD);
    String error = request.getParameter(ERROR_FIELD);
    validateAuthCallbackFields(code, error);            
    
    String state = request.getParameter(STATE_FIELD);
    CallbackState callbackState = getCallbackState(state);
    validateSessionId(request.getSession(), callbackState.sessionId);
    
    UserCredentials credentials = getAndStoreCredentialsFromCode(
        userId, code, ServletUtils.getURI(request));
    return new AuthCallbackResult(credentials, callbackState.returnUrl);
  }
  
  /**
   * Handles an OAuth2 callback request by passing the authorization code back to the return URL
   * in session state. 
   * 
   * <p>For use with getCredentials(String, HttpServletRequest) which can handle the authorization
   * code or error.
   * 
   * @param request Request of the OAuth2 callback handler.
   * @return AuthCallbackResult value including the return URL.
   * @throws IOException
   */
  public static AuthCallbackResult handleAuthCallbackPassCode(HttpServletRequest request)
      throws IOException {    

    String code = request.getParameter(CODE_FIELD);
    String state = request.getParameter(STATE_FIELD);
    String error = request.getParameter(ERROR_FIELD);
    
    CallbackState callbackState = getCallbackState(state);    
    validateSessionId(request.getSession(), callbackState.sessionId);
    
    GenericJson sessionStateJson = new GenericJson();    
    sessionStateJson.setFactory(ServletUtils.JSON_FACTORY);
    if (code != null) {
      sessionStateJson.put(CODE_FIELD, code);
    }
    if (error != null) {
      sessionStateJson.put(ERROR_FIELD, error);
    }
    sessionStateJson.put(SESSION_ID_FIELD, callbackState.sessionId);
    String sessionStateValue = sessionStateJson.toString();
    request.getSession().setAttribute(SESSION_KEY_PASS_CODE, sessionStateValue);
    
    AuthCallbackResult result = new AuthCallbackResult(null, callbackState.returnUrl);
    return result;
  }
     
  private static CallbackState getCallbackState(String state) throws IOException {
    CallbackState result = new CallbackState();
    String decodedState = ServletUtils.urlDecode(state);
    GenericJson stateJson = ServletUtils.parseJson(decodedState);    
    String returnUrlString = ServletUtils.validateOptionalString(
        stateJson, CONTINUE_URL_FIELD, PARSE_STATE_ERROR_PREFIX);
    if (returnUrlString != null) {
      result.returnUrl= new URL(returnUrlString);
    }
    result.sessionId = ServletUtils.validateOptionalString(
        stateJson, SESSION_ID_FIELD, PARSE_STATE_ERROR_PREFIX);
    return result;
  }
  
  private static String getSessionId(HttpSession session) {
    String sessionId = (String) session.getAttribute(SESSION_KEY_ID);
    if (sessionId != null) {
      sessionId = new BigInteger(130, new SecureRandom()).toString(32);
      session.setAttribute(SESSION_KEY_ID, sessionId);
    }
    return sessionId;
  }
     
  private void validateAuthCallbackFields(String code, String error) {
    if (error != null && error.length() > 0) {
      throw new SecurityException("Authorization Error: " + error); 
    }
    if (code == null || code.length() == 0) {
      throw new RuntimeException("Authorization code or error missing from pass code flow.");
    }
  }  

  private static void validateSessionId(HttpSession session, String callbackStateSessionId)
      throws IOException {
    String sessionId = getSessionId(session);
    if (callbackStateSessionId == null) {
      throw new IOException("Session ID in callback request missing.");
    }
    if (!sessionId.equals(callbackStateSessionId)) {
      throw new IOException("Session ID does not match identifier in authorization callback request"
          +" state.");
    }
  }  
      
  private static class CallbackState {
    URL returnUrl = null;
    String sessionId = null;
  }  
}
