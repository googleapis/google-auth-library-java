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

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.auth.oauth2.TokenStore;

import java.io.IOException;

/**
 * Implementation of token storage using Cloud DataStore
 */
public class DataStoreTokenStore implements TokenStore {
  
  static final String TOKENKIND = DataStoreTokenStore.class.getName();      
  
  public static DataStoreTokenStore getDefault() {
    return DefaultHolder.INSTANCE;
  }
  
  private static class DefaultHolder {
    static final DataStoreTokenStore INSTANCE = new DataStoreTokenStore();
  }  
  
  @Override
  public String load(String id) throws IOException {
    DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
    Key key = KeyFactory.createKey(TOKENKIND, id);
    String state = null;
    try {
      Entity entity = datastore.get(key);
      state = (String) entity.getProperty("state");
    } catch (EntityNotFoundException exception) {
    }
    return state;
  }
  
  @Override
  public void store(String id, String tokens) throws IOException {
    DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
    Entity entity = new Entity(TOKENKIND, id);
    entity.setProperty("state", tokens);
    datastore.put(entity);
    
  }
  
  @Override
  public void delete(String id) {
    DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
    Key key = KeyFactory.createKey(TOKENKIND, id);
    datastore.delete(key);
  }
}
