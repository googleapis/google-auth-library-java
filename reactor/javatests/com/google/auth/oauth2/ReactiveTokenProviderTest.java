/*
 * Copyright 2017-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.auth.oauth2;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

public class ReactiveTokenProviderTest {

  @Test
  public void testCreateCacheable() throws IOException {
    ClassPathResource classPathResource = new ClassPathResource("fake-credential-key.json");
    ServiceAccountCredentials serviceAccountCredentials =
        ServiceAccountCredentials.fromStream(classPathResource.getInputStream());
    ReactiveTokenProvider reactiveTokenProvider =
        ReactiveTokenProvider.createCacheable(serviceAccountCredentials);
    assertTrue(reactiveTokenProvider instanceof CacheableTokenProvider);
  }

  @Test
  public void testCreateUserCredentialsTokenProvider() {
    UserCredentials userCredentials = mock(UserCredentials.class);
    ReactiveTokenProvider reactiveTokenProvider = ReactiveTokenProvider.create(userCredentials);
    assertTrue(reactiveTokenProvider instanceof UserCredentialsTokenProvider);
  }

  @Test
  public void testCreateServiceAccountTokenProvider() {
    ServiceAccountCredentials serviceAccountCredentials = mock(ServiceAccountCredentials.class);
    ReactiveTokenProvider reactiveTokenProvider =
        ReactiveTokenProvider.create(serviceAccountCredentials);
    assertTrue(reactiveTokenProvider instanceof ServiceAccountTokenProvider);
  }

  @Test
  public void testCreateComputeEngineTokenProvider() {
    ComputeEngineCredentials computeEngineCredentials = mock(ComputeEngineCredentials.class);
    ReactiveTokenProvider reactiveTokenProvider =
        ReactiveTokenProvider.create(computeEngineCredentials);
    assertTrue(reactiveTokenProvider instanceof ComputeEngineTokenProvider);
  }
}
