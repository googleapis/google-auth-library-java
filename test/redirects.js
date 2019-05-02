// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const assert = require('assert');
const redirectUrl = require('../src/redirects.js').redirectUrl;

describe('redirectUrl', () => {

  it('should handle the latest index', () => {
    const url = 'http://googleapis.github.io/google-auth-library-java/releases/latest/apidocs/index.html';
    const expected = 'https://googleapis.dev/java/google-auth-library/latest/index.html';
  });

  it('should handle the latest index without index.html', () => {
    const url = 'http://googleapis.github.io/google-auth-library-java/releases/latest/apidocs/';
    const expected = 'https://googleapis.dev/java/google-auth-library/latest/';
  });

  it('should handle a versioned doc', () => {
    const url = 'https://googleapis.github.io/google-auth-library-java/releases/0.15.0/apidocs/index.html';
    const expected = 'https://googleapis.dev/java/google-auth-library/0.15.0/index.html';
    assert.equal(redirectUrl(url), expected);
  });

  it('should handle root page without index.html', () => {
    const url = 'https://googleapis.github.io/google-auth-library-java/releases/0.15.0/apidocs/';
    const expected = 'https://googleapis.dev/java/google-auth-library/0.15.0/';
    assert.equal(redirectUrl(url), expected);
  });

  it('should handle a deeplink', () => {
    const url = 'http://googleapis.github.io/google-auth-library-java/releases/0.15.0/apidocs/index.html?com/google/auth/appengine/AppEngineCredentials.html';
    const expected = 'https://googleapis.dev/java/google-auth-library/0.15.0/index.html?com/google/auth/appengine/AppEngineCredentials.html';
    assert.equal(redirectUrl(url), expected);
  });

  it('should handle anchor to method', () => {
    const url = 'http://googleapis.github.io/google-auth-library-java/releases/0.15.0/apidocs/com/google/auth/appengine/AppEngineCredentials.html#createScopedRequired--';
    const expected = 'https://googleapis.dev/java/google-auth-library/0.15.0/com/google/auth/appengine/AppEngineCredentials.html#createScopedRequired--';
    assert.equal(redirectUrl(url), expected);
  });

  it('defaults to the latest docs', () => {
    const path = 'http://example.com/abcd';
    const expected = null;
    assert.equal(redirectUrl(path), expected);
  });
});