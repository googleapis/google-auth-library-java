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
package com.google.auth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.*;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** Test case for {@link ApiKeyCredentials}. */
@RunWith(JUnit4.class)
public class ApiKeyCredentialsTest {

    private static final String TEST_API_KEY = "testApiKey";

    @Test
    public void testGetAuthenticationType() {
        ApiKeyCredentials credentials = ApiKeyCredentials.create(TEST_API_KEY);
        assertEquals("", credentials.getAuthenticationType());
    }

    @Test
    public void testGetRequestMetadata() throws IOException, URISyntaxException {
        ApiKeyCredentials credentials = ApiKeyCredentials.create(TEST_API_KEY);
        Map<String, List<String>> metadata = credentials.getRequestMetadata(new URI("http://test.com"));
        assertEquals(1, metadata.size());
        assertTrue(metadata.containsKey(ApiKeyCredentials.API_KEY_HEADER_KEY));
        assertEquals(1, metadata.get(ApiKeyCredentials.API_KEY_HEADER_KEY).size());
        assertEquals(TEST_API_KEY, metadata.get(ApiKeyCredentials.API_KEY_HEADER_KEY).get(0));
    }

    @Test
    public void testHasRequestMetadata() {
        ApiKeyCredentials credentials = ApiKeyCredentials.create(TEST_API_KEY);
        assertTrue(credentials.hasRequestMetadata());
    }

    @Test
    public void testHasRequestMetadataOnly() {
        ApiKeyCredentials credentials = ApiKeyCredentials.create(TEST_API_KEY);
        assertTrue(credentials.hasRequestMetadataOnly());
    }
}
