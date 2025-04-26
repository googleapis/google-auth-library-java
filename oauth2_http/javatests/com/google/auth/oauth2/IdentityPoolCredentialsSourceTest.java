/*
 * Copyright 2025 Google LLC
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

import static com.google.auth.Credentials.GOOGLE_DEFAULT_UNIVERSE;
import static com.google.auth.oauth2.MockExternalAccountCredentialsTransport.SERVICE_ACCOUNT_IMPERSONATION_URL;
import static com.google.auth.oauth2.OAuth2Utils.JSON_FACTORY;
import static org.junit.Assert.*;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.google.auth.oauth2.IdentityPoolCredentialSource.IdentityPoolCredentialSourceType;

/** Tests for {@link IdentityPoolCredentialSource}. */
@RunWith(JUnit4.class)
public class IdentityPoolCredentialsSourceTest {

  @Test
  public void constructor_certificateConfig(){
    Map<String, Object> certificateMap = new HashMap<>();
    certificateMap.put("certificate_config_location", "/path/to/certificate");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IdentityPoolCredentialSource credentialSource = new IdentityPoolCredentialSource(credentialSourceMap);
    assertEquals(IdentityPoolCredentialSourceType.CERTIFICATE, credentialSource.credentialSourceType);
    assertNotNull(credentialSource.certificateConfig);
    assertFalse(credentialSource.certificateConfig.useDefaultCertificateConfig());
    assertEquals("/path/to/certificate", credentialSource.certificateConfig.getCertificateConfigLocation());
  }

  @Test
  public void constructor_certificateConfig_useDefault(){
    Map<String, Object> certificateMap = new HashMap<>();
    certificateMap.put("use_default_certificate_config", true);

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IdentityPoolCredentialSource credentialSource = new IdentityPoolCredentialSource(credentialSourceMap);
    assertEquals(IdentityPoolCredentialSourceType.CERTIFICATE, credentialSource.credentialSourceType);
    assertNotNull(credentialSource.certificateConfig);
    assertTrue(credentialSource.certificateConfig.useDefaultCertificateConfig());
  }

  @Test
  public void constructor_certificateConfig_missingRequiredFields_throws(){
    Map<String, Object> certificateMap = new HashMap<>();
    //Missing both use_default_certificate_config and certificate_config_location
    certificateMap.put("trust_chain_path", "path/to/trust/chain");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> new IdentityPoolCredentialSource(credentialSourceMap)
    );
    assertTrue(exception.getMessage().contains("must either specify a certificate_config_location or use_default_certificate_config should be true"));
  }

  @Test
  public void constructor_certificateConfig_bothFieldsSet_throws(){
    Map<String, Object> certificateMap = new HashMap<>();
    certificateMap.put("use_default_certificate_config", true);
    certificateMap.put("certificate_config_location", "/path/to/certificate");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> new IdentityPoolCredentialSource(credentialSourceMap)
    );
    assertTrue(exception.getMessage().contains("cannot specify both a certificate_config_location and use_default_certificate_config=true"));
  }

  @Test
  public void constructor_certificateConfig_trustChainPath(){
    Map<String, Object> certificateMap = new HashMap<>();
    certificateMap.put("use_default_certificate_config", true);
    certificateMap.put("trust_chain_path", "path/to/trust/chain");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IdentityPoolCredentialSource credentialSource = new IdentityPoolCredentialSource(credentialSourceMap);
    assertEquals(IdentityPoolCredentialSourceType.CERTIFICATE, credentialSource.credentialSourceType);
    assertNotNull(credentialSource.certificateConfig);
    assertEquals("path/to/trust/chain", credentialSource.certificateConfig.getTrustChainPath());
  }


  @Test
  public void constructor_certificateConfig_invalidType_throws(){
    Map<String, Object> certificateMap = new HashMap<>();
    certificateMap.put("use_default_certificate_config", "invalid-type");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("certificate", certificateMap);

    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> new IdentityPoolCredentialSource(credentialSourceMap)
    );
    assertTrue(exception.getMessage().contains("Invalid type for 'use_default_certificate_config' in certificate configuration: expected Boolean"));
  }

}
