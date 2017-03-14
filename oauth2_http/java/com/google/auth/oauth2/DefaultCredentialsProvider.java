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

package com.google.auth.oauth2;

import com.google.auth.http.HttpTransportFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessControlException;
import java.util.Collections;
import java.util.Locale;

/**
 * Provides the Application Default Credential from the environment.
 *
 * <p>An instance represents the per-process state used to get and cache the credential and
 * allows overriding the state and environment for testing purposes.
 **/
class DefaultCredentialsProvider {

  static final String CREDENTIAL_ENV_VAR = "GOOGLE_APPLICATION_CREDENTIALS";

  static final String WELL_KNOWN_CREDENTIALS_FILE = "application_default_credentials.json";

  static final String CLOUDSDK_CONFIG_DIRECTORY = "gcloud";

  static final String HELP_PERMALINK =
      "https://developers.google.com/accounts/docs/application-default-credentials";

  static final String APP_ENGINE_SIGNAL_CLASS = "com.google.appengine.api.utils.SystemProperty";

  static final String CLOUD_SHELL_ENV_VAR = "DEVSHELL_CLIENT_PORT";

  // These variables should only be accessed inside a synchronized block
  private GoogleCredentials cachedCredentials = null;
  private boolean checkedAppEngine = false;
  private boolean checkedComputeEngine = false;

  DefaultCredentialsProvider() {
  }

  /**
   * Returns the Application Default Credentials.
   *
   * <p>Returns the Application Default Credentials which are used to identify and authorize the
   * whole application. The following are searched (in order) to find the Application Default
   * Credentials:
   * <ol>
   *   <li>Credentials file pointed to by the {@code GOOGLE_APPLICATION_CREDENTIALS} environment
   *   variable</li>
   *   <li>Credentials provided by the Google Cloud SDK
   *   {@code gcloud auth application-default login} command</li>
   *   <li>Google App Engine built-in credentials</li>
   *   <li>Google Cloud Shell built-in credentials</li>
   *   <li>Google Compute Engine built-in credentials</li>
   * </ol>
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *        tokens.
   * @return the credentials instance.
   * @throws IOException if the credentials cannot be created in the current environment.
   **/
  final GoogleCredentials getDefaultCredentials(HttpTransportFactory transportFactory)
      throws IOException {
    synchronized (this) {
      if (cachedCredentials == null) {
        cachedCredentials = getDefaultCredentialsUnsynchronized(transportFactory);
      }
      if (cachedCredentials != null) {
        return cachedCredentials;
      }
    }

    throw new IOException(String.format(
        "The Application Default Credentials are not available. They are available if running"
            + " in Google Compute Engine. Otherwise, the environment variable %s must be defined"
            + " pointing to a file defining the credentials. See %s for more information.",
        CREDENTIAL_ENV_VAR,
        HELP_PERMALINK));
  }

  private final GoogleCredentials getDefaultCredentialsUnsynchronized(
      HttpTransportFactory transportFactory) throws IOException {

    // First try the environment variable
    GoogleCredentials credentials = null;
    String credentialsPath = getEnv(CREDENTIAL_ENV_VAR);
    if (credentialsPath != null && credentialsPath.length() > 0) {
      InputStream credentialsStream = null;
      try {
        File credentialsFile = new File(credentialsPath);
        if (!isFile(credentialsFile)) {
          // Path will be put in the message from the catch block below
          throw new IOException("File does not exist.");
        }
        credentialsStream = readStream(credentialsFile);
        credentials = GoogleCredentials.fromStream(credentialsStream, transportFactory);
      } catch (IOException e) {
        // Although it is also the cause, the message of the caught exception can have very
        // important information for diagnosing errors, so include its message in the
        // outer exception message also.
        throw new IOException(String.format(
            "Error reading credential file from environment variable %s, value '%s': %s",
            CREDENTIAL_ENV_VAR, credentialsPath, e.getMessage()), e);
      } catch (AccessControlException expected) {
        // Exception querying file system is expected on App-Engine
      } finally {
        if (credentialsStream != null) {
          credentialsStream.close();
        }
      }
    }

    // Then try the well-known file
    if (credentials == null) {
      File wellKnownFileLocation = getWellKnownCredentialsFile();
      InputStream credentialsStream = null;
      try {
        if (isFile(wellKnownFileLocation)) {
          credentialsStream = readStream(wellKnownFileLocation);
          credentials = GoogleCredentials.fromStream(credentialsStream, transportFactory);
        }
      } catch (IOException e) {
        throw new IOException(String.format(
            "Error reading credential file from location %s: %s",
            wellKnownFileLocation, e.getMessage()));
      } catch (AccessControlException expected) {
        // Exception querying file system is expected on App-Engine
      } finally {
        if (credentialsStream != null) {
          credentialsStream.close();
        }
      }
    }

    // Then try App Engine
    if (credentials == null) {
      credentials = tryGetAppEngineCredential();
    }

    // Then try Cloud Shell.  This must be done BEFORE checking
    // Compute Engine, as Cloud Shell runs on GCE VMs.
    if (credentials == null) {
      credentials = tryGetCloudShellCredentials();
    }

    // Then try Compute Engine
    if (credentials == null) {
      credentials = tryGetComputeCredentials(transportFactory);
    }

    return credentials;
  }

  private final File getWellKnownCredentialsFile() {
    File cloudConfigPath;
    String os = getProperty("os.name", "").toLowerCase(Locale.US);
    String envPath = getEnv("CLOUDSDK_CONFIG");
    if (envPath != null) {
      cloudConfigPath = new File(envPath);
    } else if (os.indexOf("windows") >= 0) {
      File appDataPath = new File(getEnv("APPDATA"));
      cloudConfigPath = new File(appDataPath, CLOUDSDK_CONFIG_DIRECTORY);
    } else {
      File configPath = new File(getProperty("user.home", ""), ".config");
      cloudConfigPath = new File(configPath, CLOUDSDK_CONFIG_DIRECTORY);
    }
    return new File(cloudConfigPath, WELL_KNOWN_CREDENTIALS_FILE);
  }

  private boolean runningOnAppEngine() {
    Class<?> systemPropertyClass = null;
    try {
      systemPropertyClass = forName(APP_ENGINE_SIGNAL_CLASS);
    } catch (ClassNotFoundException expected) {
      // SystemProperty will always be present on App Engine.
      return false;
    }
    Exception cause;
    Field environmentField;
    try {
      environmentField = systemPropertyClass.getField("environment");
      Object environmentValue = environmentField.get(null);
      Class<?> environmentType = environmentField.getType();
      Method valueMethod = environmentType.getMethod("value");
      Object environmentValueValue = valueMethod.invoke(environmentValue);
      return (environmentValueValue != null);
    } catch (NoSuchFieldException | SecurityException | IllegalArgumentException
        | IllegalAccessException | NoSuchMethodException | InvocationTargetException exception) {
      cause = exception;
    }
    throw new RuntimeException(String.format(
        "Unexpected error trying to determine if runnning on Google App Engine: %s",
        cause.getMessage()), cause);
  }

  private GoogleCredentials tryGetCloudShellCredentials() {
    String port = getEnv(CLOUD_SHELL_ENV_VAR);
    if (port != null) {
      return new CloudShellCredentials(Integer.parseInt(port));
    } else {
      return null;
    }
  }

  private GoogleCredentials tryGetAppEngineCredential() throws IOException {
    // Checking for App Engine requires a class load, so check only once
    if (checkedAppEngine) {
      return null;
    }
    boolean onAppEngine = runningOnAppEngine();
    checkedAppEngine = true;
    if (!onAppEngine) {
      return null;
    }
    return new AppEngineCredentials(Collections.<String>emptyList());
  }

  private final GoogleCredentials tryGetComputeCredentials(HttpTransportFactory transportFactory) {
    // Checking compute engine requires a round-trip, so check only once
    if (checkedComputeEngine) {
      return null;
    }
    boolean runningOnComputeEngine =
        ComputeEngineCredentials.runningOnComputeEngine(transportFactory);
    checkedComputeEngine = true;
    if (runningOnComputeEngine) {
      return new ComputeEngineCredentials(transportFactory);
    }
    return null;
  }

  /*
   * Start of methods to allow overriding in the test code to isolate from the environment.
   */

  Class<?> forName(String className) throws ClassNotFoundException {
    return Class.forName(className);
  }

  String getEnv(String name) {
    return System.getenv(name);
  }

  String getProperty(String property, String def) {
    return System.getProperty(property, def);
  }

  boolean isFile(File file) {
    return file.isFile();
  }

  InputStream readStream(File file) throws FileNotFoundException {
    return new FileInputStream(file);
  }

  /*
   * End of methods to allow overriding in the test code to isolate from the environment.
   */
}
