package com.google.auth.oauth2;

import com.google.api.client.http.HttpTransport;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessControlException;
import java.util.Collection;
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

  static final String APP_ENGINE_CREDENTIAL_CLASS =
      "com.google.auth.appengine.AppEngineCredentials";

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
   * <p>Returns the Application Default Credentials which are credentials that identify and
   * authorize the whole application. This is the built-in service account if running on Google
   * Compute Engine or credentials specified by an environment variable or a file in a well-known
   * location.</p>
   *
   * @param transport the transport for Http calls.
   * @return the credentials instance.
   * @throws IOException if the credentials cannot be created in the current environment.
   **/
  final GoogleCredentials getDefaultCredentials(HttpTransport transport)
      throws IOException {
    synchronized (this) {
      if (cachedCredentials == null) {
        cachedCredentials = getDefaultCredentialsUnsynchronized(transport);
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

  private final GoogleCredentials getDefaultCredentialsUnsynchronized(HttpTransport transport)
      throws IOException {

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
        credentials = GoogleCredentials.fromStream(credentialsStream, transport);
      } catch (IOException e) {
        // Although it is also the cause, the message of the caught exception can have very
        // important information for diagnosing errors, so include its message in the
        // outer exception message also.
        throw OAuth2Utils.exceptionWithCause(new IOException(String.format(
            "Error reading credential file from environment variable %s, value '%s': %s",
            CREDENTIAL_ENV_VAR, credentialsPath, e.getMessage())), e);
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
          credentials = GoogleCredentials.fromStream(credentialsStream, transport);
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
      credentials = tryGetComputeCredentials(transport);
    }

    return credentials;
  }

  private final File getWellKnownCredentialsFile() {
    File cloudConfigPath = null;
    String os = getProperty("os.name", "").toLowerCase(Locale.US);
    if (os.indexOf("windows") >= 0) {
      File appDataPath = new File(getEnv("APPDATA"));
      cloudConfigPath = new File(appDataPath, CLOUDSDK_CONFIG_DIRECTORY);
    } else {
      File configPath = new File(getProperty("user.home", ""), ".config");
      cloudConfigPath = new File(configPath, CLOUDSDK_CONFIG_DIRECTORY);
    }
    File credentialFilePath = new File(cloudConfigPath, WELL_KNOWN_CREDENTIALS_FILE);
    return credentialFilePath;
  }

  private boolean runningOnAppEngine() {
    Class<?> systemPropertyClass = null;
    try {
      systemPropertyClass = forName(APP_ENGINE_SIGNAL_CLASS);
    } catch (ClassNotFoundException expected) {
      // SystemProperty will always be present on App Engine.
      return false;
    }
    Exception cause = null;
    Field environmentField;
    try {
      environmentField = systemPropertyClass.getField("environment");
      Object environmentValue = environmentField.get(null);
      Class<?> environmentType = environmentField.getType();
      Method valueMethod = environmentType.getMethod("value");
      Object environmentValueValue = valueMethod.invoke(environmentValue);
      return (environmentValueValue != null);
    } catch (NoSuchFieldException exception) {
      cause = exception;
    } catch (SecurityException exception) {
      cause = exception;
    } catch (IllegalArgumentException exception) {
      cause = exception;
    } catch (IllegalAccessException exception) {
      cause = exception;
    } catch (NoSuchMethodException exception) {
      cause = exception;
    } catch (InvocationTargetException exception) {
      cause = exception;
    }
    throw OAuth2Utils.exceptionWithCause(new RuntimeException(String.format(
        "Unexpcted error trying to determine if runnning on Google App Engine: %s",
        cause.getMessage())), cause);
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
    Exception innerException = null;
    try {
      Class<?> credentialClass = forName(APP_ENGINE_CREDENTIAL_CLASS);
      Constructor<?> constructor = credentialClass
          .getConstructor(Collection.class);
      Collection<String> emptyScopes = Collections.emptyList();
      return (GoogleCredentials) constructor.newInstance(emptyScopes);
    } catch (ClassNotFoundException e) {
      innerException = e;
    } catch (NoSuchMethodException e) {
      innerException = e;
    } catch (InstantiationException e) {
      innerException = e;
    } catch (IllegalAccessException e) {
      innerException = e;
    } catch (InvocationTargetException e) {
      innerException = e;
    }
    throw OAuth2Utils.exceptionWithCause(new IOException(String.format(
        "Application Default Credentials failed to create the Google App Engine service account"
            + " credentials class %s. Check that the component 'google-auth-library-appengine' is"
            + " deployed.",
        APP_ENGINE_CREDENTIAL_CLASS)), innerException);
  }

  private final GoogleCredentials tryGetComputeCredentials(HttpTransport transport) {
    // Checking compute engine requires a round-trip, so check only once
    if (checkedComputeEngine) {
      return null;
    }
    boolean runningOnComputeEngine = ComputeEngineCredentials.runningOnComputeEngine(transport);
    checkedComputeEngine = true;
    if (runningOnComputeEngine) {
      return new ComputeEngineCredentials(transport);
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
