package com.google.auth.oauth2;

import java.io.File;
import java.util.Locale;

public class GoogleAuthUtils {

    public static final String getWellKnownCredentialsPath() {
        return getWellKnownCredentialsFile().getAbsolutePath();
    }

    static final File getWellKnownCredentialsFile() {
        File cloudConfigPath;
        String envPath = getEnv("CLOUDSDK_CONFIG");
        if (envPath != null) {
            cloudConfigPath = new File(envPath);
        } else if (getOsName().indexOf("windows") >= 0) {
            File appDataPath = new File(getEnv("APPDATA"));
            cloudConfigPath = new File(appDataPath, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
        } else {
            File configPath = new File(getProperty("user.home", ""), ".config");
            cloudConfigPath = new File(configPath, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
        }
        return new File(cloudConfigPath, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);
    }

    static String getOsName() {
        return getProperty("os.name", "").toLowerCase(Locale.US);
    }

    static String getEnv(String name) {
        return System.getenv(name);
    }

    static String getProperty(String property, String def) {
        return System.getProperty(property, def);
    }
}
