package org.cloudfoundry.identity.uaa.util;

import java.util.Arrays;

/**
 * Created by taitz.
 */
public class ProxySettings {

    static {
        setProxySettings();
    }

    /**
     * Set proxy settings, as in build.gradle, but for when not run via gradle.
     */
    private static void setProxySettings() {
        setSystemPropertyFromEnv("PROXY_HOST", "http.proxyHost", "https.proxyHost");
        setSystemPropertyFromEnv("PROXY_PORT", "http.proxyPort", "https.proxyPort");
        setSystemPropertyFromEnv("NO_PROXY", "http.nonProxyHosts");
    }

    private static void setSystemPropertyFromEnv(String envName, String... sysProps) {
        String envValue = System.getenv(envName);
        if (envValue != null) {
            Arrays.stream(sysProps).forEach(p -> System.setProperty(p, envValue));
        }
    }

}
