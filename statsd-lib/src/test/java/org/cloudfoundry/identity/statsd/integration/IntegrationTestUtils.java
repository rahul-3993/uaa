package org.cloudfoundry.identity.statsd.integration;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IntegrationTestUtils {

    static final String UAA_BASE_URL = "http://localhost:8080/uaa";
    static final String TEST_USERNAME = "marissa";
    static final String TEST_PASSWORD = "koala";
    static final String CSRF_PARAMETER_NAME = "_csrf";
    private static final Pattern CSRF_FORM_ELEMENT = Pattern.compile(
        "\\<input type=\\\"hidden\\\" name=\\\"" + CSRF_PARAMETER_NAME + "\\\" value=\\\"(.*?)\\\""
    );

    public static String extractCsrfToken(String body) {
        Matcher matcher = CSRF_FORM_ELEMENT.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    static long getStatsDValueFromMessage(String message) {
        assertNotNull(message);

        String[] parts = message.split("[:|]");
        assertTrue(parts[2].equals("g") || parts[2].equals("c"));

        return Long.valueOf(parts[1]);
    }

}
