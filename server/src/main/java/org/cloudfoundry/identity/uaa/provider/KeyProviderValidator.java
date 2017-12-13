package org.cloudfoundry.identity.uaa.provider;

import org.springframework.util.StringUtils;

public class KeyProviderValidator {
//    TODO maybe validate that client_id exists in this zone. Only necessary if uaa_url is always current uaa.
    public static boolean validate(KeyProviderConfig config) {
        return StringUtils.hasText(config.getClientId()) && StringUtils.hasText(config.getDcsTenantId());
    }
}
