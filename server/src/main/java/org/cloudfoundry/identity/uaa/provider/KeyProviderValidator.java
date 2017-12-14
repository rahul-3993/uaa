package org.cloudfoundry.identity.uaa.provider;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;

public class KeyProviderValidator {
    ClientDetailsService clientDetails;

    public void validate(KeyProviderConfig config) throws KeyProviderValidatorException {
        if(!StringUtils.hasText(config.getClientId())) {
            throw new KeyProviderValidatorException("Empty client id.");
        }
        if(!StringUtils.hasText(config.getDcsTenantId())){
            throw new KeyProviderValidatorException("Empty tenant id.");
        }
        try {
            ClientDetails retrieved = clientDetails.loadClientByClientId(config.getClientId());
        } catch (NoSuchClientException e) {
            throw new KeyProviderValidatorException("Client " + config.getClientId() + " was not found.", e);
        }
    }

    public ClientDetailsService getClientDetails() {
        return clientDetails;
    }

    public void setClientDetails(ClientDetailsService clientDetails) {
        this.clientDetails = clientDetails;
    }

    public class KeyProviderValidatorException extends Exception {
        public KeyProviderValidatorException(String message) {
            super(message);
        }

        public KeyProviderValidatorException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
