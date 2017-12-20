package org.cloudfoundry.identity.uaa.provider;


public interface KeyProviderProvisioning {
    KeyProviderConfig retrieve(String keyProviderId);

    KeyProviderConfig findActive();

    KeyProviderConfig createOrUpdate(KeyProviderConfig config);

    int delete(String keyProviderId);
}
