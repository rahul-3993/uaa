package org.cloudfoundry.identity.uaa.provider;


public interface KeyProviderProvisioning {
    KeyProviderConfig retrieve();

    KeyProviderConfig retrieve(String identityZoneId);

    KeyProviderConfig createOrUpdate(KeyProviderConfig config);

    KeyProviderConfig createOrUpdate(KeyProviderConfig config, String identityZoneId);

    KeyProviderConfig delete();
}
