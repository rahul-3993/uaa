package org.cloudfoundry.identity.uaa.provider;


public interface KeyProviderProvisioning {
    KeyProviderConfig retrieve();

    KeyProviderConfig retrieve(String identityZoneId);

    KeyProviderConfig update();

    KeyProviderConfig update(String identityZoneId);

    KeyProviderConfig create(String identityZoneId);
}
