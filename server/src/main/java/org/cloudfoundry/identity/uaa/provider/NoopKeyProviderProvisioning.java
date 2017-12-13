package org.cloudfoundry.identity.uaa.provider;

import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;

//TODO replace this class with a JdbcKeyProviderProvisioning
public class NoopKeyProviderProvisioning implements KeyProviderProvisioning, SystemDeletable {

    @Override
    public KeyProviderConfig retrieve() {
        return null;
    }

    @Override
    public KeyProviderConfig retrieve(String identityZoneId) {
        return null;
    }

    @Override
    public KeyProviderConfig update() {
        return null;
    }

    @Override
    public KeyProviderConfig update(String identityZoneId) {
        return null;
    }

    @Override
    public KeyProviderConfig create(String identityZoneId) {
        return null;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return 0;
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return 0;
    }

    @Override
    public Log getLogger() {
        return null;
    }
}
