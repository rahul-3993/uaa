package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeyProviderConfig {
    private String clientId;
    private String dcsTenantId;
    private String zoneId;

    //TODO maybe add dcs url

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getDcsTenantId() {
        return dcsTenantId;
    }

    public void setDcsTenantId(String dcsTenantId) {
        this.dcsTenantId = dcsTenantId;
    }

    public String getZoneId() {
        return zoneId;
    }

    public void setZoneId(String zoneId) {
        this.zoneId = zoneId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyProviderConfig that = (KeyProviderConfig) o;
        return Objects.equals(clientId, that.clientId) &&
                Objects.equals(dcsTenantId, that.dcsTenantId) &&
                Objects.equals(zoneId, that.zoneId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, dcsTenantId, zoneId);
    }
}
