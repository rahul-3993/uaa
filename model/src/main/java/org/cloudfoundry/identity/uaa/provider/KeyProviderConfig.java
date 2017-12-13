package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeyProviderConfig {
    private String clientId;
    private String dcsTenantId;

    //TODO we don't know exactly what extra fields we need to add, since we might be able to get away with global dcs url and self-trusting uaa url

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyProviderConfig that = (KeyProviderConfig) o;
        return Objects.equals(clientId, that.clientId) &&
                Objects.equals(dcsTenantId, that.dcsTenantId);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientId, dcsTenantId);
    }
}
