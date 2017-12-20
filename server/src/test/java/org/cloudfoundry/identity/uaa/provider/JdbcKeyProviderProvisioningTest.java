package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.KeyProviderAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.KeyProviderNotFoundException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class JdbcKeyProviderProvisioningTest extends JdbcTestBase{
    JdbcKeyProviderProvisioning provisioning;

    public static final String GET_KEY_PROVIDER_BY_ID_SQL = "select * from key_provider_config where id=?";

    @Rule
    public ExpectedException expection = ExpectedException.none();
    @Before
    public void setup() {
        provisioning = new JdbcKeyProviderProvisioning(jdbcTemplate);
    }

    @Test
    public void testCreate() {
        KeyProviderConfig keyProviderConfig = new KeyProviderConfig("client1", "tenant1");
        KeyProviderConfig created = provisioning.createOrUpdate(keyProviderConfig);

        assertEquals("client1", created.getClientId());
        assertEquals("tenant1", created.getDcsTenantId());
        List<KeyProviderConfig> results = jdbcTemplate.query(GET_KEY_PROVIDER_BY_ID_SQL, JdbcKeyProviderProvisioning.mapper, created.getId());
        assertEquals(1, results.size());
        assertEquals(created, results.get(0));
    }

    @Test
    public void testCreateForExistingZone() {
        KeyProviderConfig keyProviderConfig = new KeyProviderConfig("client1", "tenant1");
        provisioning.createOrUpdate(keyProviderConfig);

        expection.expect(KeyProviderAlreadyExistsException.class);
        expection.expectMessage("Key provider already exists for this zone.");
        provisioning.createOrUpdate(keyProviderConfig);

    }

    @Test
    public void testRetrieve() {
        String keyProviderId = createKeyProvider();
        KeyProviderConfig keyProviderConfig = provisioning.retrieve(keyProviderId);
        assertEquals("client1", keyProviderConfig.getClientId());
        assertEquals("tenant1", keyProviderConfig.getDcsTenantId());
    }

    private String createKeyProvider() {
        String keyProviderId = UUID.randomUUID().toString();
        jdbcTemplate.update(JdbcKeyProviderProvisioning.INSERT_KEY_PROVIDER_CONFIG, keyProviderId, IdentityZoneHolder.get().getId(), "client1", "tenant1");
        return keyProviderId;
    }

    @Test
    public void testDelete() {
        String keyProviderId = createKeyProvider();
        KeyProviderConfig keyProviderConfig = provisioning.retrieve(keyProviderId);
        assertEquals("client1", keyProviderConfig.getClientId());
        assertEquals("tenant1", keyProviderConfig.getDcsTenantId());

        assertEquals(1, provisioning.delete(keyProviderId));

        expection.expect(KeyProviderNotFoundException.class);
        provisioning.retrieve(keyProviderId);
    }

    @Test
    public void testDeleteNotFound() {
        assertEquals(0, provisioning.delete("INVALID_ID"));
    }

    @Test
    public void testFindActiveForZone() {
        String keyProviderId = createKeyProvider();
        assertEquals(keyProviderId, provisioning.findActive().getId());
    }

    @Test
    public void testFindActiveForZoneZeroResults() {
        assertNull(provisioning.findActive());
    }

}