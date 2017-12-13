package org.cloudfoundry.identity.uaa.provider;

import org.junit.Test;

import static org.junit.Assert.*;

public class KeyProviderValidatorTest {

    @Test
    public void testValidate() {
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("valid-client-id");
        test.setDcsTenantId("anything");
        assertTrue(KeyProviderValidator.validate(test));
    }

    @Test
    public void testValidateInvalidConfig() {
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("");
        test.setDcsTenantId("anything");
        assertFalse(KeyProviderValidator.validate(test));
    }
}