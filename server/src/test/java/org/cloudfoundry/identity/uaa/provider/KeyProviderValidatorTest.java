package org.cloudfoundry.identity.uaa.provider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class KeyProviderValidatorTest {

    KeyProviderValidator keyProviderValidator;
    ClientDetailsService mockClients = Mockito.mock(ClientDetailsService.class);

    @Rule
    public ExpectedException expection = ExpectedException.none();

    @Before
    public void setup() {
        keyProviderValidator = new KeyProviderValidator();
        keyProviderValidator.setClientDetails(mockClients);
    }

    @Test
    public void testValidate() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(eq("valid-client-id"))).thenReturn(new BaseClientDetails());
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("valid-client-id");
        test.setDcsTenantId("anything");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateEmptyClientId() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new BaseClientDetails());
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("");
        test.setDcsTenantId("anything");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Empty client id.");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateEmptyTenantId() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new BaseClientDetails());
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("anything");
        test.setDcsTenantId("");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Empty tenant id.");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateClientNotFound() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenThrow(new NoSuchClientException("I dunno man, it's in the title"));
        KeyProviderConfig test = new KeyProviderConfig();
        test.setClientId("nonexistent-client-id");
        test.setDcsTenantId("anything");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Client nonexistent-client-id was not found.");
        keyProviderValidator.validate(test);
    }
}