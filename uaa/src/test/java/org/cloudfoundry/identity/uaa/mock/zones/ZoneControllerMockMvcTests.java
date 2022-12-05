package org.cloudfoundry.identity.uaa.mock.zones;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import lombok.SneakyThrows;
import net.bytebuddy.utility.RandomString;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

@DefaultTestContext
public class OrchestratorZoneControllerMockMvcTests {

    private MockMvc mockMvc;
    private String identityClientZonesReadToken = null;
    private String uaaAdminClientToken;
    private TestApplicationEventListener<AbstractUaaEvent> uaaEventListener;
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;

    private final String serviceProviderKey =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    private final String serviceProviderKeyPassword = "password";

    private final String serviceProviderCertificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----\n";

    @BeforeEach
    void setUp(@Autowired MockMvc mockMvc,
               @Autowired TestClient testClient, @Autowired ClientRegistrationService clientRegistrationService, @Autowired
               ConfigurableApplicationContext configurableApplicationContext)
        throws Exception {
        this.mockMvc = mockMvc;
        zoneModifiedEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, IdentityZoneModifiedEvent.class);
        uaaEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, AbstractUaaEvent.class);
        BaseClientDetails uaaAdminClient = new BaseClientDetails("uaa-admin-" + RandomString.make(5).toLowerCase(),
                                                                 null,
                                                                 "uaa.admin",
                                                                 "password,client_credentials",
                                                                 "uaa.admin");
        uaaAdminClient.setClientSecret("secret");
        clientRegistrationService.addClientDetails(uaaAdminClient);
        identityClientZonesReadToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read");
        uaaAdminClientToken = testClient.getClientCredentialsOAuthAccessToken(
            uaaAdminClient.getClientId(),
            "secret",
            "uaa.admin");
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZonesBaseUrlsArgumentsSource.class)
    void testGetZone_unAuthorized(String url) throws Exception {
        mockMvc.perform(get(url))
               .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ArgumentsSource(NameRequiredArgumentsSource.class)
    void testGetZone_nameRequiredError(String url) throws Exception {
        performMockMvcCallAndAssertError(get(url), status().isBadRequest(),
                                         "{\"message\", \"Required request parameter 'name' for method parameter type String is not present\" }");
    }

    @ParameterizedTest
    @ArgumentsSource(NameNotEmptyArgumentsSource.class)
    void testGetZone_nameEmptyError(String url) throws Exception {
        performMockMvcCallAndAssertError(get(url), status().isBadRequest(),
                                         "{\"message\", \"getZone.name: must not be empty\" }");
    }

    @Test
    void testGetZone() throws Exception {
        //TODO: remove this createIdentityZone method once the create orchestrator zone API is implemented and use it to create zone.
        IdentityZone identityZone = createIdentityZone();
        assertNotNull(identityZone);
        OrchestratorZoneResponse zoneResponse =
            processZoneAPI(get("/orchestrator/zones"), "test-name", status().isOk());
        assertNotNull(zoneResponse);
        assertNotNull(zoneResponse.getParameters());
        assertEquals(identityZone.getSubdomain(), zoneResponse.getParameters().getSubdomain());
        assertEquals(identityZone.getSubdomain(), zoneResponse.getConnectionDetails().getSubdomain());
        String uri = "http://" + identityZone.getSubdomain() + ".localhost";
        assertEquals(uri, zoneResponse.getConnectionDetails().getUri());
        assertEquals("http://localhost:8080/dashboard", zoneResponse.getConnectionDetails().getDashboardUri());
        assertEquals(uri + "/oauth/token", zoneResponse.getConnectionDetails().getIssuerId());
        assertEquals(X_IDENTITY_ZONE_ID, zoneResponse.getConnectionDetails().getZone().getHttpHeaderName());
        assertEquals(identityZone.getId(), zoneResponse.getConnectionDetails().getZone().getHttpHeaderValue());
        // deleting after create and get to avoid multiple value in the database
        processZoneAPI(delete("/orchestrator/zones"), identityZone.getName(), status().isAccepted());
    }

    private OrchestratorZoneResponse processZoneAPI(MockHttpServletRequestBuilder mockRequestBuilder, String nameParameter,
                                                    ResultMatcher expectedStatus)
        throws Exception {
        MvcResult result = mockMvc.perform(
                                      mockRequestBuilder.param("name", nameParameter)
                                                        .header("Authorization", "Bearer " + identityClientZonesReadToken))
                                  .andExpect(expectedStatus).andReturn();
        if (StringUtils.hasLength(result.getResponse().getContentAsString()) &&
            result.getResponse().getStatus() == 200) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), OrchestratorZoneResponse.class);
        } else {
            return null;
        }
    }

    private void performMockMvcCallAndAssertError(MockHttpServletRequestBuilder identityZone, ResultMatcher expectedStatus,
                                                  String expected) throws Exception {
        MvcResult result = mockMvc.perform(identityZone
                                          .header("Authorization", "Bearer " + identityClientZonesReadToken))
                                  .andExpect(expectedStatus).andReturn();
        assertEquals(expected, result.getResponse().getContentAsString());
    }

    @Test
    void testGetZone_Notfound() throws Exception {
        performMockMvcCallAndAssertError(get("/orchestrator/zones").param("name", "random-name"), status().isNotFound(),
                                         "{\"message\", \"Zone[random-name] not found.\" }");
    }

    @Test
    void testDeleteZone() throws Exception {
        //TODO: remove this createIdentityZone method once the create orchestrator zone API is implemented and use it to create zone.
        IdentityZone identityZone = createIdentityZone();
        uaaEventListener.clearEvents();
        processZoneAPI(delete("/orchestrator/zones"), identityZone.getName(), status().isAccepted());
        performMockMvcCallAndAssertError(get("/orchestrator/zones").param("name", identityZone.getName()),
                                         status().isNotFound(),
                                         "{\"message\", \"Zone[test-name] not found.\" }");

        // Asserting delete event
        assertThat(uaaEventListener.getEventCount(), is(1));
        AbstractUaaEvent event = uaaEventListener.getLatestEvent();
        assertThat(event, instanceOf(EntityDeletedEvent.class));
        EntityDeletedEvent deletedEvent = (EntityDeletedEvent) event;
        assertThat(deletedEvent.getDeleted(), instanceOf(IdentityZone.class));
    }

    @Test
    void testDeleteZone_ZoneNotFound() throws Exception {
        performMockMvcCallAndAssertError(delete("/orchestrator/zones").param("name", "random-name"),
                                         status().isNotFound(),
                                         "{\"message\", \"Zone[random-name] not found.\" }");
    }

    @Test
    void testUpdateZone_MethodNotImplemented() throws Exception {
        performMockMvcCallAndAssertError(put("/orchestrator/zones").contentType(APPLICATION_JSON).content(
                                       "{\"name\": \"\",\"parameters\": {\"adminSecret\": \"\",\"subDomain\": \"\"}}"),
                                         status().isMethodNotAllowed(),
                                         "{\"message\", \"Put Operation not Supported\" }");
    }

    //TODO: delete once the orchestrator create API implemented
    @SneakyThrows
    private IdentityZone createIdentityZone() {
        IdentityZone identityZone = createSimpleIdentityZone(RandomString.make(10));
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");
        identityZoneConfiguration.getTokenPolicy().setKeys(keys);
        identityZoneConfiguration.getTokenPolicy().setActiveKeyId("kid");
        identityZoneConfiguration.getTokenPolicy().setKeys(keys);

        identityZone.setConfig(identityZoneConfiguration);
        identityZone.getConfig().getSamlConfig().setPrivateKey(serviceProviderKey);
        identityZone.getConfig().getSamlConfig().setPrivateKeyPassword(serviceProviderKeyPassword);
        identityZone.getConfig().getSamlConfig().setCertificate(serviceProviderCertificate);
        MvcResult result = mockMvc.perform(
                                      post("/identity-zones")
                                          .header("Authorization", "Bearer " + uaaAdminClientToken)
                                          .contentType(APPLICATION_JSON)
                                          .content(JsonUtils.writeValueAsString(identityZone)))
                                  .andExpect(status().is(HttpStatus.CREATED.value()))
                                  .andReturn();

        return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
    }

    //TODO: delete once the orchestrator create API implemented
    private IdentityZone createSimpleIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(hasText(id) ? id : new RandomValueStringGenerator().generate());
        identityZone.setName("test-name");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    private static class IdentityZonesBaseUrlsArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones"),
                Arguments.of("/orchestrator/zones/"),
                Arguments.of("/orchestrator/zones/test")
                            );
        }
    }

    private static class NameNotEmptyArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones?name="),
                Arguments.of("/orchestrator/zones?name= ")
                            );
        }
    }

    private static class NameRequiredArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones?name"),
                Arguments.of("/orchestrator/zones")
                            );
        }
    }
}
