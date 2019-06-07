package org.cloudfoundry.identity.uaa.integration.feature;

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createClient;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.junit.Assert.*;

/**
 * Tests whether redirect_uri authentication check correctly examines the path.
 */
public class RedirectUriIntegrityCheckIT {


    private static final String REDIRECT_URL_PATTERN = "http://localhost:8080/redirect/cf#token_type=.+access_token=.+";

    @Rule
    public static ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private String implicitUrl() {
        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "token")
                        .queryParam("client_id", "app")
                        .queryParam("redirect_uri", "http://localhost:8080/app/%2E%2E/redirect/cf")
                        .queryParam("scope", "cloud_controller.read").build();
        return uri.toString();
    }

    @BeforeAll
    //todo: is beforeAll appropriate?
    private static void createClientAndUser() throws Exception {
        createTestClient();
    }

    private static void createTestClient() throws Exception {
        String clientId = "client_for_redirect_uri_test";
        String baseUrl = serverRunning.getBaseUrl();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        BaseClientDetails client = new BaseClientDetails();
        client.setClientId(clientId);
        client.setAuthorizedGrantTypes(Collections.singleton(TokenConstants.GRANT_TYPE_IMPLICIT));
        client.setRegisteredRedirectUri(Collections.singleton("http://example.com/foo"));
        createClient(adminToken, baseUrl, client);
    }

    @Test
    void authzViaJsonEndpointFailsWithHttpGet() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
                        testAccounts.getPassword());

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl() + "&credentials={credentials}",
                        headers, credentials);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());

    }

    @Test
    void authzViaJsonEndpointSucceedsWithCorrectCredentials() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
                        testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
            .matches(REDIRECT_URL_PATTERN));

    }

    @Test
    void authzViaJsonEndpointSucceedsWithAcceptForm() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED));

        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
                        testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        URI location = result.getHeaders().getLocation();
        assertNotNull(location);
        assertTrue("Wrong location: " + location, location.toString()
            .matches(REDIRECT_URL_PATTERN));

    }

    @Test
    void authzWithIntermediateFormLoginSucceeds() {

        BasicCookieStore cookies = new BasicCookieStore();

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), getHeaders(cookies));
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));


        location = "/login.do";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        result = serverRunning.postForRedirect(location, getHeaders(cookies), formData);

        // System.err.println(result.getStatusCode());
        // System.err.println(result.getHeaders());

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
            .matches(REDIRECT_URL_PATTERN));
    }

    @Test
    void authzWithNonExistingIdentityZone() {
        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzonedoesnotexist.localhost"), new HttpHeaders());
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    void authzWithInactiveIdentityZone() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzoneinactive.localhost"), new HttpHeaders());
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }


}
