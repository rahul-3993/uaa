package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.ZoneScimInviteData;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.hamcrest.core.StringContains;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.NONE;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.SIMPLE;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(Parameterized.class)
public class LdapMockMvcTests  {


    private static int ldapPortRotation = 0;
    private String host;
    private static WebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;

    public WebApplicationContext getWebApplicationContext() {
        return webApplicationContext;
    }

    public MockMvc getMockMvc() {
        return mockMvc;
    }



    @Parameters(name = "{index}: auth[{0}]; group[{1}]; url[{2}]; tls[{3}]")
    public static List<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"ldap-simple-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389", NONE},
            //{"ldap-simple-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389", SIMPLE},
            //{"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389", SIMPLE},
            //{"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636", NONE},
            //{"ldap-search-and-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389", SIMPLE},
            //{"ldap-search-and-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389", SIMPLE},
            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389", SIMPLE},
            //{"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636", NONE},
            //{"ldap-search-and-compare.xml", "ldap-groups-null.xml", "ldap://localhost:33389", NONE},
            //{"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389", NONE},
            //{"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389", SIMPLE},
            {"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml", "ldaps://localhost:33636", NONE},
            //{"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636", NONE}
        });
    }

    private static ApacheDsSSLContainer apacheDS;
    private static ApacheDsSSLContainer apacheDS2;
    private static File tmpDir;

    @AfterClass
    public static void afterClass() throws Exception {
        DefaultConfigurationTestSuite.destroyMyContext();
        apacheDS.stop();
    }

    public static boolean checkOpenPorts(int port) throws Exception {
        //need to configure gradle to not swallow the output, but log it to a file
        System.out.println("Checking for processes using port:"+port);
        ProcessBuilder builder = new ProcessBuilder(Arrays.asList("sudo", "lsof", "-i", ":"+port));
        builder.inheritIO().redirectOutput(ProcessBuilder.Redirect.PIPE);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(builder.start().getInputStream()))) {
            long count = reader.lines().count();
            reader.lines().forEach(line -> System.err.println("LDAP Port["+port+"] lsof:"+line));
            return count > 0;
        }
    }

    @BeforeClass
    public static void startApacheDS() throws Exception {
        checkOpenPorts(33389);
        checkOpenPorts(33636);
        apacheDS = ApacheDSHelper.start();
        webApplicationContext = DefaultConfigurationTestSuite.setUpContext();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
    }

    private String ldapProfile;
    private String ldapGroup;
    private String ldapBaseUrl;
    private String tlsConfig;

    private String REDIRECT_URI = "http://invitation.redirect.test";
    private ZoneScimInviteData zone;
    private IdentityProvider<LdapIdentityProviderDefinition> provider;

    public LdapMockMvcTests(String ldapProfile, String ldapGroup, String baseUrl, String tlsConfig) {
        this.ldapGroup = ldapGroup;
        this.ldapProfile = ldapProfile;
        this.ldapBaseUrl = baseUrl;
        this.tlsConfig = tlsConfig;
    }

    @Before
    public void createTestZone() throws Exception {

        String clientId = new RandomValueStringGenerator().generate().toLowerCase();
        zone = utils().createZoneForInvites(getMockMvc(), getWebApplicationContext(), clientId, REDIRECT_URI);

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        definition.setLdapProfileFile("ldap/" + ldapProfile);
        definition.setLdapGroupFile("ldap/" + ldapGroup);
        definition.setMaxGroupSearchDepth(10);
        definition.setBaseUrl(ldapBaseUrl);
        definition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
        definition.setBindPassword("adminsecret");
        definition.setSkipSSLVerification(true);
        definition.setTlsConfiguration(tlsConfig);
        definition.setMailAttributeName("mail");
        definition.setReferral("ignore");

        provider = MockMvcUtils.createIdentityProvider(getMockMvc(),
                                                       zone.getZone(),
                                                       LDAP,
                                                       definition);

        host = zone.getZone().getIdentityZone().getSubdomain() + ".localhost";
        IdentityZoneHolder.clear();
    }

    @After
    public void tearDown() throws Exception {
        getMockMvc().perform(
            delete("/identity-zones/{id}", zone.getZone().getIdentityZone().getId())
                .header("Authorization", "Bearer " + zone.getDefaultZoneAdminToken())
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk());
    }


    @Test
    public void testLdapGroupMapping() throws Exception {
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));

        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroup create = new ScimGroup("cloud_controller.admin");
        String uaaZoneId = IdentityZone.getUaa().getId();
        create.setZoneId(uaaZoneId);
        ScimGroup group = MockMvcUtils.createGroup(getWebApplicationContext(),
                                                   create,
                                                   uaaZoneId
        );

        MockMvcUtils.mapExternalGroup(getWebApplicationContext(),
                                      group.getId(),
                                      externalGroup,
                                      OriginKeys.LDAP,
                                      uaaZoneId
        );

        BaseClientDetails cfClient = new BaseClientDetails("cf", "", "cloud_controller.admin,openid", "password", "");
        cfClient.setClientSecret("");
        MockMvcUtils.createClient(getWebApplicationContext(), cfClient, zone.getZone().getIdentityZone().getId());

        LdapIdentityProviderDefinition definition = provider.getConfig();
        provider.setConfig(definition);
        updateLdapProvider();

        String username = "marissa6";
        String password = "ldap6";
        MvcResult result = performPasswordGrant(username,
                                                password,
                                                host,
                                                HttpStatus.OK,
                                                "cf",
                                                "");

        Map<String,Object> json = JsonUtils.readValue(result.getResponse().getContentAsString(),
                                                      new TypeReference<Map<String, Object>>() {});
        String accessToken = (String) json.get("access_token");

        Map<String,Object> claims = JsonUtils.readValue(JwtHelper.decode(accessToken).getClaims(),
                                                        new TypeReference<Map<String, Object>>() {});

        List<String> scopes = (List<String>) claims.get("scope");
        assertThat(scopes, containsInAnyOrder("openid"));
    }

    @Test
    public void acceptInvitation_for_ldap_user_whose_username_is_not_email() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        String email = "marissa2@test.com";
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM users WHERE email=?", email);
        LdapIdentityProviderDefinition definition = provider.getConfig();
        definition.setEmailDomain(Arrays.asList("test.com"));
        updateLdapProvider();

        URL url = utils().inviteUser(
            getWebApplicationContext(),
            getMockMvc(),
            email,
            zone.getAdminToken(),
            zone.getZone().getIdentityZone().getSubdomain(),
            zone.getScimInviteClient().getClientId(),
            LDAP,
            REDIRECT_URI
        );


        String code = utils().extractInvitationCode(url.toString());

        String userInfoOrigin = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String userInfoId = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertEquals(LDAP, userInfoOrigin);


        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                                                         .param("code", code)
                                                         .accept(MediaType.TEXT_HTML)
                                                         .header(HOST, host)
        );
        MvcResult result = actions.andExpect(status().isOk())
            .andExpect(content().string(containsString("Link your account")))
            .andExpect(content().string(containsString("Email: " + email)))
            .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
            .andExpect(content().string(containsString("username")))
            .andExpect(content().string(containsString("<input type=\"submit\" value=\"Sign in\" class=\"island-button\"/>")))
            .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        IdentityZoneHolder.clear();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(post("/invitations/accept_enterprise.do")
                                 .session(session)
                                 .param("enterprise_username", "marissa2")
                                 .param("enterprise_password", LDAP)
                                 .param("enterprise_email", "email")
                                 .param("code", code)
                                 .header(HOST, host)
                                 .with(csrf()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(REDIRECT_URI))
            .andReturn();

        String newUserInfoId = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoOrigin = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoUsername = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select username from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertEquals(LDAP, newUserInfoOrigin);
        assertEquals("marissa2", newUserInfoUsername);
        //ensure that a new user wasn't created
        assertEquals(userInfoId, newUserInfoId);


        //email mismatch
        getWebApplicationContext().getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        email = "different@test.com";
        url = utils().inviteUser(getWebApplicationContext(), getMockMvc(), email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), LDAP, REDIRECT_URI);
        code = utils().extractInvitationCode(url.toString());
>>>>>>> Add tests for external group mappings

// All of the copied and pasted code between the three classes below
// is because it is quite expensive to start ApacheDS in the BeforeEach,
// and because we would like these three classes to use different port
// numbers so these test classes can be run in parallel.
//
// At the time of writing, caching the ApacheDs server like this is saving us
// 30 seconds off our test time.
//
// Since JUnit BeforeAll's must be static, each of these classes
// needs to have copy/pasted static members and methods.

class LdapSimpleBindTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = 44389;
    private static int ldapSPort = 44336;

    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                "ldap://localhost:" + ldapPort,
                NONE
        );
<<<<<<< HEAD
=======
        result = actions.andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
            .andExpect(content().string(containsString("username")))
            .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        IdentityZoneHolder.clear();
        session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(post("/invitations/accept_enterprise.do")
                                 .session(session)
                                 .param("enterprise_username", "marissa2")
                                 .param("enterprise_password", LDAP)
                                 .param("enterprise_email", "email")
                                 .param("code", code)
                                 .header(HOST, host)
                                 .with(csrf()))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(content().string(containsString("The authenticated email does not match the invited email. Please log in using a different account.")))
            .andReturn();
        boolean userVerified = Boolean.parseBoolean(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select verified from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId()));
        assertFalse(userVerified);
>>>>>>> Add tests for external group mappings
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}

<<<<<<< HEAD
class LdapSearchAndCompareTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = 44390;
    private static int ldapSPort = 44337;

    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                "ldaps://localhost:" + ldapSPort,
                NONE
        );
=======
    private String getPhoneNumber(String username) throws Exception {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select phonenumber from users where username=? and origin=? and identity_zone_id=?", String.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private MvcResult performAuthentication(String username, String password) throws Exception {
        return performAuthentication(username, password, HttpStatus.OK);
    }

    private MvcResult performAuthentication(String username, String password, HttpStatus status) throws Exception {
        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .header(HOST, host)
                .accept(MediaType.APPLICATION_JSON)
                .param("username", username)
                .param("password", password);

        return getMockMvc().perform(post)
            .andExpect(status().is(status.value()))
            .andReturn();
    }

    private MvcResult performPasswordGrant(String username,
                                           String password,
                                           String host,
                                           HttpStatus status,
                                           String clientId,
                                           String clientSecret) throws Exception {
        MockHttpServletRequestBuilder post =
            post("/oauth/token")
                .header(HOST, host)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("grant_type", "password")
                .param("response_type", "token")
                .param("username", username)
                .param("password", password);

        return getMockMvc().perform(post)
            .andDo(print())
            .andExpect(status().is(status.value()))
            .andReturn();
    }

    private MvcResult performUiAuthentication(String username, String password, HttpStatus status, boolean authenticated) throws Exception {
        MockHttpServletRequestBuilder post =
            post("/login.do")
                .with(cookieCsrf())
                .header(HOST, host)
                .accept(MediaType.TEXT_HTML)
                .param("username", username)
                .param("password", password);

        return getMockMvc().perform(post)
            .andExpect(status().is(status.value()))
            .andExpect(authenticated ? authenticated() : unauthenticated())
            .andReturn();
>>>>>>> Add tests for external group mappings
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}

class LdapSearchAndBindTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = 44391;
    private static int ldapSPort = 44338;

    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                "ldap://localhost:" + ldapPort,
                SIMPLE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}
