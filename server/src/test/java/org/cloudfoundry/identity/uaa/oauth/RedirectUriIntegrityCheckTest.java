package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests whether redirect_uri authentication check correctly examines the path.
 */
class RedirectUriIntegrityCheckTest {

    @Test
    void authorize_implicitGrant_succeeds() throws Exception {
        UaaAuthorizationEndpoint endpoint = new UaaAuthorizationEndpoint();
        ClientDetailsService clientDetailsService = mock(ClientServicesExtension.class);
        String clientId = "alpha";
        ClientDetails clientDetails = new BaseClientDetails(); //todo
        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);
        endpoint.setClientDetailsService(clientDetailsService);
        AuthorizationServerEndpointsConfigurer endpointsConfigurer = new AuthorizationServerEndpointsConfigurer();
        TokenGranter tokenGranter = endpointsConfigurer.getTokenGranter();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.afterPropertiesSet(); //todo
        Map<String, Object> model = new HashMap<>();
        Map<String, String> parameters = ImmutableMap.of(
                "response_type", "token",
                ClaimConstants.CLIENT_ID, clientId,
                "redirect_uri", "http://example.com/foo/bar"
        );
        SessionStatus sessionStatus = new SimpleSessionStatus();
        UaaPrincipal uaaPrincipal = new UaaPrincipal(
                new UUID(1,1).toString(),
                "bob",
                "bob@example.com",
                OriginKeys.UAA,
                null,
                OriginKeys.UAA
        );
        String sessionId = "1EB2BB5923CBD91FC21656920DF4D9F2"; //todo
        Principal principal = new UaaAuthentication(
                uaaPrincipal,
                Collections.singleton(new SimpleGrantedAuthority("alv")),
                new UaaAuthenticationDetails(false, null, "127.0.0.1", sessionId)
        );
        HttpServletRequest request = new MockHttpServletRequest();
        ModelAndView mav = endpoint.authorize(model, parameters, sessionStatus, principal, request);
        System.out.println(mav);
    }

}
