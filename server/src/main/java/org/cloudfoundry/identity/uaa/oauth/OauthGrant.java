package org.cloudfoundry.identity.uaa.oauth;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

public class OauthGrant {
    
    public static final Set<String> SUPPORTED_GRANTS =
            Collections.unmodifiableSet(
                        new HashSet<>(Arrays.asList(
                                            GRANT_TYPE_CLIENT_CREDENTIALS,
                                            GRANT_TYPE_PASSWORD,
                                            GRANT_TYPE_IMPLICIT,
                                            GRANT_TYPE_AUTHORIZATION_CODE,
                                            GRANT_TYPE_REFRESH_TOKEN,
                                            GRANT_TYPE_JWT_BEARER,
                                            GRANT_TYPE_USER_TOKEN,
                                            GRANT_TYPE_SAML2_BEARER)));
}
