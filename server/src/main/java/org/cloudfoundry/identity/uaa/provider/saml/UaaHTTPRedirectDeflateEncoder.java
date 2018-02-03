package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.credential.Credential;

public class UaaHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {

    private SecurityConfiguration securityConfiguration;

    public void setSecurityConfiguration(SecurityConfiguration securityConfiguration) {
        this.securityConfiguration = securityConfiguration;
    }

    @Override
    protected String getSignatureAlgorithmURI(Credential credential, SecurityConfiguration securityConfiguration) throws MessageEncodingException {
        if(securityConfiguration == null) {
            securityConfiguration = this.securityConfiguration;
        }
        return super.getSignatureAlgorithmURI(credential, securityConfiguration);
    }
}
