/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.*;


public class GeneralIdentityZoneConfigurationValidator implements IdentityZoneConfigurationValidator {

    private SignatureAlgorithm defaultSamlSignatureAlgorithm;

    @Override
    public IdentityZoneConfiguration validate(IdentityZoneConfiguration config, IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        if (mode == IdentityZoneValidator.Mode.CREATE || mode == IdentityZoneValidator.Mode.MODIFY) {
            String currentKeyId = null;
            try {
                SamlConfig samlConfig;
                if ((samlConfig = config.getSamlConfig()) != null && samlConfig.getKeys().size()>0) {
                    String activeKeyId = samlConfig.getActiveKeyId();
                    if ( (activeKeyId == null || samlConfig.getKeys().get(activeKeyId) == null)) {

                        throw new InvalidIdentityZoneConfigurationException(String.format("Invalid SAML active key ID: '%s'. Couldn't find any matching keys.", activeKeyId));
                    }

                    for (Map.Entry<String, SamlKey> entry : samlConfig.getKeys().entrySet()) {
                        currentKeyId = entry.getKey();
                        String samlSpCert = entry.getValue().getCertificate();
                        String samlSpKey = entry.getValue().getKey();
                        String samlSpkeyPassphrase = entry.getValue().getPassphrase();
                        if (samlSpKey != null && samlSpCert != null) {
                            new KeyWithCert(samlSpKey, samlSpkeyPassphrase, samlSpCert);
                        }
                        failIfPartialCertKeyInfo(samlSpCert, samlSpKey, samlSpkeyPassphrase);
                    }
                }
                if(samlConfig != null && samlConfig.getSignatureAlgorithm() != null) {
                    boolean invalidSignatureAlgorithm = false;
                    switch(samlConfig.getSignatureAlgorithm()) {

                        case UNKNOWN :
                            throw new InvalidIdentityZoneConfigurationException(String.format("Invalid SAML signatureAlgorithm. Must be one of : %s", JsonUtils.writeValueAsString(SignatureAlgorithm.values())));
                        case SHA1:
                            if(mode == IdentityZoneValidator.Mode.CREATE && defaultSamlSignatureAlgorithm != SHA1) {
                                invalidSignatureAlgorithm = true;
                            }
                            break;
                        case SHA256:
                            if(mode == IdentityZoneValidator.Mode.CREATE && defaultSamlSignatureAlgorithm == SHA512) {
                                invalidSignatureAlgorithm = true;
                            }
                            break;
                    }
                    if(invalidSignatureAlgorithm) {
                        throw new InvalidIdentityZoneConfigurationException("Invalid SAML signatureAlgorithm. Must be " + defaultSamlSignatureAlgorithm + " or higher");
                    }
                }
            } catch (GeneralSecurityException ex) {
                throw new InvalidIdentityZoneConfigurationException(String.format("There is a security problem with the SAML SP Key configuration for key '%s'.", currentKeyId), ex);
            }

            TokenPolicy tokenPolicy = config.getTokenPolicy();
            if (tokenPolicy != null) {
                String activeKeyId = tokenPolicy.getActiveKeyId();
                if (StringUtils.hasText(activeKeyId)) {
                    Map<String, String> jwtKeys = tokenPolicy.getKeys();

                    if (jwtKeys == null || jwtKeys.isEmpty()) {
                        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot specify an active key ID with no keys configured for the zone.", null);
                    } else {
                        if (!jwtKeys.containsKey(activeKeyId)) {
                            throw new InvalidIdentityZoneConfigurationException("The specified active key ID is not present in the configured keys: " + activeKeyId, null);
                        }
                    }
                }
            }

            Links links = config.getLinks();
            if (links != null){
                List<String> redirectURIProtocolSchemes = links.getRedirectURIProtocolWhiteList();
                if (redirectURIProtocolSchemes == null || redirectURIProtocolSchemes.isEmpty()) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid Redirect Uri Protocol Whitelist. Must provide at least one protocol scheme.");
                } else {
                    boolean inValidScheme =  redirectURIProtocolSchemes.stream().anyMatch(scheme -> (!UaaUrlUtils.allowedRedirectUriProtocolPattern.matcher(scheme).matches()) );
                    if (inValidScheme) {
                        throw new InvalidIdentityZoneConfigurationException(
                                String.format("Invalid Redirect Uri Protocol Whitelist Element(s) found. Must Match the pattern %s", UaaUrlUtils.allowedRedirectUriProtocolPattern));
                    }
                }
            }
        }

        if(config.getBranding() != null && config.getBranding().getBanner() != null) {
           BannerValidator.validate(config.getBranding().getBanner());
        }

        return config;
    }

    private void failIfPartialCertKeyInfo(String samlSpCert, String samlSpKey, String samlSpkeyPassphrase) throws InvalidIdentityZoneConfigurationException {
        if ((samlSpCert == null && samlSpKey == null && samlSpkeyPassphrase == null) ||
            (samlSpCert != null && samlSpKey != null && samlSpkeyPassphrase != null)) {
            return;
        }
        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot be udpated with partial Saml CertKey config.", null);
    }

    public void setDefaultSamlSignatureAlgorithm(SignatureAlgorithm samlSignatureAlgorithm) {
        this.defaultSamlSignatureAlgorithm = samlSignatureAlgorithm;
    }
}
