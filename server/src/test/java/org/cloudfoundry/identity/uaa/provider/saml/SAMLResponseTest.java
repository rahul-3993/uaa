package org.cloudfoundry.identity.uaa.provider.saml;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLResponseTest {
    protected static BasicParserPool parser;

    @Before
    public void initializeOpenSAML() throws Exception {
        DefaultBootstrap.bootstrap();

        parser = new BasicParserPool();
        parser.setNamespaceAware(true);
    }

    @Test
    public void testSAMLAssertionSignature() throws Exception {

        // String certStr =
        // "MIIC8DCCAdigAwIBAgIQVXSp8+EzY6xO31CACTtJaTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0xODA5MTAxNzI0NDRaFw0yMTA5MTAxNzI0NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr6mvzY1Vz/fbbevWvphe15sb8ApPsYCozybotCpml5L/+SNtwDqxafBZFR0UOCOV0oFFg+Nqrd4MuJFxS46vkk/ia8TtiEjxeknbs1aVIaTKU9Etn44phKDdGJVlgSoectqxX7ubWianAQgn9id/pel0ECKUxN6WUjBzHHTy3GgBIyYy/Kw+Hji8vu4P9XAtisOBOST5hW2nMRKFG/FpH3xR5pBxhKqtxvQUKl3SKMcor4HPuL7Lp36Q6N3BWS8obqySWZA+TtCZDYK3M1be5yHWnWt+w7YS4AlmMK4dHeytxFPmc/zwqKum3BY0pM9GY2Pr/WS3cBuTbwFf3U4RywIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCQ2q8n9kXCMkgwRTV4UaTVrNMoweQfUYTqg/2M6giNxXUvuUq0XaI+WIVIBDVgByFhFeZmRTqCKm9fIiCOMD4M7zCi+uO89kPP8g9Da1J01RJK7nHrIkcfVTbtlfSFsVMtn7bT+tw7g+hkLzPRGleXmO0SBXY6kzD0BkStacxO2hrSFrQUuOFf6OpaQd0EBTNQu+B2m1VWYJd+dBisDZFka7pUFcNWy0M6Vk+bpWQDKkTtkip5AjuyQaLcYh3SoFAk5hCOUTHwxxYGV8p8Puqb5IIuNswBIO8TBMCcyIlL0sivQhVNv2JDS9XBbm+z2CNjC6GUp7xz7G/ULTwrVhBQ";
        // X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
        // .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certStr)));

        // X509Certificate certificate = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        // assertNotNull(certificate);
        // assertNotNull(certificate..getPublicKey());
        //
        // BasicX509Credential credential = new BasicX509Credential();
        // credential.setEntityId(assertion.getIssuer().getValue());
        // credential.setUsageType(UsageType.SIGNING);
        // credential.setEntityCertificate(certificate);
        // credential.setPublicKey(certificate.getPublicKey());

        // SignatureValidator validator = new SignatureValidator(credential);
        // validator.validate(signature);

        // List<Credential> credentials = new ArrayList<>();
        // credentials.add(credential);

        Response response = readSAMLResponse("/saml/saml-response-success.xml");
        Assertion assertion = response.getAssertions().get(0);
        assertNotNull(assertion);

        Signature signature = assertion.getSignature();
        assertNotNull(signature);

        MetadataProvider metadata = readIdpMetadata("/saml/idp-metadata.xml");
        MetadataCredentialResolver metadataResolver = new MetadataCredentialResolver(metadata);
        metadataResolver.setMeetAllCriteria(false); 
        metadataResolver.setUnevaluableSatisfies(true);

//        MetadataManager metadataManager = null;
//        KeyManager keyManager = null;
//        MetadataCredentialResolver metadataResolver = new MetadataCredentialResolver(metadataManager, keyManager); 
//        metadataResolver.setMeetAllCriteria(false); 
//        metadataResolver.setUnevaluableSatisfies(true); 

        SignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(metadataResolver,
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());

        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(signature);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(assertion.getIssuer().getValue()));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME,
                org.opensaml.common.xml.SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

//        assertEquals("xxxxx", metadataResolver.resolve(criteriaSet).iterator().next().getEntityId());

        assertTrue(trustEngine.validate(signature, criteriaSet));
    }

    private MetadataProvider readIdpMetadata(final String file) {
        try {
            DOMMetadataProvider metadata = new DOMMetadataProvider(readElement(file));
            metadata.initialize();
            return metadata;
        } catch (XMLParserException e) {
            fail("Unable to parse element file " + file);
        } catch (MetadataProviderException e) {
            fail("Unable to initialize metadata from file " + file);
        }
        return null;
    }

    private Response readSAMLResponse(final String file) {
        return (Response) unmarshallElement(file);
    }


    private Element readElement(final String elementFile) throws XMLParserException {
        Document doc = parser.parse(SAMLResponseTest.class.getResourceAsStream(elementFile));
        Element samlElement = doc.getDocumentElement();
        return samlElement;
    }

    private XMLObject unmarshallElement(final String elementFile) {
        try {
            Element samlElement = readElement(elementFile);

            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
            if (unmarshaller == null) {
                fail("Unable to retrieve unmarshaller by DOM Element");
            }

            return unmarshaller.unmarshall(samlElement);
        } catch (XMLParserException e) {
            fail("Unable to parse element file " + elementFile);
        } catch (UnmarshallingException e) {
            fail("Unmarshalling failed when parsing element file " + elementFile + ": " + e);
        }
        return null;
    }
}

