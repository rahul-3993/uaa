package org.cloudfoundry.identity.uaa.provider.saml;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.evaluateXPathExpression;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.trust.AllowAllSignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SAMLResponseTest {

    @Before
    public void initializeOpenSAML() throws Exception {
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void testSAMLAssertionSignature() throws Exception {

//        String certStr = "MIIC8DCCAdigAwIBAgIQVXSp8+EzY6xO31CACTtJaTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0xODA5MTAxNzI0NDRaFw0yMTA5MTAxNzI0NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr6mvzY1Vz/fbbevWvphe15sb8ApPsYCozybotCpml5L/+SNtwDqxafBZFR0UOCOV0oFFg+Nqrd4MuJFxS46vkk/ia8TtiEjxeknbs1aVIaTKU9Etn44phKDdGJVlgSoectqxX7ubWianAQgn9id/pel0ECKUxN6WUjBzHHTy3GgBIyYy/Kw+Hji8vu4P9XAtisOBOST5hW2nMRKFG/FpH3xR5pBxhKqtxvQUKl3SKMcor4HPuL7Lp36Q6N3BWS8obqySWZA+TtCZDYK3M1be5yHWnWt+w7YS4AlmMK4dHeytxFPmc/zwqKum3BY0pM9GY2Pr/WS3cBuTbwFf3U4RywIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCQ2q8n9kXCMkgwRTV4UaTVrNMoweQfUYTqg/2M6giNxXUvuUq0XaI+WIVIBDVgByFhFeZmRTqCKm9fIiCOMD4M7zCi+uO89kPP8g9Da1J01RJK7nHrIkcfVTbtlfSFsVMtn7bT+tw7g+hkLzPRGleXmO0SBXY6kzD0BkStacxO2hrSFrQUuOFf6OpaQd0EBTNQu+B2m1VWYJd+dBisDZFka7pUFcNWy0M6Vk+bpWQDKkTtkip5AjuyQaLcYh3SoFAk5hCOUTHwxxYGV8p8Puqb5IIuNswBIO8TBMCcyIlL0sivQhVNv2JDS9XBbm+z2CNjC6GUp7xz7G/ULTwrVhBQ";
//        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
//                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certStr)));

        Response response = readSAMLResponseFromFile();
        Assertion assertion = response.getAssertions().get(0);
        assertNotNull(assertion);

        Signature signature = assertion.getSignature();
        assertNotNull(signature);

//        X509Certificate certificate = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
//        assertNotNull(certificate);
//        assertNotNull(certificate..getPublicKey());
//
//        BasicX509Credential credential = new BasicX509Credential();
//        credential.setEntityId(assertion.getIssuer().getValue());
//        credential.setUsageType(UsageType.SIGNING);
//        credential.setEntityCertificate(certificate);
//        credential.setPublicKey(certificate.getPublicKey());
//
//        SignatureValidator validator = new SignatureValidator(credential);
//        validator.validate(signature);

        SignatureTrustEngine trustEngine = new AllowAllSignatureTrustEngine(
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());

        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator(); 
        validator.validate(signature);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(assertion.getIssuer().getValue()));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, org.opensaml.common.xml.SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING)); 

        assertTrue(trustEngine.validate(signature, criteriaSet));
    }

    private Response readSAMLResponseFromFile() throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document doc = documentBuilderFactory.newDocumentBuilder()
                .parse(SAMLResponseTest.class.getResourceAsStream("/saml/saml-response.xml"));

        NodeList signatureNodes = evaluateXPathExpression(doc,
                "//*[local-name()='SignatureMethod' and @*[local-name() = 'Algorithm']='" + SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256 + "']");
        assertEquals(1, signatureNodes.getLength());

        Element element = doc.getDocumentElement();
        assertNotNull(element);

        Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(element);
        assertNotNull(unmarshaller);

        Response response = (Response) unmarshaller.unmarshall(element);
        return response;
    }
}
