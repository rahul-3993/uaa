/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.experimental.runners.Enclosed;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(Enclosed.class)
public class AntPathRedirectResolverTests {

    public static class AntPathRedirectResolverTestsNonParameterized {
        String requestedRedirectHttp = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

        private final String clientRedirectUri = "http://domain.com";

        @Test
        public void allSubdomainsShouldNotMatch() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com", clientRedirectUri));
        }

        @Test
        public void allPathsShouldMatch() {
            assertTrue(resolver.redirectMatches("http://domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/another", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://domain.com/one/two", clientRedirectUri));
        }

        @Test
        public void allPathsInAnySubdomainShouldNotMatch() {
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://another-subdomain.domain.com/one/two", clientRedirectUri));

            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/another", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://one.two.domain.com/one/two", clientRedirectUri));
        }

        @Test
        public void test_Redirect_Matches_Happy_Day() throws Exception {
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, "http://domain.com"));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, "https://domain.com"));
        }

        @Test
        public void testClientMissingRedirectUri() {
            ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", "authorization_code", "");
            try {
                resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
                fail();
            } catch (RedirectMismatchException e) {
                String reason = "Client registration is missing redirect_uri";
                Assert.assertThat(e.getMessage(), containsString(reason));
            }
        }

        @Test
        public void testClientWithInvalidRedirectUri() {
            ClientDetails clientDetails = new BaseClientDetails("client1", "", "openid", "authorization_code", "", "*, */*");
            try {
                resolver.resolveRedirect(requestedRedirectHttp, clientDetails);
                fail();
            } catch (RedirectMismatchException e) {
                String reason = "Client registration contains invalid redirect_uri";
                Assert.assertThat(e.getMessage(), containsString(reason));
                Assert.assertThat(e.getMessage(), containsString("*,  */*"));
            }
        }

        @Test
        public void test_Redirect_Any_Scheme() throws Exception {
            String path = "http*://subdomain.domain.com/**";
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
        }

        @Test
        public void test_Redirect_Http_Only_Scheme() throws Exception {
            String path = "http://subdomain.domain.com/**";
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
        }

        @Test
        public void test_Redirect_Https_Only_Scheme() throws Exception {
            String path = "https://subdomain.domain.com/**";
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
        }

        @Test
        public void test_Redirect_Query_Path() throws Exception {
            String path = "http*://subdomain.domain.com/path1/path2**";
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

            path = "http*://subdomain.domain.com/path1/path3**";
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
        }

        @Test
        public void test_Redirect_Subdomain() throws Exception {
            String path = "http*://*.domain.com/path1/path2**";
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, path));
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, path));

            path = "http*://*.domain.com/path1/path3**";
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, path));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, path));
        }
    }

    @RunWith(Parameterized.class)
    public static class WhenMatchingWithAllSubPathsPattern {
        private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

        private String requestedRedirectUri;
        private boolean expectedMatch;

        public WhenMatchingWithAllSubPathsPattern(String requestedRedirectUri, boolean expectedMatch) {
            this.requestedRedirectUri = requestedRedirectUri;
            this.expectedMatch = expectedMatch;
        }

        @Parameters
        public static List<Object[]> data() {
            return Arrays.asList(new Object[][] {
                {"http://subdomain.domain.com",                   true},
                {"http://another-subdomain.domain.com",           true},
                {"http://one.two.domain.com",                     true},
                {"http://domain.com/one",                         false},
                {"http://domain.com/another",                     false},
                {"http://domain.com/one/two",                     false},
                {"http://subdomain.domain.com/one",               true},
                {"http://subdomain.domain.com/another",           true},
                {"http://subdomain.domain.com/one/two",           true},
                {"http://another-subdomain.domain.com/one",       true},
                {"http://another-subdomain.domain.com/another",   true},
                {"http://another-subdomain.domain.com/one/two",   true},
                {"http://one.two.domain.com/one",                 true},
                {"http://one.two.domain.com/another",             true},
                {"http://one.two.domain.com/one/two",             true},
                {"http://other-domain.com",                       false},
                {"http://domain.io",                              false},
                {"https://domain.com",                            false},
                {"ws://domain.com",                               false},
            });
        }

        @Parameterized.Parameters(name = "{index} matching {0} against http://*.domain.com/**")
        public void matchAgainstUriThatAllowsSubdomains() {
            String registeredRedirectUri = "http://*.domain.com/**";

            boolean actualMatch = resolver.redirectMatches(requestedRedirectUri, registeredRedirectUri);

            if (expectedMatch) {
                assertTrue("expected " + requestedRedirectUri + " to match " + registeredRedirectUri + " but did not match", actualMatch);
            } else {
                assertFalse("expected " + requestedRedirectUri + " not to match " + registeredRedirectUri + " but did match", actualMatch);
            }
        }

        @Test(expected = Exception.class)
        public void setMatchSubdomains_throwsException() {
            resolver.setMatchSubdomains(true);
        }
    }

    public class ResolveRedirect {
        ClientDetails mockClientDetails;
        private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

        @Before
        void setUp() {
            mockClientDetails = mock(BaseClientDetails.class);
            when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        }

        @Test(expected = RedirectMismatchException.class)
        void testResolveClientWithUrlWhichHasNoWildcardsAndDoesNotEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("https://uaa.com");
        }


        @Test(expected = RedirectMismatchException.class)
        void testResolveClientWithUrlWhichHasPortAndHasNoWildcardsAndDoesNotEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz/abc/1234");
            assertResolveRedirectThrows________("http://subdomain.uaa.com:8080");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com:8080");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com:8081");
            assertResolveRedirectThrows________("https://uaa.com:8080");
        }

        @Test(expected = RedirectMismatchException.class)
        void testResolveClientWithUrlWhichHasNoWildcardsAndDoesEndInSlash() {
            mockRegisteredRedirectUri("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://user:pass@uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.uaa.com");
            assertResolveRedirectThrows________("https://uaa.com");
        }

        private void mockRegisteredRedirectUri(String allowedRedirectUri) {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton(allowedRedirectUri));
        }
        private void assertResolveRedirectReturnsSameUrl(String requestedRedirect) {
            assertThat(resolver.resolveRedirect(requestedRedirect, mockClientDetails), equalTo(requestedRedirect));
        }

        private void assertResolveRedirectThrows________(String requestedRedirect) {
            resolver.resolveRedirect(requestedRedirect, mockClientDetails);
        }
    }

    @RunWith(Parameterized.class)
    public static class IntegrityCheckBypass {
        AntPathRedirectResolver resolver = new AntPathRedirectResolver();

        enum Type {SINGLE_DOT_TRAVERSAL, DOUBLE_DOT_TRAVERSAL}

        private String requestedSuffix;
        private String registeredSuffix;
        private Type type;

        public IntegrityCheckBypass(Type type, String requestedSuffix, String registeredSuffix) {
            this.type = type;
            this.requestedSuffix = requestedSuffix;
            this.registeredSuffix = registeredSuffix;
        }

        private static final String REGISTERED_REDIRECT_URI = "http://example.com/foo";

        @Parameters
        public static List<Object[]> data() {
            return Arrays.asList(new Object[][] {
                { Type.SINGLE_DOT_TRAVERSAL, "/./bar", "" },
                { Type.SINGLE_DOT_TRAVERSAL, "/./bar", "/**" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%2e/bar", "" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%2e/bar", "/**" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%252e/bar", "" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%252e/bar", "/**" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%2525252e/bar", "" },
                { Type.SINGLE_DOT_TRAVERSAL, "/%2525252e/bar", "/**" },

                { Type.DOUBLE_DOT_TRAVERSAL, "/../bar", "" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/../bar", "/**" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%2e./bar", "" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%2e./bar", "/**" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%252e./bar", "" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%252e./bar", "/**" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%2525252e./bar", "" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%2525252e./bar", "/**" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%25252525252525252525252e./bar", "" },
                { Type.DOUBLE_DOT_TRAVERSAL, "/%25252525252525252525252e./bar", "/**" }
            });
        }

        @Parameterized.Parameters(name = "{index} " + REGISTERED_REDIRECT_URI + "{1} shoud not match " + REGISTERED_REDIRECT_URI + "{2}")
        @Test
        public void doubleDotTraversal() {
            Assume.assumeTrue(type == Type.DOUBLE_DOT_TRAVERSAL);
            assertFalse(resolver.redirectMatches(REGISTERED_REDIRECT_URI + requestedSuffix, REGISTERED_REDIRECT_URI + registeredSuffix));
        }

        @Parameterized.Parameters(name = "{index} " + REGISTERED_REDIRECT_URI + "{1} shoud match " + REGISTERED_REDIRECT_URI + "{2}")
        @Test
        public void singleDotTraversal() {
            Assume.assumeTrue(type == Type.SINGLE_DOT_TRAVERSAL);
            assertTrue(resolver.redirectMatches(REGISTERED_REDIRECT_URI + requestedSuffix, REGISTERED_REDIRECT_URI + registeredSuffix));
        }
    }
}