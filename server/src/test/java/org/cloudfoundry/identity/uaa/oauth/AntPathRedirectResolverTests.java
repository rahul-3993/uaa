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

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;
import lombok.experimental.FieldDefaults;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests.RegisteredRedirectUri.*;
import static org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests.RequestedRedirectUri.Protocol.____http;
import static org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests.RequestedRedirectUri.Protocol.not_http;
import static org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests.RequestedRedirectUri.SecondLevelDomain.not_part_of_domain_dot_com;
import static org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests.RequestedRedirectUri.SecondLevelDomain.____part_of_domain_dot_com;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AntPathRedirectResolverTests {

    private final AntPathRedirectResolver resolver = new AntPathRedirectResolver();

    //todo: username@password?

    @FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
    enum RequestedRedirectUri {

        eg01("http://subdomain.domain.com",                 ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(0)),
        eg02("http://another-subdomain.domain.com",         ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(0)),
        eg03("http://one.two.domain.com",                   ____http, domain.parts(4), ____part_of_domain_dot_com, path.segments(0)),
        eg04("http://domain.com/one",                       ____http, domain.parts(2), ____part_of_domain_dot_com, path.segments(1)),
        eg05("http://domain.com/another",                   ____http, domain.parts(2), ____part_of_domain_dot_com, path.segments(1)),
        eg06("http://domain.com/one/two",                   ____http, domain.parts(2), ____part_of_domain_dot_com, path.segments(2)),
        eg07("http://subdomain.domain.com/one",             ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(1)),
        eg08("http://subdomain.domain.com/another",         ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(1)),
        eg09("http://subdomain.domain.com/one/two",         ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(2)),
        eg10("http://another-subdomain.domain.com/one",     ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(1)),
        eg11("http://another-subdomain.domain.com/another", ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(1)),
        eg12("http://another-subdomain.domain.com/one/two", ____http, domain.parts(3), ____part_of_domain_dot_com, path.segments(2)),
        eg13("http://one.two.domain.com/one",               ____http, domain.parts(4), ____part_of_domain_dot_com, path.segments(1)),
        eg14("http://one.two.domain.com/another",           ____http, domain.parts(4), ____part_of_domain_dot_com, path.segments(1)),
        eg15("http://one.two.domain.com/one/two",           ____http, domain.parts(4), ____part_of_domain_dot_com, path.segments(2)),
        eg16("http://other-domain.com",                     ____http, domain.parts(2), not_part_of_domain_dot_com, path.segments(0)),
        eg17("http://domain.io",                            ____http, domain.parts(2), not_part_of_domain_dot_com, path.segments(0)),
        eg18("https://domain.com",                          not_http, domain.parts(2), ____part_of_domain_dot_com, path.segments(0)),
        eg19("ws://domain.com",                             not_http, domain.parts(2), ____part_of_domain_dot_com, path.segments(0)),
        ;

        RequestedRedirectUri(String uri, Protocol protocol, domain d, SecondLevelDomain secondLevelDomain, path p) {
            this.uri = uri;
            http = protocol == ____http;
            domainParts = d.parts;
            belongsToDomainDotCom = secondLevelDomain == ____part_of_domain_dot_com;
            pathSegements = p.segments;
        }

        enum Protocol {
            ____http,
            not_http,
        }

        @Value
        private static class domain {
            int parts;

            static domain parts(int count) {
                return new domain(count);
            }
        }

        enum SecondLevelDomain {
            ____part_of_domain_dot_com,
            not_part_of_domain_dot_com,
        }

        @Value
        private static class path {
            int segments;

            static path segments(int count) {
                return new path(count);
            }
        }

        String uri;
        boolean http;
        int domainParts;
        boolean belongsToDomainDotCom;
        int pathSegements;


        @Override
        public String toString() {
            return uri;
        }

    }

    @FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
    @AllArgsConstructor
    enum RegisteredRedirectUri {

        URI_WITHOUT_WILDCARDS(
                "http://domain.com",
                u -> u.http && u.domainParts == 2 && u.belongsToDomainDotCom
        ),
        URI_ALLOWING_SINGLE_PATH_SEGMENT(
                "http://domain.com/*",
                u -> u.http && u.domainParts == 2 && u.belongsToDomainDotCom && u.pathSegements <= 1
        ),
        URI_ALLOWING_MULTIPLE_PATH_SEGMENTS(
                "http://domain.com/**",
                u -> u.http && u.domainParts == 2 && u.belongsToDomainDotCom
        ),
        URI_ALLOWING_SUBDOMAINS(
                "http://*.domain.com/**",
                u -> u.http && u.domainParts >= 3 && u.belongsToDomainDotCom
        ),
        ;

        String uri;
        Predicate<RequestedRedirectUri> expectedMatcher;

        @Override
        public String toString() {
            return uri;
        }

        public boolean expectedMatch(RequestedRedirectUri requestedRedirectUri) {
            return expectedMatcher.test(requestedRedirectUri);
        }

    }

    @Nested
    @DisplayName("general matching")
    class GeneralMatching {

        @DisplayName("matching http://domain.com")
        @ParameterizedTest(name = "{index} matching {0} against http://domain.com")
        @EnumSource(RequestedRedirectUri.class)
        void matchAgainstUriWithoutWildcards(RequestedRedirectUri requestedRedirectUri) {
            match(requestedRedirectUri, URI_WITHOUT_WILDCARDS);
        }

        @DisplayName("matching http://domain.com/*")
        @ParameterizedTest(name = "{index} matching {0} against http://domain.com/*")
        @EnumSource(RequestedRedirectUri.class)
        void matchAgainstUriThatAllowsSinglePathSegment(RequestedRedirectUri requestedRedirectUri) {
            match(requestedRedirectUri, URI_ALLOWING_SINGLE_PATH_SEGMENT);
        }

        @DisplayName("matching http://domain.com/**")
        @ParameterizedTest(name = "{index} matching {0} against http://domain.com/**")
        @EnumSource(RequestedRedirectUri.class)
        void matchAgainstUriThatAllowsMulipltePathSegments(RequestedRedirectUri requestedRedirectUri) {
            match(requestedRedirectUri, URI_ALLOWING_MULTIPLE_PATH_SEGMENTS);
        }

        @DisplayName("matching http://*.domain.com/**")
        @ParameterizedTest(name = "{index} matching {0} against http://*.domain.com/**")
        @EnumSource(RequestedRedirectUri.class)
        void matchAgainstUriThatAllowsSubdomains(RequestedRedirectUri requestedRedirectUri) {
            match(requestedRedirectUri, URI_ALLOWING_SUBDOMAINS);
        }

        private void match(RequestedRedirectUri requestedRedirectUri, RegisteredRedirectUri registeredRedirectUri) {
            boolean expectedMatch = registeredRedirectUri.expectedMatch(requestedRedirectUri);

            boolean actualMatch = resolver.redirectMatches(requestedRedirectUri.uri, registeredRedirectUri.uri);

            if (expectedMatch) {
                assertTrue("expected " + requestedRedirectUri.uri + " to match " + registeredRedirectUri + " but did not match", actualMatch);
            } else {
                assertFalse("expected " + requestedRedirectUri.uri + " not to match " + registeredRedirectUri + " but did match", actualMatch);
            }
        }

        @DisplayName("should not be able to set subdomain matching")
        @Test
        void setMatchSubdomains_throwsException() {
            assertThrows(Exception.class, () -> resolver.setMatchSubdomains(true));
        }

    }


    @Nested
    @DisplayName("redirectMatches")
    class RedirectMatches {

        private final String requestedRedirectHttp = "http://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        private final String requestedRedirectHttps = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";

        @Test
        void trailingSlash() {
            final String clientRedirectUri = "http://subdomain.domain.com/";

            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void trailingPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleTrailingAsterisk() {
            final String clientRedirectUri = "http://subdomain.domain.com/*";

            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleTrailingAsterisk_withPath() {
            final String clientRedirectUri = "http://subdomain.domain.com/one*";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one-foo-bar", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three", clientRedirectUri));
        }

        @Test
        void singleAsterisk_insidePath() {
            String clientRedirectUri = "http://subdomain.domain.com/one/*/four";

            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/four", clientRedirectUri));
            assertTrue(resolver.redirectMatches("http://subdomain.domain.com/one/middle/four", clientRedirectUri));
            assertFalse(resolver.redirectMatches("http://subdomain.domain.com/one/two/three/four", clientRedirectUri));
        }

        @Test
        void matchesSchemeWildcard() {
            String clientRedirectUri = "http*://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesSchemeHttp() {
            String clientRedirectUri = "http://subdomain.domain.com/**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesSchemeHttps() {
            String clientRedirectUri = "https://subdomain.domain.com/**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesPathContainingAntPathMatcher() {
            String clientRedirectUri = "http*://subdomain.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));

            clientRedirectUri = "http*://subdomain.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
        }

        @Test
        void matchesHashFragments() {
            assertTrue(resolver.redirectMatches("http://uaa.com/#fragment", "http://uaa.com"));
        }

        @Test
        void redirectSubdomain() {
            String clientRedirectUri = "http*://*.domain.com/path1/path2**";

            assertTrue(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertTrue(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));

            clientRedirectUri = "http*://*.domain.com/path1/<invalid>**";

            assertFalse(resolver.redirectMatches(requestedRedirectHttps, clientRedirectUri));
            assertFalse(resolver.redirectMatches(requestedRedirectHttp, clientRedirectUri));
        }

        @Test
        void redirectSupportsMultipleSubdomainWildcards() {
            String clientRedirectUri = "http://*.*.domain.com/";
            assertTrue(resolver.redirectMatches("http://sub1.sub2.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSubdomain() {
            String clientRedirectUri = "http://*.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnMultilevelWildcardSubdomain() {
            String clientRedirectUri = "http://**.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnWildcardSuffixedSubdomain() {
            String clientRedirectUri = "http://sub*.example.com";
            assertFalse(resolver.redirectMatches("http://sub.other-domain.com?stuff.example.com", clientRedirectUri));
        }

        @Test
        void subdomainMatchingDoesNotBlowUpWhenRequestedRedirectIsShorterThanConfiguredRedirect() {
            String clientRedirectUri = "http://sub*.domain.com/";
            assertFalse(resolver.redirectMatches("http://domain.com/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingOnWildcardSubdomainWithBasicAuth() {
            String clientRedirectUri = "http://u:p@*.domain.com/";
            assertTrue(resolver.redirectMatches("http://u:p@sub.domain.com/", clientRedirectUri));
        }

        @Test
        void matchesHostsWithPort() {
            String clientRedirectUri = "http://*.domain.com:8080/";
            assertTrue(resolver.redirectMatches("http://any.domain.com:8080/", clientRedirectUri));
        }

        @Test
        void subdomainMatchingRejectsDomainRedirectOnAntPathVariableSubdomain() {
            String clientRedirectUri = "http://{foo:.*}.domain.com/";
            assertFalse(resolver.redirectMatches("http://other-domain.com?stuff.domain.com/", clientRedirectUri));
        }
    }


    private static Stream<Arguments> doubleDotTraversalArguments() {
        Iterable<String> requestedSuffix = Arrays.asList(
                "/../bar",
                "/%2e./bar",        //%2e is . url encoded
                "/%252e./bar",      //%25 is % url encoded
                "/%2525252e./bar",  //path may be url decoded multiple times when passing through web servers, proxies and browser
                "/%25252525252525252525252e./bar"
        );
        return generateDotTraversalArguments(requestedSuffix);
    }

    private static Stream<Arguments> singleDotTraversalArguments() {
        Iterable<String> requestedSuffix = Arrays.asList(
                "/./bar",
                "/%2e/bar",
                "/%252e/bar",
                "/%2525252e/bar"
        );
        return generateDotTraversalArguments(requestedSuffix);
    }

    private static Stream<Arguments> generateDotTraversalArguments(Iterable<String> requestedSuffix) {
        //registered redirect uri that contains a wildcard (*) is matched using an Ant path matcher
        //registered redirect uri that lacks a wildcard is matched using a different path matcher
        //hence both cases must be verified for ability to withstand integrity check bypass
        Iterable<String> registeredSuffix = Arrays.asList(
                "",
                "/**"
        );
        Stream.Builder<Arguments> builder = Stream.builder();
        requestedSuffix.forEach(
                req -> registeredSuffix.forEach(reg -> builder.accept(Arguments.of(req, reg)))
        );
        return builder.build();
    }

    @Nested
    @DisplayName("integrity check bypass")
    class IntegrityCheckBypass {

        private static final String REGISTERED_REDIRECT_URI = "http://example.com/foo";

        @ParameterizedTest(name = "{index} " + REGISTERED_REDIRECT_URI + "{0} shoud not match " + REGISTERED_REDIRECT_URI + "{1}")
        @MethodSource("org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests#doubleDotTraversalArguments")
        void doubleDotTraversal(String requestedSuffix, String registeredSuffix) {
            assertFalse(resolver.redirectMatches(REGISTERED_REDIRECT_URI + requestedSuffix, REGISTERED_REDIRECT_URI + registeredSuffix));
        }

        @ParameterizedTest(name = "{index} " + REGISTERED_REDIRECT_URI + "{0} shoud match " + REGISTERED_REDIRECT_URI + "{1}")
        @MethodSource("org.cloudfoundry.identity.uaa.oauth.AntPathRedirectResolverTests#singleDotTraversalArguments")
        void singleDotTraversal(String requestedSuffix, String registeredSuffix) {
            assertTrue(resolver.redirectMatches(REGISTERED_REDIRECT_URI + requestedSuffix, REGISTERED_REDIRECT_URI + registeredSuffix));
        }

    }

    @Nested
    @DisplayName("resolveRedirect")
    class ResolveRedirect {

        ClientDetails mockClientDetails;

        @BeforeEach
        void setUp() {
            mockClientDetails = mock(BaseClientDetails.class);
            when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        }

        @Test
        void clientMissingRedirectUri() {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(new HashSet<>());

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration is missing redirect_uri"));
        }

        @Test
        void clientWithInvalidRedirectUri() {
            final String invalidRedirectUri = "*, */*";
            mockRegisteredRedirectUri(invalidRedirectUri);

            RedirectMismatchException exception = assertThrows(RedirectMismatchException.class,
                    () -> resolver.resolveRedirect("http://somewhere.com", mockClientDetails));

            assertThat(exception.getMessage(), containsString("Client registration contains invalid redirect_uri"));
            assertThat(exception.getMessage(), containsString(invalidRedirectUri));
        }

        @Test
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

        @Test
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

        @Test
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

        @Test
        void testResolveClientWithUrlWhichHasWildcardsOrDoubleWildcardsInTheSubdomainAndDoesNotEndInSlash() {
            for (String uriPattern : newArrayList("http://*.uaa.com", "http://**.uaa.com")) {
                mockRegisteredRedirectUri(uriPattern);

                assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://user:pass@subdomain.uaa.com");

                assertResolveRedirectThrows________("http://subdomain.evil.com/domain.uaa.com");
                assertResolveRedirectThrows________("http://evil.com/domain.uaa.com");
                assertResolveRedirectThrows________("http://evil.com/uaa.com");

                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz/abc/1234");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com?foo=bar");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/xyz?foo=bar#fragment");

                assertResolveRedirectThrows________("http://subdomain.uaa.com:8080");
                assertResolveRedirectThrows________("http://uaa.com");
                assertResolveRedirectThrows________("http://subdomain.uaa.com#foo");
                assertResolveRedirectThrows________("http://subdomain.uaa.com/");
                assertResolveRedirectThrows________("https://subdomain.uaa.com");
            }

            for (String uriPattern : newArrayList("http://sub*.uaa.com", "http://sub**.uaa.com")) {
                mockRegisteredRedirectUri(uriPattern);

                assertResolveRedirectReturnsSameUrl("http://subdomain.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.uaa.com");
                assertResolveRedirectReturnsSameUrl("http://subdomain1.subdomain2.subdomain3.uaa.com");
                assertResolveRedirectThrows________("http://user:pass@subdomain.uaa.com");
            }
        }

        @Test
        void testResolveClientWithUrlWhichHasWildcardAsThePath() {
            mockRegisteredRedirectUri("http://uaa.com/*");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/#fragment");

            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com");
            assertResolveRedirectThrows________("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.uaa.com");
            assertResolveRedirectThrows________("https://uaa.com");
            assertResolveRedirectThrows________("https://uaa.com/");
        }

        @Test
        void testResolveClientWithUrlWhichHasWildcardInThePath() {
            mockRegisteredRedirectUri("http://uaa.com/a/*/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b#fragment");
            assertResolveRedirectThrows________("http://uaa.com/a/b");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/xyz");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com:8080/a/zzz/b");
            assertResolveRedirectThrows________("https://uaa.com/a/zzz/b");

            mockRegisteredRedirectUri("http://uaa.com/a/z*z/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxxxxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/z?foo=baz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b#foo");

            mockRegisteredRedirectUri("http://uaa.com/a/z*z/b*c");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/bc");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/bxc");
            assertResolveRedirectThrows________("http://uaa.com/a/zz/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/bxc?foo=bar");

            mockRegisteredRedirectUri("http://uaa.com/a/b*");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/bzzz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b#foo");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c?foo=bar");
        }

        @Test
        void testResolveClientWithUrlWhichHasDoubleWildcardAsThePath() {
            mockRegisteredRedirectUri("http://uaa.com/**");

            assertResolveRedirectReturnsSameUrl("http://uaa.com");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234?foo=bar#fragment");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/xyz/abc/1234#fragment");

            assertResolveRedirectThrows________("http://user:pass@uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/");
            assertResolveRedirectThrows________("http://subdomain.uaa.com");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/");
            assertResolveRedirectThrows________("http://uaa.com:8080");
            assertResolveRedirectThrows________("http://uaa.com:8080/");
            assertResolveRedirectThrows________("http://uaa.com?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com#foo");
            assertResolveRedirectThrows________("https://uaa.com");
            assertResolveRedirectThrows________("https://uaa.com/");
        }

        @Test
        void testResolveClientWithUrlWhichHasDoubleWildcardInThePath() {
            // note that this case works as you might expect, but the other cases below work as if you had used a single '*'
            mockRegisteredRedirectUri("http://uaa.com/a/**/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zzz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/c/d/e/f/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zzz/b#fragment");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/xyz");
            assertResolveRedirectThrows________("http://uaa.com");
            assertResolveRedirectThrows________("http://user:pass@uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b");
            assertResolveRedirectThrows________("http://uaa.com:8080/a/zzz/b");
            assertResolveRedirectThrows________("https://uaa.com/a/zzz/b");

            mockRegisteredRedirectUri("http://uaa.com/a/z**z/b");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxxxxz/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/z?foo=baz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/x/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxx/xx/xxz/b");
            assertResolveRedirectThrows________("http://uaa.com/a/z/z/b");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b?foo=bar");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/b#foo");

            mockRegisteredRedirectUri("http://uaa.com/a/z**z/b**c");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zz/bc");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/zxz/bxc");
            assertResolveRedirectThrows________("http://uaa.com/a/z/x/z/b/x/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zz/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/zxz/bxc?foo=bar");

            mockRegisteredRedirectUri("http://uaa.com/a/b**");

            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/bzzz");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b?foo=bar");
            assertResolveRedirectReturnsSameUrl("http://uaa.com/a/b#foo");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c");
            assertResolveRedirectThrows________("http://uaa.com/a/b/c?foo=bar");
        }

        private void mockRegisteredRedirectUri(String allowedRedirectUri) {
            when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton(allowedRedirectUri));
        }

        private void assertResolveRedirectReturnsSameUrl(String requestedRedirect) {
            assertThat(resolver.resolveRedirect(requestedRedirect, mockClientDetails), equalTo(requestedRedirect));
        }

        private void assertResolveRedirectThrows________(String requestedRedirect) {
            assertThrows(RedirectMismatchException.class, () -> resolver.resolveRedirect(requestedRedirect, mockClientDetails));
        }

    }

}
