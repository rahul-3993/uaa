/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;

import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.io.IOException;
import java.util.Arrays;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;

import static javax.ws.rs.HttpMethod.GET;
import static javax.ws.rs.HttpMethod.POST;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;
import static org.springframework.mock.web.MockHttpSession.SESSION_COOKIE_NAME;

public class CookieBasedCsrfTokenRepositoryTests {

    @Test
    public void testGetHeader_and_Parameter_Name() throws Exception {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        assertEquals(DEFAULT_CSRF_COOKIE_NAME, repo.getParameterName());
        repo.setParameterName("testcookie");
        assertEquals("testcookie", repo.getParameterName());

        assertEquals(DEFAULT_CSRF_HEADER_NAME, repo.getHeaderName());
        repo.setHeaderName("testheader");
        assertEquals("testheader", repo.getHeaderName());

        repo.setGenerator(new RandomValueStringGenerator() {
            @Override
            public String generate() {
                return "token-id";
            }
        });

        CsrfToken token = repo.generateToken(new MockHttpServletRequest());
        assertEquals("testheader", token.getHeaderName());
        assertEquals("testcookie", token.getParameterName());
        assertEquals("token-id", token.getToken());
    }



    @Test
    public void testSave_and_Load_Token() throws Exception {
        for (String contextPath : Arrays.asList("", "/uaa")) {
            String expectedCookiePath = contextPath + "/";
            CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            request.setPathInfo("/login/somepath");
            request.setContextPath(contextPath);
            CsrfToken token = repo.generateToken(request);
            assertTrue("The token is at least 22 characters long.", token.getToken().length() >= 22);
            repo.saveToken(token, request, response);

            Cookie cookie = response.getCookie(token.getParameterName());
            assertNotNull(cookie);
            assertEquals(token.getToken(), cookie.getValue());
            assertEquals(true, cookie.isHttpOnly());
            assertEquals(repo.getCookieMaxAge(), cookie.getMaxAge());
            assertNotNull(cookie.getPath());
            assertEquals(expectedCookiePath, cookie.getPath());

            request.setCookies(cookie);

            CsrfToken saved = repo.loadToken(request);
            assertEquals(token.getToken(), saved.getToken());
            assertEquals(token.getHeaderName(), saved.getHeaderName());
            assertEquals(token.getParameterName(), saved.getParameterName());
        }
    }

    @Test
    public void testLoad_Token_During_Get() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(HttpMethod.GET.name());
        request.setCookies(new Cookie(DEFAULT_CSRF_COOKIE_NAME, "should-be-removed"));

        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();

        CsrfToken csrfToken = repo.loadToken(request);
        assertThat(csrfToken, nullValue());
    }

    @Test
    public void csrfCookie_alwaysHttpOnly() throws Exception {
        Cookie cookie = getCookie(false);
        assertTrue(cookie.isHttpOnly());
        assertFalse(cookie.getSecure());
    }

    @Test
    public void csrfCookie_SecureIfHttpsRequired() throws Exception {
        Cookie cookie = getCookie(true);
        assertTrue(cookie.getSecure());
    }

    @Test
    public void csrfCookie_SecureIfRequestIsOverHttps() throws Exception {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("https");
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(request);
        repo.saveToken(token, request, response);
        Cookie cookie = response.getCookie(token.getParameterName());
        assertTrue(cookie.getSecure());
    }

    private Cookie getCookie(boolean isSecure) {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSecure(isSecure);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(request);
        repo.saveToken(token, request, response);

        return response.getCookie(token.getParameterName());
    }
    
    @Test
    public void doFilterInternal_postCsrfTokenMatchesGetCsrfToken_filterChainContinues() throws ServletException, IOException {
        CookieBasedCsrfTokenRepository repository = new CookieBasedCsrfTokenRepository();
        CsrfFilter csrfFilter = new CsrfFilter(repository);
        String parameterName = repository.getParameterName();
        
        
        MockHttpServletRequest getRequest = new MockHttpServletRequest(GET, "/bar");
        MockHttpServletResponse getResponse = new MockHttpServletResponse();
        MockFilterChain getFilterChain = new MockFilterChain();

        csrfFilter.doFilter(getRequest, getResponse, getFilterChain);

        MockHttpServletRequest postRequest = new MockHttpServletRequest(POST, "/foo");
        postRequest.setParameter(parameterName, "joeblogs");
        MockHttpServletResponse postResponse = new MockHttpServletResponse();
        MockFilterChain postFilterChain = new MockFilterChain();
        
        csrfFilter.doFilter(postRequest, postResponse, postFilterChain);
        
        assertNotNull("filter chain should have been called, but was not", postFilterChain.getRequest()); 
    }
    
    @Test
    public void doFilterInternal_postCsrfTokenDoesNotMatchGetCsrfToken_filterChainTerminates() {
        //todo: re-use code or parameterize
    }
    
    @Test
    public void doFilterInternal_postCsrfTokenMatchesCookieButIsFabricated_filterChainTerminates() {
        
    }

    @Test
    public void loadToken_correctTokenLoadedForEachSession() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();

        String session0 = "alex";
        String session1 = "bob";
        String session2 = "charles";
        
        DefaultCsrfToken token1 = createToken("foo1");
        DefaultCsrfToken token2 = createToken("foo2");
        DefaultCsrfToken token3 = createToken("foo3");

        MockHttpServletRequest saveRequest1 = new MockHttpServletRequest();
        MockHttpServletRequest saveRequest2 = new MockHttpServletRequest();
        MockHttpServletRequest saveRequest3 = new MockHttpServletRequest();

        saveRequest1.setParameter(SESSION_COOKIE_NAME, session1);
        saveRequest2.setParameter(SESSION_COOKIE_NAME, session2);
        saveRequest3.setParameter(SESSION_COOKIE_NAME, session2);

        MockHttpServletResponse response = new MockHttpServletResponse();

        MockHttpServletRequest loadRequest0 = new MockHttpServletRequest();
        MockHttpServletRequest loadRequest1 = new MockHttpServletRequest();
        MockHttpServletRequest loadRequest2 = new MockHttpServletRequest();

        loadRequest0.setParameter(SESSION_COOKIE_NAME, session0);
        loadRequest1.setParameter(SESSION_COOKIE_NAME, session1);
        loadRequest2.setParameter(SESSION_COOKIE_NAME, session2);
        
        repo.saveToken(token1, saveRequest1, response);
        repo.saveToken(token2, saveRequest2, response);
        repo.saveToken(token3, saveRequest3, response);

        CsrfToken actualToken0 = repo.loadToken(loadRequest0); //alex has placed 0 GET requests
        assertNull("expected no token but found one", actualToken0);
        
        CsrfToken actualToken1 = repo.loadToken(loadRequest1); //bob has placed 1 GET request
        assertEquals(token1.getToken(), actualToken1.getToken());

        CsrfToken actualToken2 = repo.loadToken(loadRequest2); //charles has placed 2 GET requests, expect more recent
        assertEquals(token3.getToken(), actualToken2.getToken());
    }

    private DefaultCsrfToken createToken(String value) {
        return new DefaultCsrfToken(DEFAULT_CSRF_HEADER_NAME, DEFAULT_CSRF_COOKIE_NAME, value);
    }

}
