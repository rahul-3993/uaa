/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.Collection;

import org.cloudfoundry.identity.uaa.health.HealthzEndpoint;
import org.cloudfoundry.identity.uaa.health.UaaMonitoringRepository;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mockito;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.jdbc.datasource.lookup.DataSourceLookupFailureException;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(Enclosed.class)
public abstract class HealthzEndpointTests {

    private static final int SLEEP_UPON_SHUTDOWN = 150;
    private static final MockHttpServletResponse RESPONSE = new MockHttpServletResponse();

    @RunWith(Parameterized.class)
    public static class ParameterizedHealthzEndpointTests {
        @Parameters
        public static Collection<Object[]> statuses() {
            return Arrays.asList(new Object[][] { { mockDbWithUp(), HealthzEndpoint.OK },
                    { mockDbWithException(new TransientDataAccessResourceException("")), HealthzEndpoint.DOWN },
                    { mockDbWithException(new DataSourceLookupFailureException("")), HealthzEndpoint.DOWN },
                    { mockDbWithException(new PermissionDeniedDataAccessException("", null)), HealthzEndpoint.DOWN },
                    { mockDbWithException(new ConcurrencyFailureException("")), HealthzEndpoint.DOWN } });
        }

        private UaaMonitoringRepository uaaMonitoringRepository;
        private String status;

        public ParameterizedHealthzEndpointTests(final UaaMonitoringRepository uaaMonitoringRepository,
                final String status) {
            this.uaaMonitoringRepository = uaaMonitoringRepository;
            this.status = status;
        }

        @Test
        public void testGetHealthz() throws Exception {
            HealthzEndpoint endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, uaaMonitoringRepository);
            assertEquals(status, endpoint.getHealthz(RESPONSE));
        }
    }

    public static class NotParameterizedHealthzEndpointTests {

        private HealthzEndpoint endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, mockDbWithUp());

        @Test
        public void shutdown_sends_stopping() throws Exception {
            long now = System.currentTimeMillis();
            assertEquals(HealthzEndpoint.OK, endpoint.getHealthz(RESPONSE));
            runShutdownHook();
            assertEquals(HealthzEndpoint.STOPPING, endpoint.getHealthz(RESPONSE));
            assertEquals(503, RESPONSE.getStatus());
            long after = System.currentTimeMillis();
            assertThat(after, Matchers.greaterThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN));
        }

        @Test
        public void shutdown_without_sleep() throws Exception {
            long now = System.currentTimeMillis();
            endpoint = new HealthzEndpoint(-1, mockDbWithUp());
            runShutdownHook();
            assertEquals(HealthzEndpoint.STOPPING, endpoint.getHealthz(RESPONSE));
            assertEquals(503, RESPONSE.getStatus());
            long after = System.currentTimeMillis();
            assertThat(after, Matchers.lessThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN));
        }

        protected void runShutdownHook() {
            Object t = ReflectionTestUtils.getField(endpoint, "shutdownhook");
            ReflectionTestUtils.invokeMethod(t, "run");
            ReflectionTestUtils.invokeMethod(t, "join");
        }
    }

    private static UaaMonitoringRepository mockDbWithUp() {
        UaaMonitoringRepository uaaMonitoringRepository = Mockito.mock(UaaMonitoringRepository.class);
        Mockito.doNothing().when(uaaMonitoringRepository).queryIdentityZoneTable();
        return uaaMonitoringRepository;
    }

    private static UaaMonitoringRepository mockDbWithException(final Exception e) {
        UaaMonitoringRepository uaaMonitoringRepository = Mockito.mock(UaaMonitoringRepository.class);
        Mockito.doThrow(e).when(uaaMonitoringRepository).queryIdentityZoneTable();
        return uaaMonitoringRepository;
    }
}
