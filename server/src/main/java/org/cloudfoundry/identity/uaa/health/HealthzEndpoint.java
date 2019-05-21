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

package org.cloudfoundry.identity.uaa.health;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.jdbc.datasource.lookup.DataSourceLookupFailureException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Simple controller for monitoring health of the application including connectivity to its database. It returns
 * "down" in a response body and a 503 if unable to connect to the database. It also registers a shutdown hook and
 * returns "stopping" and a 503 when the process is shutting down. Otherwise, it returns "ok".
 *
 */
@Controller
public class HealthzEndpoint {
    public enum HealthCode {
        ERROR, AVAILABLE, UNAVAILABLE, UNREACHABLE, MISCONFIGURATION
    }

    public static final String DOWN = "down\n";
    public static final String OK = "ok\n";
    public static final String STOPPING = "stopping\n";

    private static Log logger = LogFactory.getLog(HealthzEndpoint.class);

    private volatile boolean stopping = false;
    private final Thread shutdownhook;
    private final long sleepTime;

    private final String ERROR_MESSAGE_FORMAT = "Unexpected exception while checking UAA database status: {}";
    private final UaaMonitoringRepository uaaMonitoringRepository;

    public HealthzEndpoint(final long sleepTime, @Autowired final UaaMonitoringRepository uaaMonitoringRepository) {
        this.uaaMonitoringRepository = uaaMonitoringRepository;

        this.sleepTime = sleepTime;
        shutdownhook = new Thread(() -> {
            stopping = true;
            logger.warn("Shutdown hook received, future requests to this endpoint will return 503");
            try {
                if (sleepTime > 0) {
                    logger.debug("Healthz is sleeping shutdown thread for " + sleepTime + " ms.");
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                logger.warn("Shutdown sleep interrupted.", e);
            }
        });
        Runtime.getRuntime().addShutdownHook(shutdownhook);
    }

    @RequestMapping("/healthz")
    @ResponseBody
    public String getHealthz(final HttpServletResponse response) throws Exception {
        if (stopping) {
            logger.debug("Received /healthz request during shutdown. Returning 'stopping'");
            response.setStatus(503);
            return STOPPING;
        } else if (checkDbStatus() != HealthCode.AVAILABLE) {
            response.setStatus(503);
            return DOWN;
        } else {
            return OK;
        }
    }

    public long getSleepTime() {
        return sleepTime;
    }

    private HealthCode checkDbStatus() {
        HealthCode healthCode;

        logger.debug("Received /healthz request. Checking UAA database status");
        try {
            this.uaaMonitoringRepository.queryIdentityZoneTable();
            healthCode = HealthCode.AVAILABLE;
        } catch (TransientDataAccessResourceException | QueryTimeoutException e) {
            logger.error(ERROR_MESSAGE_FORMAT, e);
            healthCode = HealthCode.UNAVAILABLE;
        } catch (DataSourceLookupFailureException e) {
            logger.error(ERROR_MESSAGE_FORMAT, e);
            healthCode = HealthCode.UNREACHABLE;
        } catch (PermissionDeniedDataAccessException e) {
            logger.error(ERROR_MESSAGE_FORMAT, e);
            healthCode = HealthCode.MISCONFIGURATION;
        } catch (Exception e) {
            logger.error(ERROR_MESSAGE_FORMAT, e);
            healthCode = HealthCode.ERROR;
        }

        return healthCode;
    }
}