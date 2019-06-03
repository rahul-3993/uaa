package org.cloudfoundry.identity.uaa.health;

import java.util.List;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class UaaMonitoringRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(UaaMonitoringRepository.class);

    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setDataSource(final DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public void queryIdentityZoneTable() {
        String query = "select id from identity_zone limit 1";
        List<String> queryResults = this.jdbcTemplate.query(query, (rs, rowNum) -> rs.getString(1));
        LOGGER.debug("Successfully executed health check query on UAA database: {} (result set size: {})", query,
                queryResults.size());
    }
}
