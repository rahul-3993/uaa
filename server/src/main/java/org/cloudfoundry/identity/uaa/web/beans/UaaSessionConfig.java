package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

public class UaaSessionConfig {

    @Bean
    public CookieSerializer uaaCookieSerializer(
            final @Value("${servlet.session-cookie.max-age:-1}") int cookieMaxAge
    ) {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setSameSite(null);
        cookieSerializer.setCookieMaxAge(cookieMaxAge);
        cookieSerializer.setCookieName("JSESSIONID");

        return cookieSerializer;
    }
}
