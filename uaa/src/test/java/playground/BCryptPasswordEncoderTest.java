package playground;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by taitz.
 */
class BCryptPasswordEncoderTest {

    private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder();

    @ParameterizedTest
    @ValueSource(strings = {
            "$2a$10$Aa4jgeMW.YEymBi3B6GznOgg6pWFKP9kEbexoH8fXWcgw2dakRhtm",
            "$2a$10$ZpsecOlJubCVDgdCMdzZDOFHqT9D.mGrkayM8fXTdBWoAaV73qaNC",
    })
    void verifyMatch(String encodedPassword) {
        boolean matches = ENCODER.matches("", encodedPassword);
        assertTrue(matches, "expected match but did not");
    }

}
