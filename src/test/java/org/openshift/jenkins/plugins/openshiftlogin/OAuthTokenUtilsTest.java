package org.openshift.jenkins.plugins.openshiftlogin;
import static junit.framework.TestCase.assertEquals;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
public class OAuthTokenUtilsTest {
    @Test
    public void testTokenToObjectName() throws NoSuchAlgorithmException {
        String input = "sha256~FS-hBG4Sm1gh5Eb0po5jUPoMpVfmLa_6wNqamsAA8bM";
        String expected = "sha256~JzvK219R86Q30jidBjO7CYMcYV5JaRVFPS6uWY2KNZo";
        assertEquals(expected, OpenShiftOAuth2SecurityRealm.tokenToObjectName(input));
    }
    @Test
    public void testTokenToObjectNameWithoutPrefix() throws NoSuchAlgorithmException {
        String input = "HQlI91PGxyt39s7xcMQ8EteviaRUKx4eGBYKwNPnab0";
        String expected = "HQlI91PGxyt39s7xcMQ8EteviaRUKx4eGBYKwNPnab0";
        assertEquals(expected, OpenShiftOAuth2SecurityRealm.tokenToObjectName(input));
    }
    @Test
    public void testTokenToObjectNameWitNullInput() throws NoSuchAlgorithmException {
        String input = null;
        String expected = "";
        assertEquals(expected, OpenShiftOAuth2SecurityRealm.tokenToObjectName(input));
    }
    @Test
    public void testTokenToObjectNameWithEmptyStringInput() throws NoSuchAlgorithmException {
        String input = "";
        String expected = "";
        assertEquals(expected, OpenShiftOAuth2SecurityRealm.tokenToObjectName(input));
    }
}