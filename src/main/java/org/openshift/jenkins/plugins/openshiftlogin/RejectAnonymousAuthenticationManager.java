package org.openshift.jenkins.plugins.openshiftlogin;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;

public final class RejectAnonymousAuthenticationManager implements AuthenticationManager {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (authentication instanceof AnonymousAuthenticationToken)
                return authentication;
            throw new BadCredentialsException("Unexpected authentication type: " + authentication);
        }
    }