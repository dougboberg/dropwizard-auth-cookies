package com.ikonetics.dropwizard.authcookie;

import java.security.Principal;
import java.util.Optional;
import jakarta.ws.rs.core.SecurityContext;


public class AuthCookieSecurityContext implements SecurityContext {
    private final AuthCookiePrincipal principal;
    private final boolean secure;

    public AuthCookieSecurityContext(AuthCookiePrincipal principal, boolean secure) {
        this.principal = principal;
        this.secure = secure;
    }


    @Override
    public Principal getUserPrincipal() {
        return principal;
    }


    @Override
    public boolean isUserInRole(String role) {
        return Optional.ofNullable(principal).map(s -> s.isInRole(role)).orElse(false);
    }


    @Override
    public boolean isSecure() {
        return secure;
    }


    @Override
    public String getAuthenticationScheme() {
        return "AUTH_COOKIE";
    }

}
