package com.ikonetics.dropwizard.authcookie;

import java.io.IOException;
import java.security.Principal;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;


public class AuthCookieResponseFilter<P extends AuthCookiePrincipal> implements ContainerResponseFilter {

    // General config
    final Class<P> principalClass; // class to build and return
    final long sessionMinutes;
    final boolean systemLogging;

    // Cookie setup
    final String cookieName;
    final String cookieDomain;
    final String cookiePath;
    final boolean cookieSecure;
    final boolean cookieHttpOnly;

    // JWT setup
    final Signer jwtSigner;
    final String jwtIssuer;

    // private internals; not configurable.
    final String roleKey;

    public AuthCookieResponseFilter(Class<P> principalClass, long sessionMinutes, boolean systemLogging, String cookieName, String cookieDomain,
            String cookiePath, boolean cookieSecure, boolean cookieHttpOnly, Signer jwtSigner, String jwtIssuer, String roleKey) {
        this.principalClass = principalClass;
        this.cookieName = cookieName;
        this.cookieDomain = cookieDomain;
        this.cookiePath = cookiePath;
        this.cookieSecure = cookieSecure;
        this.cookieHttpOnly = cookieHttpOnly;
        this.jwtSigner = jwtSigner;
        this.jwtIssuer = jwtIssuer;
        this.sessionMinutes = sessionMinutes;
        this.systemLogging = systemLogging;

        this.roleKey = roleKey;
    }


    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        if (!(request.getSecurityContext() instanceof AuthCookieSecurityContext)) {
            return;
        }

        Principal principal = request.getSecurityContext().getUserPrincipal();
        if (principalClass.isInstance(principal)) {
            AuthCookiePrincipal cookiePrincipal = (AuthCookiePrincipal) principal;

            // add Principal name as the JWT subject
            JWT jwt = new JWT();
            jwt = jwt.setSubject(cookiePrincipal.getName());

            // add Principal Roles with a known named key
            Set<String> roles = cookiePrincipal.getRoles();
            if (roles != null) {
                jwt.addClaim(this.roleKey, roles);
            }

            // put custom claim values into JWT standard Claims payload. There is no setter available so add directly to the jwt 'otherClaims' property.
            Map<String, Object> claims = cookiePrincipal.getClaims();
            if (claims != null) {
                jwt.otherClaims.putAll(claims);
            }

            // JWT start and expiration constraints
            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
            ZonedDateTime expiration = now.plus(sessionMinutes, ChronoUnit.MINUTES);
            jwt = jwt.setIssuedAt(now).setNotBefore(now).setExpiration(expiration);

            // add these optional values only if they are not blank
            if (StringUtils.isNotBlank(jwtIssuer)) {
                jwt = jwt.setIssuer(jwtIssuer);
            }

            // Sign and encode the JWT to a string representation
            String token = JWT.getEncoder().encode(jwt, jwtSigner);

            if (this.systemLogging) {
                // if you're here debugging something, you can decode the token at https://jwt.io
                System.out.println(this + " Add session cookie [" + cookieName + "] with value token: " + token);
            }

            // set the token as the cookie value and -1 maxAge 'session' cookie that expires at browser close; probably irrelevant because of the JWT expiration
            Cookie cookie = new NewCookie(cookieName, token, cookiePath, cookieDomain, NewCookie.DEFAULT_VERSION, null, -1, null, cookieSecure, cookieHttpOnly);
            response.getHeaders().add(HttpHeaders.SET_COOKIE, cookie);

        } else if (request.getCookies().containsKey(cookieName)) {
            if (this.systemLogging) {
                System.out.println(this + " Delete dead cookie [" + cookieName + "] using a maxAge of 0 and null value");
            }
            Cookie cookie = new NewCookie(cookieName, null, cookiePath, cookieDomain, NewCookie.DEFAULT_VERSION, null, 0, null, cookieSecure, cookieHttpOnly);
            response.getHeaders().add(HttpHeaders.SET_COOKIE, cookie);
        }

    }

}
