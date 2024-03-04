package com.ikonetics.dropwizard.authcookie;

import java.io.IOException;
import java.security.Principal;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.http.CookieCompliance;
import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.http.HttpCookie.SameSite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;


public class AuthCookieResponseFilter<P extends AuthCookiePrincipal> implements ContainerResponseFilter {

    static final Logger LOG = LoggerFactory.getLogger(AuthCookieResponseFilter.class);

    // General config
    final Class<P> principalClass; // class to build and return
    final Level logAtLevel; // defaults to Trace
    final long sessionMinutes;

    // Cookie setup
    final String cookieName;
    final String cookieDomain;
    final String cookiePath;
    final boolean cookieSecure;
    final boolean cookieHttpOnly;
    final SameSite cookieSameSite;
    final boolean cookiePartitioned;
    final CookieCompliance cookieCompliance;

    // JWT setup
    final Signer jwtSigner;
    final String jwtIssuer;

    // private internals; not configurable.
    final String roleKey;

    public AuthCookieResponseFilter(Class<P> principalClass, Level logAtLevel, long sessionMinutes, String cookieName, String cookieDomain, String cookiePath,
            boolean cookieSecure, boolean cookieHttpOnly, SameSite cookieSameSite, boolean cookiePartitioned, CookieCompliance cookieCompliance,
            Signer jwtSigner, String jwtIssuer, String roleKey) {
        this.principalClass = principalClass;
        this.logAtLevel = logAtLevel;
        this.sessionMinutes = sessionMinutes;
        this.cookieName = cookieName;
        this.cookieDomain = cookieDomain;
        this.cookiePath = cookiePath;
        this.cookieSecure = cookieSecure;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSameSite = cookieSameSite;
        this.cookiePartitioned = cookiePartitioned;
        this.cookieCompliance = cookieCompliance;
        this.jwtSigner = jwtSigner;
        this.jwtIssuer = jwtIssuer;
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

            // if you're here debugging something, you can decode the token at https://jwt.io
            LOG.atLevel(this.logAtLevel).log("Add session cookie [{}] with value token: {}", cookieName, token);

            // set the token as the cookie value and -1 maxAge 'session' cookie that expires at browser close; probably irrelevant because of the JWT expiration
            String cookieString = makeCookie(token, -1);
            response.getHeaders().add(HttpHeaders.SET_COOKIE, cookieString);

        } else if (request.getCookies().containsKey(cookieName)) {
            LOG.atLevel(this.logAtLevel).log("Delete dead session cookie [{}] using a maxAge of 0 and null value", cookieName);

            String cookieString = makeCookie(null, 0);
            response.getHeaders().add(HttpHeaders.SET_COOKIE, cookieString);
        }
    }


    String makeCookie(String value, int maxAge) {
        HttpCookie httpCookie = new HttpCookie(cookieName, value, cookieDomain, cookiePath, maxAge, cookieHttpOnly, cookieSecure, null, 1, cookieSameSite,
                cookiePartitioned);
        // return the 'SetCookie' string value which is formatted for the compliance rules. do not use toString() or asString()
        return httpCookie.getSetCookie(cookieCompliance);
    }

}
