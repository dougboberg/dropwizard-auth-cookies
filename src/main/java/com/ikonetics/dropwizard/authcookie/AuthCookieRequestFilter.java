package com.ikonetics.dropwizard.authcookie;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.Authorizer;
import io.fusionauth.jwt.InvalidJWTSignatureException;
import io.fusionauth.jwt.JWTExpiredException;
import io.fusionauth.jwt.JWTUnavailableForProcessingException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import jakarta.annotation.Priority;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;


@Priority(Priorities.AUTHENTICATION)
public class AuthCookieRequestFilter<P extends AuthCookiePrincipal> extends AuthFilter<Cookie, P> {

    static final Logger LOG = LoggerFactory.getLogger(AuthCookieRequestFilter.class);

    // General config
    final Class<P> principalClass; // class to build and return
    final Level logAtLevel;

    // Cookie setup
    final String cookieName;

    // JWT setup
    final Verifier jwtVerifier;
    final String jwtIssuer;

    // private internals; not configurable.
    final String roleKey;

    public AuthCookieRequestFilter(Class<P> principalClass, Level logAtLevel, String cookieName, Verifier jwtVerifier, String jwtIssuer, String roleKey) {
        this.principalClass = principalClass;
        this.logAtLevel = logAtLevel;
        this.cookieName = cookieName;
        this.jwtVerifier = jwtVerifier;
        this.jwtIssuer = jwtIssuer;
        this.roleKey = roleKey;

        // tne authorizer utility checks for access to specific role
        this.authorizer = (Authorizer<P>) (principal, role, requestContext) -> principal.isInRole(role);

        // the authenticator utility checks for for general authentication
        this.authenticator = (Authenticator<Cookie, P>) credentials -> {
            if (credentials == null || StringUtils.isBlank(credentials.getValue())) {
                LOG.atLevel(this.logAtLevel).log("Invalid cookie credentials: {}", credentials);
                return Optional.empty();
            }

            // try to decode and read base values from the JWT or return an empty() result.
            JWT jwt;
            try {
                String token = credentials.getValue();
                LOG.atLevel(this.logAtLevel).log("Credentials token: {}", token);
                jwt = JWT.getDecoder().decode(token, jwtVerifier);

            } catch (JWTUnavailableForProcessingException | JWTExpiredException | InvalidJWTSignatureException ex) {
                // library throws errors for notBefore, expired, and if the signing key changes; these are not 'errors' for us.
                LOG.atLevel(this.logAtLevel).log("Dead session credentials: {}", String.valueOf(ex));
                return Optional.empty();
            }

            try {
                // if bundle configuration values are configured / not blank, check the token against them
                if (StringUtils.isNotBlank(jwtIssuer) && !Objects.equals(jwtIssuer, jwt.issuer)) {
                    LOG.atLevel(this.logAtLevel).log("Dead session becacuse of unrecognized credential issuer: {}", jwt.issuer);
                    return Optional.empty();
                }

                // Principal name is in the JWT Subject. Avoid passing null Name for the constructor below.
                String name = StringUtils.trimToEmpty(jwt.subject);

                // convert JWT list to Principal roles Set. Avoid passing null Roles in the constructor below.
                Set<String> roles = new HashSet<>();
                List<Object> list = jwt.getList(roleKey);
                if (list != null) {
                    for (Object obj : list) {
                        roles.add(String.valueOf(obj));
                    }
                }

                // the JWT claims map. Avoid null and default to a new Map
                Map<String, Object> claims = Optional.ofNullable(jwt.getOtherClaims()).orElse(new HashMap<>());

                // cleanup by removing the Roles from the Claims. We injected them during Response and already read them back out above.
                claims.remove(roleKey);

                // the returned Principal must have its own 1-argument constructor (the Bundle verified this at setup)
                Constructor<P> principalConstructor = principalClass.getConstructor(String.class);

                // create and return the Principal by passing the Name to the constructor
                P principal = principalConstructor.newInstance(name);

                // set the Roles and Claims
                principal.setRoles(roles);
                principal.setClaims(claims);

                // set internal JWT values. they might be useful to read
                principal.storeJwtInternals(buildInternalsMap(jwt));

                return Optional.of(principal);

            } catch (Exception ex) {
                // an actual error we care about
                LOG.atLevel(this.logAtLevel).log("Rethrowing authenticator exception: {}", String.valueOf(ex));
                throw new AuthenticationException(ex);
            }
        };

    }


    @Override
    public void filter(ContainerRequestContext request) {
        Cookie cookie = request.getCookies().get(cookieName);
        try {
            final Optional<P> optional = authenticator.authenticate(cookie);
            if (optional.isPresent()) {
                optional.get().addInContext(request);
                return;
            }

        } catch (AuthenticationException ex) {
            throw new InternalServerErrorException(ex);
        }

        // did not return as authenticated above
        LOG.atLevel(this.logAtLevel).log("Throwing authentication failure and passing on to super unauthorizedHandler.buildResponse()");
        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }


    Map<String, String> buildInternalsMap(JWT jwt) {
        Map<String, String> map = new HashMap<>();
        // the library stores these as dates, we want seconds as Strings
        if (jwt.expiration != null) {
            map.put("exp", String.valueOf(jwt.expiration.toEpochSecond()));
        }
        if (jwt.issuedAt != null) {
            map.put("iat", String.valueOf(jwt.issuedAt.toEpochSecond()));
        }
        if (jwt.notBefore != null) {
            map.put("nbf", String.valueOf(jwt.notBefore.toEpochSecond()));
        }

        // these objects we stringify (they're probably strings anyway)
        if (jwt.audience != null) {
            map.put("aud", String.valueOf(jwt.audience));
        }
        if (jwt.issuer != null) {
            map.put("iss", String.valueOf(jwt.issuer));
        }
        if (jwt.subject != null) {
            map.put("sub", String.valueOf(jwt.subject));
        }
        if (jwt.uniqueId != null) {
            map.put("jti", String.valueOf(jwt.uniqueId));
        }
        return map;
    }
}
