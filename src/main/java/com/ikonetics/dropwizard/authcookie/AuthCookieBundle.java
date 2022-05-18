package com.ikonetics.dropwizard.authcookie;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;


public class AuthCookieBundle<C extends Configuration, P extends CookiePrincipal> implements ConfiguredBundle<C> {

    // General config
    final Class<P> principalClass; // class to build and return
    final long sessionMinutes;
    final boolean systemLogging; // debug helper

    // Cookie config
    final String cookieName;
    final String cookieDomain;
    final String cookiePath;
    final boolean cookieSecure;
    final boolean cookieHttpOnly;

    // JWT config
    final Signer jwtSigner;
    final Verifier jwtVerifier;
    final String jwtIssuer;
    final String jwtRolesKey;

    // Use the Builder to create the Bundle. Configuration validation is done in the Builder.build(). Most things you should leave as default.
    //
    AuthCookieBundle(Builder<C, P> builder) {
        this.principalClass = builder.principalClass;
        this.sessionMinutes = builder.sessionMinutes;
        this.cookieName = builder.cookieName;
        this.cookieDomain = builder.cookieDomain;
        this.cookiePath = builder.cookiePath;
        this.cookieSecure = builder.cookieSecure;
        this.cookieHttpOnly = builder.cookieHttpOnly;
        this.jwtSigner = builder.jwtSigner;
        this.jwtVerifier = builder.jwtVerifier;
        this.jwtIssuer = builder.jwtIssuer;
        this.jwtRolesKey = builder.jwtRolesKey;
        this.systemLogging = builder.systemLogging;
    }


    // Dropwizard bundle setup
    @Override
    public void run(C configuration, Environment env) throws Exception {
        AuthCookieRequestFilter<P> requestFilter = new AuthCookieRequestFilter<>(principalClass, systemLogging, cookieName, jwtVerifier, jwtIssuer,
                jwtRolesKey);
        AuthCookieResponseFilter<P> responseFilter = new AuthCookieResponseFilter<>(principalClass, sessionMinutes, systemLogging, cookieName, cookieDomain,
                cookiePath, cookieSecure, cookieHttpOnly, jwtSigner, jwtIssuer, jwtRolesKey);

        JerseyEnvironment jersey = env.jersey();
        jersey.register(new AuthDynamicFeature(requestFilter));
        jersey.register(new AuthValueFactoryProvider.Binder<>(principalClass));
        jersey.register(RolesAllowedDynamicFeature.class);
        jersey.register(responseFilter);
    }

    //
    //
    // ---
    //

    // Public Builder for the bundle
    //
    public static class Builder<C extends Configuration, P extends CookiePrincipal> {
        final Class<P> principalClass; // required you provide a class that extends CookiePrincipal
        long sessionMinutes = 10; // non-zero positive count of minutes. defaults to 10 if zero
        boolean systemLogging; // some basic debugging, boolean primitive defaults to false
        String cookieName; // empty value defaults to '_authcookie'
        String cookieDomain; // can be null
        String cookiePath; // empty value defaults to '/'
        Boolean cookieSecure; // use Boolean object to check for null and set a default not provided
        Boolean cookieHttpOnly; // use Boolean object to check for null and set a default not provided
        String jwtSecret; // empty value generates a new key at server runtime
        Signer jwtSigner;
        Verifier jwtVerifier;
        String jwtIssuer; // can be null
        String jwtRolesKey; // empty value defaults to '_principal_roles_claim'

        // minimum setup just needs the name of your CookiePrincipal subclass
        public Builder(Class<P> principalClass) {
            this.principalClass = principalClass;
        }


        public Builder<C, P> withSessionMinutes(long sessionMinutes) {
            this.sessionMinutes = sessionMinutes;
            return this;
        }


        public Builder<C, P> withCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }


        public Builder<C, P> withDomain(String cookieDomain) {
            this.cookieDomain = cookieDomain;
            return this;
        }


        public Builder<C, P> withPath(String cookiePath) {
            this.cookiePath = cookiePath;
            return this;
        }


        public Builder<C, P> withSecure(boolean cookieSecure) {
            this.cookieSecure = Boolean.valueOf(cookieSecure);
            return this;
        }


        public Builder<C, P> withHttpOnly(boolean cookieHttpOnly) {
            this.cookieHttpOnly = Boolean.valueOf(cookieHttpOnly);
            ;
            return this;
        }


        public Builder<C, P> withSecret(String jwtSecret) {
            this.jwtSecret = jwtSecret;
            return this;
        }


        public Builder<C, P> withIssuer(String jwtIssuer) {
            this.jwtIssuer = jwtIssuer;
            return this;
        }


        public Builder<C, P> withRolesKey(String jwtRolesKey) {
            this.jwtRolesKey = jwtRolesKey;
            return this;
        }


        public Builder<C, P> withSystemLogging(boolean systemLogging) {
            this.systemLogging = systemLogging;
            return this;
        }


        // builder checks that we have enough valid info to create the Bundle
        public AuthCookieBundle<C, P> build() {

            // must have a Class that extends CookiePrincipal
            if (principalClass == null) {
                throw new IllegalArgumentException(
                        "AuthCookieBundle.Builder: Principal class must not be null. Provide your own or use the default CookiePrincipal in this package.");
            }

            // verify the passed in Principal class has its own 3-argument constructor for Name, Roles, and Claims
            try {
                principalClass.getConstructor(String.class, Set.class, Map.class);
            } catch (Exception ex) {
                throw new IllegalArgumentException(
                        "AuthCookieBundle.Builder: Principal class must implement its own 3-argument constructor (String, Set, Map) for Name, Roles, and Claims",
                        ex);
            }

            // cap session duration between 1 minute - 16819200 minutes (32 years)
            sessionMinutes = Math.min(16819200, Math.max(1, sessionMinutes));

            // debug helper, no checking needed. boolean primitive defaults to false but we reset it explicitly anyway
            systemLogging = Boolean.valueOf(systemLogging).booleanValue();

            // name of the cookie in the browser can only have ASCII alphanumerics, dashes, and underscores.
            if (cookieName != null) {
                cookieName = cookieName.trim();
            }
            if (cookieName == null || cookieName.isBlank()) {
                cookieName = "_authcookie";
            }
            if (cookieName.matches(".*[^\\p{ASCII}].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains non-ASCII characters.");
            }
            if (cookieName.matches(".*[\s\\p{Cntrl}].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains whitespace or control characters.");
            }
            if (cookieName.matches(".*[\\(\\)\\<\\>\\@\\,\\;\\:\\\"\\[\\]\\?\\=\\{\\}\\/\\\\].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains restricted puncutation.");
            }
            if (cookieName.length() > 64) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it is longer than 64 characters.");
            }

            // domain should be null if it is blank
            if (cookieDomain != null) {
                cookieDomain = cookieDomain.trim();
                if (cookieDomain.isBlank()) {
                    cookieDomain = null;
                }
            }

            // path must be non-null, non-empty, defaulting to '/'. If this is null you'll get new cookies for every distinct URL /path
            if (cookiePath == null || cookiePath.isBlank()) {
                cookiePath = "/";
            }
            cookiePath = cookiePath.trim();

            // default secure cookies requiring requests use the https: scheme
            if (cookieSecure == null) {
                cookieSecure = Boolean.TRUE;
            }

            // default true to forbid JavaScript from accessing the cookie
            if (cookieHttpOnly == null) {
                cookieHttpOnly = Boolean.TRUE;
            }

            // verify secret is usable. if it is missing default to a random Base64 UUID
            if (jwtSecret == null || jwtSecret.isBlank()) {
                UUID uuid = UUID.randomUUID();
                ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
                bb.putLong(uuid.getMostSignificantBits());
                bb.putLong(uuid.getLeastSignificantBits());
                jwtSecret = Base64.getEncoder().withoutPadding().encodeToString(bb.array());
            }
            if (jwtSecret.length() < 4 || jwtSecret.length() > 256) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: JWT Secret is invalid and should be between 4 and 256 characters in length.");
            }
            try {
                jwtSigner = HMACSigner.newSHA256Signer(jwtSecret);
                jwtVerifier = HMACVerifier.newVerifier(jwtSecret);
            } catch (Exception ex) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: JWT Secret is invalid and cannot be used to sign or verify tokens.", ex);
            }

            // issuer should be null if it is blank
            if (jwtIssuer != null) {
                jwtIssuer = jwtIssuer.trim();
                if (jwtIssuer.isBlank()) {
                    jwtIssuer = null;
                }
            }

            // name of the claims key that holds the Principal Roles. Must not conflict with standard JWT keys, have quotes, or slashes
            if (jwtRolesKey != null) {
                jwtRolesKey = jwtRolesKey.trim();
            }
            if (jwtRolesKey == null || jwtRolesKey.isBlank()) {
                jwtRolesKey = "_principal_roles_claim";
            }
            if (jwtRolesKey.length() == 3 && "aud,exp,iat,iss,jti,nbf,sub".contains(jwtRolesKey.toLowerCase())) {
                throw new IllegalArgumentException(
                        "AuthCookieBundle.Builder: JWT Roles Key is invalid because it conflicts with a Registered Claim name defined in RFC 7519");
            }
            if (jwtRolesKey.matches(".*[\\p{Cntrl}\\\"'\\/\\\\].*")) {
                throw new IllegalArgumentException(
                        "AuthCookieBundle.Builder: JWT Roles Key is invalid because it contains control characters or restricted puncutation.");
            }
            if (jwtRolesKey.length() > 64) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: JWT Roles Key is invalid because it is longer than 64 characters.");
            }

            return new AuthCookieBundle<>(this);
        }
    }

}