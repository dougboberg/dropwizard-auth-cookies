package com.ikonetics.dropwizard.authcookie;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.UUID;
import org.eclipse.jetty.http.CookieCompliance;
import org.eclipse.jetty.http.HttpCookie.SameSite;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.slf4j.event.Level;
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


public class AuthCookieBundle<C extends Configuration, P extends AuthCookiePrincipal> implements ConfiguredBundle<C> {

    // General config
    final String runid; // a short, usually unique, alphanumeric ID string, used internally
    final Class<P> principalClass; // class to build and return
    final Level logAtLevel; // defaults to Trace
    final long sessionMinutes;

    // Cookie config
    final String cookieName;
    final String cookieDomain;
    final String cookiePath;
    final Long cookieMaxAge; // Long so we can check for null
    final boolean cookieSecure;
    final boolean cookieHttpOnly;
    final SameSite cookieSameSite;
    final boolean cookiePartitioned;
    final CookieCompliance cookieCompliance;

    // JWT config
    final Signer jwtSigner;
    final Verifier jwtVerifier;
    final String jwtIssuer;

    // Use the Builder to create the Bundle. Configuration validation is done in the Builder.build(). Most things you should leave as default.
    //
    AuthCookieBundle(Builder<C, P> builder) {
        // convert some UUID bytes to Base64 to get a mix of upper, lower, numeric, and punctuation, then remove the punctuation
        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[8]);
        bb.putLong(uuid.getLeastSignificantBits());
        this.runid = Base64.getEncoder().encodeToString(bb.array()).replaceAll("[^a-zA-Z0-9]", "");

        this.principalClass = builder.principalClass;
        this.sessionMinutes = builder.sessionMinutes;
        this.cookieName = builder.cookieName;
        this.cookieDomain = builder.cookieDomain;
        this.cookiePath = builder.cookiePath;
        this.cookieMaxAge = builder.cookieMaxAge;
        this.cookieSecure = builder.cookieSecure;
        this.cookieHttpOnly = builder.cookieHttpOnly;
        this.cookieSameSite = builder.cookieSameSite;
        this.cookiePartitioned = builder.cookiePartitioned;
        this.cookieCompliance = builder.cookieCompliance;
        this.jwtSigner = builder.jwtSigner;
        this.jwtVerifier = builder.jwtVerifier;
        this.jwtIssuer = builder.jwtIssuer;
        this.logAtLevel = builder.logAtLevel;
    }


    // Dropwizard bundle setup
    @Override
    public void run(C configuration, Environment env) throws Exception {

        // shared key created at runtime and used by both Request & Response. internal and not configurable.
        String roleKey = "_internal_roles_" + runid;

        AuthCookieRequestFilter<P> requestFilter = new AuthCookieRequestFilter<>(principalClass, logAtLevel, cookieName, jwtVerifier, jwtIssuer, roleKey);
        AuthCookieResponseFilter<P> responseFilter = new AuthCookieResponseFilter<>(principalClass, logAtLevel, sessionMinutes, cookieName, cookieDomain,
                cookiePath, cookieMaxAge, cookieSecure, cookieHttpOnly, cookieSameSite, cookiePartitioned, cookieCompliance, jwtSigner, jwtIssuer, roleKey);

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
    public static class Builder<C extends Configuration, P extends AuthCookiePrincipal> {
        final Class<P> principalClass; // required you provide a class that extends AuthCookiePrincipal
        Level logAtLevel = Level.TRACE; // logging level for all messages coming from this library
        long sessionMinutes = 10; // non-zero positive count of minutes. defaults to 10
        String cookieName; // empty value defaults to '_authcookie'
        String cookieDomain; // can be null
        String cookiePath; // empty value defaults to '/'
        Long cookieMaxAge; // default is 60 * sessionMinutes; Long so we can check for null
        Boolean cookieSecure; // use Boolean internally to check for null/missing builder param, or default to 'true'
        Boolean cookieHttpOnly; // use Boolean internally to check for null/missing builder param, or default to 'true'
        SameSite cookieSameSite; // cross-site cookie behavior: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute
        Boolean cookiePartitioned; // partitioned privacy storage: https://developer.mozilla.org/en-US/docs/Web/Privacy/State_Partitioning#state_partitioning
        CookieCompliance cookieCompliance; // rules for writing cookie value. default 'null' uses RFC6265 and writes out SameSite & Partitioned values
        String jwtSecret; // empty value generates a new key at server runtime
        Signer jwtSigner;
        Verifier jwtVerifier;
        String jwtIssuer; // can be null

        // minimum setup just needs the name of your CookiePrincipal subclass
        public Builder(Class<P> principalClass) {
            this.principalClass = principalClass;
        }


        public Builder<C, P> logAtLevel(Level logAtLevel) {
            this.logAtLevel = logAtLevel;
            return this;
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


        public Builder<C, P> withMaxAge(Long cookieMaxAge) {
            this.cookieMaxAge = cookieMaxAge;
            return this;
        }


        public Builder<C, P> withSecure(boolean cookieSecure) {
            this.cookieSecure = Boolean.valueOf(cookieSecure);
            return this;
        }


        public Builder<C, P> withHttpOnly(boolean cookieHttpOnly) {
            this.cookieHttpOnly = Boolean.valueOf(cookieHttpOnly);
            return this;
        }


        public Builder<C, P> withSameSite(SameSite cookieSameSite) {
            this.cookieSameSite = cookieSameSite;
            return this;
        }


        public Builder<C, P> withPartitioned(boolean cookiePartitioned) {
            this.cookiePartitioned = cookiePartitioned;
            return this;
        }


        public Builder<C, P> withCookieCompliance(CookieCompliance cookieCompliance) {
            this.cookieCompliance = cookieCompliance;
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


        // builder checks that we have enough valid info to create the Bundle
        public AuthCookieBundle<C, P> build() {

            // must have a Class that extends AuthCookiePrincipal
            if (principalClass == null) {
                throw new IllegalArgumentException(
                        "AuthCookieBundle.Builder: Principal class must not be null. Provide your own or use the default CookiePrincipal in this package.");
            }

            // verify the passed in Principal class has its own 3-argument constructor for Name, Roles, and Claims
            try {
                principalClass.getConstructor(String.class);
            } catch (Exception ex) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Principal class must implement its own 1-argument constructor", ex);
            }

            // cap session duration between 1 minute - 16819200 minutes (32 years)
            sessionMinutes = Math.min(16819200, Math.max(1, sessionMinutes));

            // name of the cookie in the browser can only have ASCII alphanumerics, dashes, and underscores.
            if (cookieName == null || cookieName.isBlank()) {
                cookieName = "_authcookie";
            }
            cookieName = cookieName.trim();
            if (cookieName.matches(".*[^\\p{ASCII}].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains non-ASCII characters.");
            }
            if (cookieName.matches(".*[\s\\p{Cntrl}].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains whitespace or control characters.");
            }
            if (cookieName.matches(".*[\\(\\)\\<\\>\\@\\,\\;\\:\\\"\\[\\]\\?\\=\\{\\}\\/\\\\].*")) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name is invalid because it contains restricted puncutation.");
            }
            if (cookieName.length() < 4 || cookieName.length() > 64) {
                throw new IllegalArgumentException("AuthCookieBundle.Builder: Cookie name length must be between 4 and 64 characters.");
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

            // use the sessionMinutes if the maxAge was not explicitly set
            if (cookieMaxAge == null) {
                cookieMaxAge = sessionMinutes * 60;
            }

            // default secure cookies requiring requests use the https: scheme
            if (cookieSecure == null) {
                cookieSecure = Boolean.TRUE;
            }

            // default true to forbid JavaScript from accessing the cookie
            if (cookieHttpOnly == null) {
                cookieHttpOnly = Boolean.TRUE;
            }

            // default 'lax' samesite / cross-site behavior
            if (cookieSameSite == null) {
                cookieSameSite = SameSite.LAX;
            }

            // default partitioned cookies for storage
            if (cookiePartitioned == null) {
                cookiePartitioned = Boolean.TRUE;
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

            return new AuthCookieBundle<>(this);
        }
    }

}
