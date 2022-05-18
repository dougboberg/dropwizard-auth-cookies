package com.ikonetics.dropwizard.authcookie;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.container.ContainerRequestContext;


public class CookiePrincipal implements Principal {
    String name; // Java standard Principal name
    Set<String> roles; // Java standard concept of Roles for the Principal - store as Set to avoid dupes
    Map<String, Object> claims; // optional JWT map of arbitrary values / custom session values

    // simple inits for start of new session
    public CookiePrincipal(String name) {
        this(name, new HashSet<>(), null);
    }


    public CookiePrincipal(String name, Set<String> roles) {
        this(name, roles, null);
    }


    // init used when the JWT is decoded from the returning request cookie
    public CookiePrincipal(String name, Set<String> roles, Map<String, Object> claims) {
        this.name = Objects.requireNonNull(name, "Principal name must not be null");
        this.roles = Objects.requireNonNull(roles, "Principal roles must not be null");
        this.claims = claims; // can be null
    }


    //
    // ---
    // support standard Principal name and its access Roles
    //
    @Override
    public String getName() {
        return this.name;
    }


    public boolean isInRole(String role) {
        return roles.contains(role);
    }


    public Set<String> setRoles(Set<String> roles) {
        if (roles == null) {
            this.roles = new HashSet<>();
        } else {
            this.roles = roles;
        }
        return roles;
    }


    public Set<String> getRoles() {
        return roles;
    }


    public Set<String> addRole(String role) {
        roles.add(role);
        return roles;
    }


    public Set<String> removeRole(String role) {
        roles.remove(role);
        return roles;
    }


    //
    // ---
    // support JWT arbitrary claim values, which may be null
    //
    public Map<String, Object> setClaims(HashMap<String, Object> claims) {
        this.claims = claims;
        return this.claims;
    }


    public Map<String, Object> getClaims() {
        return this.claims;
    }


    public Map<String, Object> addClaim(String key, Object value) {
        this.claims = Optional.ofNullable(this.claims).orElse(new HashMap<>());
        this.claims.put(key, value);
        return this.claims;
    }


    public Object getClaim(String key) {
        if (this.claims == null) {
            return null;
        }
        return this.claims.get(key);
    }


    public Map<String, Object> removeClaim(String key) {
        if (this.claims == null) {
            return null;
        }
        this.claims.remove(key);
        return this.claims;
    }


    //
    // ---
    // helpers for SecurityContext and Dropwizard Authorizer
    //
    public void addInContext(ContainerRequestContext context) {
        context.setSecurityContext(new AuthCookieSecurityContext(this, context.getSecurityContext().isSecure()));
    }


    public static void removeFromContext(ContainerRequestContext context) {
        context.setSecurityContext(new AuthCookieSecurityContext(null, context.getSecurityContext().isSecure()));
    }


    //
    // ---
    // debug helpers
    //
    @Override
    public String toString() {
        return String.format("<%s> JSON: %s", this.getClass().getName(), this.toJson());
    }


    public String toJson() {
        // returns JSON string with an extra space after the JSON comma separators, for word-wrap happiness
        final ObjectMapper mapper = new ObjectMapper();
        final MinimalPrettyPrinter extraspaces = new MinimalPrettyPrinter() {
            @Override
            public void writeObjectEntrySeparator(JsonGenerator jg) throws IOException {
                super.writeObjectEntrySeparator(jg); // super writes a default comma separator
                jg.writeRaw(' '); // the extra char space
            }


            @Override
            public void writeArrayValueSeparator(JsonGenerator jg) throws IOException {
                super.writeArrayValueSeparator(jg); // super writes a default comma separator
                jg.writeRaw(' '); // the extra char space
            }
        };

        try {
            return mapper.writer(extraspaces).writeValueAsString(this);

        } catch (IOException ex) {
            return "{-- JSON ERROR " + ex.getMessage() + " --}";
        }
    }
}
