package com.ikonetics.dropwizard.authcookie;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import jakarta.ws.rs.container.ContainerRequestContext;


public abstract class AuthCookiePrincipal implements Principal {
    final String name; // Java standard Principal name
    Set<String> roles; // Java SecurityContext concept of arbitrary Roles for the Principal - store as Set to avoid dupes
    Map<String, Object> claims; // map of arbitrary session values
    Map<String, String> internals; // map of internal JWT registered claims we might want to read. Not settable.

    //
    // ---
    // Java Principal
    //
    protected AuthCookiePrincipal(String name) {
        this.name = name;
    }


    public String getName() {
        return name;
    }


    //
    // ---
    // roles for Java SecurityContext and Dropwizard Authorizer
    //
    public final void addInContext(ContainerRequestContext request) {
        request.setSecurityContext(new AuthCookieSecurityContext(this, request.getSecurityContext().isSecure()));
    }


    public static final void removeFromContext(ContainerRequestContext request) {
        request.setSecurityContext(new AuthCookieSecurityContext(null, request.getSecurityContext().isSecure()));
    }


    public boolean isInRole(String role) {
        return (roles != null) && roles.contains(role);
    }


    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }


    public Set<String> getRoles() {
        return roles;
    }


    public void addRole(String role) {
        if (roles == null) {
            roles = new HashSet<>();
        }
        roles.add(role);
    }


    public void removeRole(String role) {
        if (roles != null) {
            roles.remove(role);
        }
    }


    //
    // ---
    // arbitrary JWT claim values
    //
    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }


    public Map<String, Object> getClaims() {
        return claims;
    }


    public void addClaim(String key, Object value) {
        if (claims == null) {
            claims = new HashMap<>();
        }
        claims.put(key, value);
    }


    public Object getClaim(String key) {
        return (claims == null) ? null : claims.get(key);
    }


    public void removeClaim(String key) {
        if (claims != null) {
            claims.remove(key);
        }
    }


    //
    // ---
    // helpers for the internal generated JWT values. for example, you could read the 'exp' value of the JWT to get the expiration second
    //
    final void storeJwtInternals(Map<String, String> internals) {
        this.internals = internals;
    }


    public final Map<String, String> readJwtInternals() {
        return (internals == null) ? null : Collections.unmodifiableMap(internals);
    }

}
