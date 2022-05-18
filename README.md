# dropwizard-auth-cookies
Cookies for Dropwizard 4 session management using standard Java 17 Principal and JSON Web Tokens. 
Obviously heavily inspired by @dhatim and https://github.com/dhatim/dropwizard-jwt-cookie-authentication

* Dropwizard 4 targets Java 11+ and the jakarta namespace.
* This library targets Java 17.

## Detailed Description
This library creates a standard HTTP cookie whose value is a JSON Web Token (JWT https://jwt.io) object. 
The JWT may contain standard Java Principal Roles and additional custom key-value "claims". 
The cookie is stored on the remote client (web browser) and the Prinicpal is used in Java on the Dropwizard server. 
You can use the Java Principal and its Roles for standard Java authorization patterns.


### Even more detail...
During a response to a request, a cookie is created and returned to the calling client (perhaps a web browser client). 
The cookie is stored on the browser to be returned at a later time; on the next request.

When the cookie is returned, its JWT value is verified to ensure that the JWT has not expired and is still valid. 
A valid JWT is converted into a standard Java Principal class and the Principal Roles are read from the JWT and assigned to the Principal. 
If the JWT is invalid for any reason, the Principal is unknown (not logged in) and is not created.

## Overview of available configuration options
* Set the user's session duration to 1 or more minutes
* Add zero or many Principal Roles which work with `@RolesAllowed` on your server methods to limit which actions a remote caller may perform.
* Use your own custom Principal class, or use the default `CookiePrincipal` which should work in most scenarios.
* Limit the cookie with `path`, `domain`, `secure`, and `HttpOnly`. 
* Specify the cookie's name.


# Setup

## Add the Dependency 
The compiled binary for this project is currently hosted with GitHub Packages.
You need to have a personal access token from GitHub and use it to configure your .m2/settings.xml file.
https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-to-github-packages

After GitHub Packages settings are configured, add the following to your project's Maven `pom.xml`
```xml
<dependency>
    <groupId>com.ikonetics</groupId>
    <artifactId>dropwizard-auth-cookies</artifactId>
    <version>0.8</version>
</dependency>
```

## Create the AuthCookieBundle and add it to Dropwizard
Use the `AuthCookieBundle.Builder` to create and configure the `AuthCookieBundle`. Add the bundle to the Dropwizard Application's `bootstrap` configuration.

Modify the `initialize()` method of your Dropwizard Application as shown below for a bare-minimum configuration of this library:
```java
import com.ikonetics.dropwizard.authcookie.*;

@Override
public void initialize(Bootstrap<Configuration> bootstrap) {
    Builder<Configuration, CookiePrincipal> builder = new AuthCookieBundle.Builder<>(CookiePrincipal.class);
    // TODO: maybe add optional builder configurations here
    bootstrap.addBundle(builder.build());

    // ... my other bundles and dropwizard configs...
}
```

# Usage

## Protecting a Dropwizard Resource
This section assumes you are familiar with Dropwizard Resources.
Review the Dropwizard docs for correct and detailed information (linked below).
You should also already have methods to verify user credentials.

### Creating an newly authenticated Principal
When you authenticate a user, create a `CookiePrincipal` for them and attach it to the Java context:
```java
@GET
@Path("/login")
public void login(@Context ContainerRequestContext context) {

    // ... my custom login code to verify the user and their credentials ... 

    // create a Principal for this user, passing in their unique ID as the Principal Name value (arbitrary and up to you)
    CookiePrincipal principal = new CookiePrincipal( aGoodUser.userId );

    // attach to the context
    principal.addInContext(context);
}
```
The created Principal object is serialized and returned to the calling client in the form of a JWT cookie.
When the client returns the cookie to the server on its next call, the JWT cookie is verified then deserialized back into the Principal object.

### Identifying a returning authenticated Principal
Use the `@Auth` annotation to retrieve the Principal on resources that require a known user.
If the client has a good and valid JWT cookie the library deserializes the JWT into the Principal object and passes it through the `@Auth` annotation.
```java
@GET
@Path("/whoami")
public String whoami(@Auth CookiePrincipal principal) {
    // the @Auth annotation ensures the 'principal' must exist
    return "Who Am I? " + principal.toString();
}
```
If the client does not have a valid JWT cookie, they will not have a Principal and will be blocked from accessing the method above.


## Adding custom information to the Principal's session
**You should not put secret information into a claim**

You may add custom application information to any user Principal you create.
The easiest way is to use `addClaim(key, value)` and `getClaim(key)`.
```java
principal.addClaim("postalCode", "KA14 3BL");

// ... some time later ...

String postcode = principal.getClaim("postalCode");
```
All custom information is stored in the JWT as *claim* values.
The claims are part of the cookie value and are sent to the calling client.

**You should not put secret information into a claim**
JWT information, including all claims, are only *encoded* and are absolutely not *encrypted*.

The `CookiePrincipal` has helper methods to set all claims at once, get all claims, and remove a claim.
* `setClaims(HashMap<String, Object>)`
* `getClaims()`
* `addClaim(String, Object)`
* `getClaim(String)`
* `removeClaim(String)`


## Limiting Resources to Principals within a specific Role

### Assign Roles to an authenticated user Principal
Roles are a set of arbitrary sting values you can assign to a Principal object when it is created.
The set of roles may be checked later, when restricting access to a specific method action on the server.
```java
// this user can view parts of the Accounting section of our website and can access all of the Marketing sections
Set<String> roles = Set.of("Accounting_ReadOnly", "Marketing_Admin");

// pass in the roles when creating the user's Principal:
CookiePrincipal principal = new CookiePrincipal(aGoodUser.userId, roles );
principal.addInContext(context);
```
Again, the Role names are made up.
Use any string that makes sense in your own application.


### Verify the Principal is a member of a Role
Use the `@RolesAllowed` annotation on a Dropwizard resource class or method to restrict access to only users with the correct Role assigned.
```java
@GET
@Path("/acct/reports")
@RolesAllowed({"Accounting_Admin", "Accounting_ReadOnly"})
public String acctReports(@Auth CookiePrincipal principal) {
    // our user from the previous example above can access this resource 
    // because they have the 'Accounting_ReadOnly' Role
    // which is allowed by the '@RolesAllowed()' annotation.
}

@GET
@Path("/acct/admin")
@RolesAllowed({"Accounting_Admin"})
public String acctAdminArea(@Auth CookiePrincipal principal) {
    // our user above can not access this resource 
    // because they do not have the Role 'Accounting_Admin'
    // which is required by the '@RolesAllowed()' annotation.
}
```

The `CookiePrincipal` has helper methods to set all roles, get all roles, add a role, or remove a role.
* `setRoles(Set<String>)`
* `getRoles()`
* `addRole(String)`
* `removeRole(String)`


# Custom Configuration
Configuring the library is performed by chaining calls to the `AuthCookieBundle.Builder` object. 
Create a new instance of the `Builder` as shown above, then call any of the following methods before calling the final `build()` method.

For example:
```java
    Builder<Configuration, CookiePrincipal> builder = new AuthCookieBundle.Builder<>(CookiePrincipal.class);

    // 25 minute session with cookies on a specific path without a HTTPS connection
    builder = builder.withSessionMinutes(25)
        .withPath("/mydocs/")
        .withSecure(false);

    // my configuration is complete,
    // call .build() and pass it to Dropwizard
    bootstrap.addBundle( builder.build() );
```

## Easy Optional Configuration

### `withSessionMinutes(long)`
* default is a `10` minute session

Pass in the duration of whole minutes the session should be considered valid. 
The value provided must be a minimum of `1` minute and a maximum of `16819200` minutes (32 years).
Values outside of the minimum and maximum range are capped to fit in the range.
*(If you pass in `-3` it is changed to the minimum value of `1`)*

The session time is 'restarted' with each request. 
This behavior is intentional. 
Each new response from a protected resource on the server receives a new cookie JWT, which is valid for *SessionMinutes* number of minutes, starting *now*. 
For example, if you configure the session to be valid for 5 minutes and the cookie is returned to the server at 4 minutes, a new cookie is created for another 5 minutes starting at the time of this new cookie's creation, then returned to the calling client.


### `withSecure(boolean)`
* default is `true` and the cookie is only sent over `https:`

Specifies whether the cookie will only be sent over a secure connection. 
The default value of `true` indicates that the cookie is sent to the server only when a request is made with the `https:` scheme *(except on localhost)*.
A `true` value makes the cookie more *resistant* to man-in-the-middle attacks. 
Pass `false` to disable the cookie Secure option.


### `withHttpOnly(boolean)`
* default is `true` and the cookie is only visible as part of an HTTP request.

A `true` value is intended to forbid JavaScript on the web browser from accessing the cookie, for example, through the Document.cookie property.
A `true` value also *helps mitigate* attacks against cross-site scripting (XSS). 
Pass `false` to disable the cookie HttpOnly option.



## Advanced Optional Configuration

Most scenarios won't need to use these advanced optional configurations.

### `new Builder(Class<P>)`
* a `CookiePrincipal` class is **always** required when instantiating a new Builder

Provide your own custom Principal class that extends `com.ikonetics.dropwizard.authcookie.CookiePrincipal`.

The custom Principal class must implement its own 3-argument constructor `(String, Set<String>, Map)` for Name, Roles, and Claims.
The constructor must call to `super(n, r, c)` and can otherwise be empty:
```java
public class MyCustomPrincipal extends CookiePrincipal {
    public MyCustomPrincipal(String name, Set<String> roles, Map<String, Object> claims) {
        // pass arguments to super CookiePrincipal
        super(name, roles, claims);
    }
}
```


### `withDomain(String)`
* ignored by default
* ignored when set to `null` or a blank string.

The host domain for which the cookie is valid. 
Multiple host/domain values are not allowed, but if a domain is specified, then subdomains are always included.


### `withPath(String)`
* default is a root path '`/`', which matches all subdirectories 
* the default is used if it is set to `null` or blank. 

The URI path for which the cookie is valid. 
The provided path string must exist in the requested URL for the browser to send the Cookie header. 

The forward slash (`/`) character is interpreted as a directory separator, and subdirectories are matched as well. For example, for `withPath("/docs")` :
* the request paths `/docs`, `/docs/`, `/docs/Web/`, and `/docs/Web/HTTP` **will all match**.
* the request paths `/`, `/docsets`, `/fr/docs` **will not match**.


### `withCookieName(String)`
* the default cookie is named '`_authcookie`' 
* names can be `1` to `64` characters in length

Pass in a simple string of ASCII alphanumerics, dashes, and underscores to change the cookie name.


### `withRolesKey(String)`
* the default internal key is '`_principal_roles_claim`' 
* key can be `1` to `64` characters in length

You probably should not change this default value. 

The library uses this key to inject the Principal Roles into a custom JWT claim. If you override the default, your key must be a simple string and cannot conflict with any standard JWT key names and cannot have quotes, slashes, or control characters.


### `withIssuer(String)`
* ignored by default
* ignored when set to `null` or a blank string.

An arbitrary name to identify which system issued the JWT cookie. 
When this value is set, the JWT objects are created with the `iss` claim. 
During JWT validation on subsequent requests the `iss` value is verified to match the issuer before being accepted as a valid JWT.


### `withSecret(String)`
* the default is a random string that is not exposed nor stored
* a new secret is generated at each application reboot
* the secret can be `4` to `256` characters in length

You probably don't need to set this value.

A secret string used to create a SHA-256 hash for signing and verifying the JWT. 
When not provided the library will create a new UUID, convert it to a Base64 encoded string, and use that string as the secret.
A new secret string is created at each Dropwizard Application reboot (during `initialize()` as described in Setup above).

Theoretically you could use this configuration to share the same secret across multiple instances of your Dropwizard Application.
The resulting cookie JWT values will be valid on any instance using the same shared secret that needs to verify the JWT.



### `withSystemLogging(boolean)`
* default is `false` which disables all printing

Pass `true` to have the library print some informational messages to `System.out.println()`.



# References
* *@dhatim's Dropwizard 2 auth library https://github.com/dhatim/dropwizard-jwt-cookie-authentication
* Dropwizard 4 (versus 3 or 2) https://github.com/dropwizard/dropwizard/discussions/4720#discussioncomment-2496043
* Dropwizard resources: https://www.dropwizard.io/en/latest/getting-started.html#creating-a-resource-class
* Dropwizard authentication: https://www.dropwizard.io/en/latest/manual/auth.html?highlight=RolesAllowed#protecting-resources
* Cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
* JWT: https://jwt.io/introduction
* Security considerations about storing data on the client browser: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage


