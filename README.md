# dropwizard-auth-cookies
Use simple HTTP cookies for Dropwizard 4 session management with a standard Java 17 Principal and JSON Web Token. 

### Details
This library creates a standard HTTP cookie whose value is a JSON Web Token (JWT https://jwt.io) object. 
The JWT may contain standard Java Principal `Roles` and additional custom key-value `claims`. 
The cookie is stored on the remote client (web browser) to be returned at a later time; on a future request. 
The Java Prinicpal is used on the Dropwizard server for standard Java authorization patterns.

When the cookie is returned to the server, its JWT value is verified to ensure that the JWT has not expired and is still valid. 
A valid JWT is converted into a standard Java `Principal` class and the Principal Roles are read from the JWT and assigned to the Principal. 
If the JWT is invalid for any reason, the Principal is unknown (not logged in) and is not created.

Obviously heavily inspired by @dhatim and https://github.com/dhatim/dropwizard-jwt-cookie-authentication

### Some of the available configuration options
* Session durations of 1 or more minutes.
* Add zero or many Principal Roles which work with `@RolesAllowed` on your server methods to limit which actions a remote caller may perform.
* Use your own custom Principal class, or use the default `CookiePrincipal` which should work in most scenarios.
* Limit the cookie with `path`, `domain`, `secure`, and `HttpOnly`. 
* Customize the JWT issuer and secret.


# Setup &nbsp; &nbsp; ![Release](https://jitpack.io/v/com.ikonetics/dropwizard-auth-cookies.svg)

## Add the Dependency 
The compiled binary for this project is hosted with JitPack.
https://jitpack.io/#com.ikonetics/dropwizard-auth-cookies

Add the following to your project's Maven `pom.xml`
```xml
<!-- Add the JitPack repository -->
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<!-- Add the dependency -->
<dependency>
    <groupId>com.ikonetics</groupId>
    <artifactId>dropwizard-auth-cookies</artifactId>
    <version>2.0</version>
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

    bootstrap.addBundle(builder.build());

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
@POST
@Path("/process_login")
public void login(@Context ContainerRequestContext context) {

    // ... my custom login code to verify the user and their credentials ... 

    // create a Principal for the user after account validation succeeds, 
    // passing in their unique ID as the Principal Name value (arbitrary and up to you)
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
@Path("/private-page")
public String getPrivatePage(@Auth CookiePrincipal principal) {
    // the @Auth annotation ensures the 'principal' must exist, or an unauthorized error is thrown (see Dropwizard docs)
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

// ... some time later, perhaps on a future unrelated request ...

String postcode = principal.getClaim("postalCode");
```
All custom information is stored in the JWT as *claim* values.
The claims are part of the cookie value and are sent to the calling client.

**You should not put secret information into a claim.**
JWT information, including all claims, are simply *encoded* and are absolutely not *encrypted*.

The `AuthCookiePrincipal` super class has helper methods to set all claims at once, get all claims, and remove a claim.
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

The `AuthCookiePrincipal` super class has helper methods to set all roles, get all roles, add a role, or remove a role.
* `setRoles(Set<String>)`
* `getRoles()`
* `addRole(String)`
* `removeRole(String)`



# Custom Configuration (easy tweaks)
Configuring the library is performed by chaining calls to the `AuthCookieBundle.Builder` object. 
Create a new instance of the `Builder` as shown above, then call any of the following methods before calling the final `build()` method.

For example, to customize the session length and cookie behavior in Dropwizard's `initialize()` setup:
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

### `withSessionMinutes(long)`
* default is a `10` minute session

Pass in the duration of whole minutes the session should be considered valid. 
The value provided must be a minimum of `1` minute and a maximum of `16819200` minutes (32 years).
Values outside of the minimum and maximum range are capped to fit in the range.
*(If you pass in `-3` it is changed to the minimum value of `1`)*

The session time is renewed with each request. 
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



# Advanced Configuration

Most scenarios won't need to use these advanced optional configurations.

## Use a custom Java Principal class
For most cases you can simply use the provided `CookiePrincipal` class, which already extends `AuthCookiePrincipal`. 
If you need something more complex, create your own custom `AuthCookiePrincipal` extension and pass it to the `Builder()`.

### `new Builder(Class<P>)`
* the class must extend the abstract class `com.ikonetics.dropwizard.authcookie.AuthCookiePrincipal` 

A custom Principal class must implement its own 1-argument constructor `(String)` for the Java Principal Name.
The constructor must call to `super(name)` and can otherwise be empty:
```java
public class MyCustomPrincipal extends AuthCookiePrincipal {
    public MyCustomPrincipal(String name) {
        super(name);
    }
}
```

## Custom cookie properties

### `withDomain(String)`
* ignored by default and when set to `null` or a blank string.

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
* names can be `4` to `64` characters in length

Pass in a simple string of ASCII alphanumerics, dashes, and underscores to change the cookie name.


## Custom JWT properties

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

## Debugging options

### `withSilent(boolean)`
* default is `true` which silences all `Logger` messages generated by this library.

Pass `false` to have the library write various `Logger.debug()`,  `Logger.info()`, and  `Logger.warn()` messages.



# References
* @dhatim's Dropwizard 2 auth library https://github.com/dhatim/dropwizard-jwt-cookie-authentication
* Dropwizard 4 (versus 3 or 2) https://github.com/dropwizard/dropwizard/discussions/4720#discussioncomment-2496043
* Dropwizard resources: https://www.dropwizard.io/en/latest/getting-started.html#creating-a-resource-class
* Dropwizard authentication: https://www.dropwizard.io/en/latest/manual/auth.html?highlight=RolesAllowed#protecting-resources
* Cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
* JWT: https://jwt.io/introduction
* Security considerations about storing data on the client browser: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage


