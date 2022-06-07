package com.ikonetics;

import java.time.Instant;
import java.util.Set;
import com.codahale.metrics.health.HealthCheck;
import com.ikonetics.dropwizard.authcookie.AuthCookieBundle;
import com.ikonetics.dropwizard.authcookie.AuthCookieBundle.Builder;
import com.ikonetics.dropwizard.authcookie.CookiePrincipal;
import io.dropwizard.auth.Auth;
import io.dropwizard.core.Application;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;;


public class SampleApp extends Application<Configuration> {

    public static void main(String[] args) throws Exception {
        new SampleApp().run("server");
        // new SampleApp().run(args);
    }


    @Override
    public void initialize(Bootstrap<Configuration> bootstrap) {
        Builder<Configuration, CookiePrincipal> builder = new AuthCookieBundle.Builder<>(CookiePrincipal.class);
        builder = builder.withSessionMinutes(25).withSecure(false);
        bootstrap.addBundle(builder.build());
    }


    @Override
    public void run(Configuration configuration, Environment env) {

        env.healthChecks().register("unusedhealthcheck", new HealthCheck() {
            @Override
            protected HealthCheck.Result check() {
                return HealthCheck.Result.healthy();
            }
        });

        env.jersey().register(new SampleResource());
    }

    @Path("/")
    @Produces(MediaType.TEXT_HTML)
    public class SampleResource {
        String links = "\n\n\n\n<a href='/'>root: / </a> - public page. no login needed                                    "
                + "\n<a href='/login'>/login</a> - authenticates and gives you a new Principal session                     "
                + "\n<a href='/behindLogin'>/behindLogin</a> - a private page for any authenticated user, only viewable after you've logged in "
                + "\n<a href='/loginasadmin'>/loginAsAdmin</a> - authenticates and gives you a custom 'admin' role        "
                + "\n<a href='/behindAdmin'>/admin only area</a> - a private page for users in a custom admin role           "
                + "\n<a href='/logout'>/logout</a> - removes your authenticated user. good bye.";

        public SampleResource() {
            super();
        }


        @GET
        public String getRoot(@Context ContainerRequestContext context) {
            Long now = Instant.now().getEpochSecond();
            return "<pre>Public home page  [now " + now + "] \n\n   my user: " + context.getSecurityContext().getUserPrincipal() + links + "</pre>";
        }


        @GET
        @Path("login")
        public String login(@Context ContainerRequestContext context) {
            Long now = Instant.now().getEpochSecond();
            CookiePrincipal principal = new CookiePrincipal("My User Name");
            principal.setRoles(Set.of("General_User_Role"));
            principal.addClaim("loginsecond", "" + Instant.now().getEpochSecond());
            principal.addInContext(context);
            return "<pre>Login   [now " + now + ") \n\n   my user: " + principal + links + "</pre>";
        }


        @GET
        @Path("behindLogin")
        public String behindLogin(@Auth CookiePrincipal principal) {
            Long now = Instant.now().getEpochSecond();
            return "<pre>Behind Login  [now " + now + "] \n\n   my user: " + principal.toString() + links + "</pre>";
        }


        @GET
        @Path("loginasadmin")
        public String loginAsAdmin(@Context ContainerRequestContext context) {
            Long now = Instant.now().getEpochSecond();
            CookiePrincipal principal = new CookiePrincipal("My Admin Name");
            principal.setRoles(Set.of("I_AM_ADMIN"));
            principal.addClaim("loginsecond", "" + Instant.now().getEpochSecond());
            principal.addInContext(context);
            return "<pre>Admin Login  [now " + now + "] \n\n   my user: " + principal + links + "</pre>";
        }


        @GET
        @Path("behindAdmin")
        @RolesAllowed("I_AM_ADMIN")
        public String behindAdmin(@Auth CookiePrincipal principal) {
            Long now = Instant.now().getEpochSecond();
            return "<pre>Admin Only Area  [now " + now + "] \n\n   my user: " + principal + links + "</pre>";
        }


        @GET
        @Path("logout")
        public String logout(@Context ContainerRequestContext context) {
            Long now = Instant.now().getEpochSecond();
            CookiePrincipal.removeFromContext(context);
            return "<pre> Log Out  [now " + now + "] \n\n   my user: " + context.getSecurityContext().getUserPrincipal() + links + "</pre>";
        }

    }
}
