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
        String links = "\n\n\n<a href='/'>/ public root</a> \n<a href='/whoami'>/whoami</a> \n<a href='/login'>/login</a>"
                + "\n<a href='/loginasadmin'>/loginAsAdmin</a> \n<a href='/admin'>/admin only area</a> \n<a href='/logout'>/logout</a>";

        public SampleResource() {
            super();
        }


        @GET
        public String getRoot(@Context ContainerRequestContext context) {
            return "<pre> Public root home: " + Instant.now().getEpochSecond() + "\n user: " + context.getSecurityContext().getUserPrincipal() + links
                    + "</pre>";
        }


        @GET
        @Path("login")
        public String login(@Context ContainerRequestContext context) {
            CookiePrincipal principal = new CookiePrincipal("My User Name", Set.of("Some_User"));
            principal.addClaim("loginsecond", "" + Instant.now().getEpochSecond());
            principal.addInContext(context);
            return "<pre> Login: " + Instant.now().getEpochSecond() + "\n user:" + principal + links + "</pre>";
        }


        @GET
        @Path("whoami")
        public String whoami(@Auth CookiePrincipal principal) {
            return "<pre> WhoAmI: " + Instant.now().getEpochSecond() + "\n user:" + principal.toString() + links + "</pre>";
        }


        @GET
        @Path("loginasadmin")
        public String loginAsAdmin(@Context ContainerRequestContext context) {
            CookiePrincipal principal = new CookiePrincipal("My Admin Name", Set.of("I_AM_ADMIN"));
            principal.addClaim("loginsecond", "" + Instant.now().getEpochSecond());
            principal.addInContext(context);
            return "<pre> Admin Login: " + Instant.now().getEpochSecond() + "\n user:" + principal + links + "</pre>";
        }


        @GET
        @Path("admin")
        @RolesAllowed("I_AM_ADMIN")
        public String getAdminResource(@Auth CookiePrincipal principal) {
            return "<pre> Admin Check:" + Instant.now().getEpochSecond() + "\n user:" + principal + links + "</pre>";
        }


        @GET
        @Path("logout")
        public String logout(@Context ContainerRequestContext context) {
            CookiePrincipal.removeFromContext(context);
            return "<pre> Log Out: " + Instant.now().getEpochSecond() + "\n user:" + context.getSecurityContext().getUserPrincipal() + links + "</pre>";
        }

    }
}
