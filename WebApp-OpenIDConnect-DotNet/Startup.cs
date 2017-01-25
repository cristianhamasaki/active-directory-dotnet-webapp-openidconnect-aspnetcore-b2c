using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public static string SignUpPolicyId;
        public static string SignInPolicyId;
        public static string ProfilePolicyId;
        public static string ClientId;
        public static string PostLogoutRedirectUri;
        public static string AadInstance;
        public static string Tenant;

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets();
            }
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            services.AddAuthentication(
                SharedOptions => SharedOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseCookieAuthentication();

            // App config settings
            ClientId = Configuration["Authentication:AzureAD:ClientId"];
            AadInstance = Configuration["Authentication:AzureAd:AADInstance"];
            Tenant = Configuration["Authentication:AzureAd:TenantId"];
            PostLogoutRedirectUri = Configuration["Authentication:AzureAD:PostLogoutRedirectUri"];

            // B2C policy identifiers
            SignUpPolicyId = Configuration["Authentication:AzureAD:SignUpPolicyId"];
            SignInPolicyId = Configuration["Authentication:AzureAD:SignInPolicyId"];

            // Configure the OWIN pipeline to use OpenID Connect auth.
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignUpPolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignInPolicyId));

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private OpenIdConnectOptions CreateOptionsFromPolicy(string policy)
        {
            policy = policy.ToLower();
            return new OpenIdConnectOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = string.Format(AadInstance, Tenant, policy),
                AuthenticationScheme = policy,
                CallbackPath = new PathString(string.Format("/{0}", policy)),

                // These are standard OpenID Connect parameters, with values pulled from config.json
                ClientId = ClientId,
                PostLogoutRedirectUri = new PathString(string.Format("/{0}", PostLogoutRedirectUri)),
                Events = new OpenIdConnectEvents
                {
                    OnRemoteFailure = RemoteFailure,
                },
                ResponseType = OpenIdConnectResponseType.IdToken,

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                },
            };
        }

        // Used for avoiding yellow-screen-of-death
        private Task RemoteFailure(FailureContext context)
        {
            context.HandleResponse();
            if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
            {
                context.Response.Redirect("/");
            }
            else
            {
                context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
            }

            return Task.FromResult(0);
        }

    }
}
