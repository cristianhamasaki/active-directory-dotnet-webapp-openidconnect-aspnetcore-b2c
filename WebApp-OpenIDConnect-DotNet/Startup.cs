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
        public static string SignUpSignInPolicyId;
        public static string EditProfilePolicyId;
        public static string ResetPasswordPolicyId;
        public static string ClientId;
        public static string PostLogoutRedirectUri;
        public static string AadInstance;
        public static string Tenant;
        public static string ClientSecret;
        public static string ApiUri;
        public static string Scopes;

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
            SignUpSignInPolicyId = Configuration["Authentication:AzureAd:SignUpSignInPolicyId"].ToLower();
            EditProfilePolicyId = Configuration["Authentication:AzureAd:EditProfilePolicyId"].ToLower();
            ResetPasswordPolicyId = Configuration["Authentication:AzureAd:ResetPasswordPolicyId"].ToLower();

            // Web API
            ClientSecret = Configuration["Authentication:AzureAd:ClientSecret"];
            ApiUri = Configuration["Authentication:AzureAd:ApiUri"];
            Scopes = Configuration["Authentication:AzureAd:Scopes"];

            // Configure the OWIN pipeline to use OpenID Connect auth.
            var openIdConnectAuthenticationOptions = new OpenIdConnectOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = string.Format(AadInstance, Tenant, SignUpSignInPolicyId),

                // These are standard OpenID Connect parameters, with values pulled from config.json
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                PostLogoutRedirectUri = PostLogoutRedirectUri,
                Events = new OpenIdConnectEvents
                {
                    OnRemoteFailure = RemoteFailure,
                    OnRedirectToIdentityProvider = RedirectToIdentityProvider,
                    OnTokenResponseReceived = TokenReceived
                },
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                }
            };
            openIdConnectAuthenticationOptions.Scope.Add(OpenIdConnectScope.OpenId);
            foreach(var scope in Scopes.Split(';')) {
                openIdConnectAuthenticationOptions.Scope.Add("https://" + Tenant + "/" + ApiUri + "/" + scope);
            }

            app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private Task TokenReceived(TokenResponseReceivedContext context)
        {
            Console.WriteLine(context.TokenEndpointResponse.AccessToken);
            return Task.FromResult(0);
        }

        private Task RedirectToIdentityProvider(RedirectContext context)
        {
            var policy = context.HttpContext.Items["policy"]?.ToString() ?? string.Empty;
            if (!string.IsNullOrEmpty(policy))
            {
                context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.Replace(SignUpSignInPolicyId, policy);
                context.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
            }
            return Task.FromResult(0);
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