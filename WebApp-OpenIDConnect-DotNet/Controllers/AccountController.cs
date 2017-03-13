using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public async Task SignUpSignIn()
        {
            if (HttpContext.User == null || !HttpContext.User.Identity.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                await HttpContext.Authentication.ChallengeAsync(authenticationProperties);
            }
        }

        [HttpGet]
        public async Task EditProfile()
        {
            if (HttpContext.User == null || HttpContext.User.Identity.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                HttpContext.Items["policy"] = Startup.EditProfilePolicyId;
                await HttpContext.Authentication.ChallengeAsync(
                    OpenIdConnectDefaults.AuthenticationScheme, authenticationProperties,
                     ChallengeBehavior.Unauthorized);
            }
        }

        [HttpGet]
        public async Task ResetPassword()
        {
            if (HttpContext.User == null || HttpContext.User.Identity.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                HttpContext.Items["policy"] = Startup.ResetPasswordPolicyId;
                await HttpContext.Authentication.ChallengeAsync(
                    OpenIdConnectDefaults.AuthenticationScheme, authenticationProperties,
                     ChallengeBehavior.Unauthorized);
            }
        }

        public async Task SignOut()
        {
            if (HttpContext.User != null && HttpContext.User.Identity.IsAuthenticated)
            {

                await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.Authentication.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
            }
        }
    }
}
