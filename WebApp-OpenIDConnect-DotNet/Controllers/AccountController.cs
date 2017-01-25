﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    public class AccountController : Controller
    {
        public async Task SignUp()
        {
            if (HttpContext.User == null || !HttpContext.User.Identity.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                await HttpContext.Authentication.ChallengeAsync(Startup.SignUpPolicyId.ToLower(), authenticationProperties);
            }
        }

        public async Task SignIn()
        {
            if (HttpContext.User == null || !HttpContext.User.Identity.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                await HttpContext.Authentication.ChallengeAsync(Startup.SignInPolicyId.ToLower(), authenticationProperties);
            }
        }

        public async Task SignOut()
        {
            if (HttpContext.User != null && HttpContext.User.Identity.IsAuthenticated)
            {
                // try to find the tfp policy id claim (default)
                var scheme = (HttpContext.User.FindFirst("tfp"))?.Value;

                // fall back to legacy acr policy id claim
                if (string.IsNullOrEmpty(scheme))
                    scheme = (HttpContext.User.FindFirst("http://schemas.microsoft.com/claims/authnclassreference"))?.Value;

                await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.Authentication.SignOutAsync(scheme.ToLower(), new AuthenticationProperties { RedirectUri = "/" });
            }

            /*
            var callbackUrl = Url.Action("SignedOut", "Account", values: null, protocol: Request.Scheme);
            return SignOut(new AuthenticationProperties { RedirectUri = callbackUrl },
                CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
            */
        }

        public IActionResult SignedOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                // Redirect to home page if the user is authenticated.
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }
    }
}
