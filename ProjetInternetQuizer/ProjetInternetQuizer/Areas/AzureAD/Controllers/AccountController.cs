using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using ProjetInternetQuizer.Controllers;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace ProjetInternetQuizer.Areas.AzureAD.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult SignIn()
        {
            var redirectUrl = Url.Action(nameof(HomeController.Index), "Home");
            return Challenge(
                new AuthenticationProperties { RedirectUri = redirectUrl, AllowRefresh = true },
                OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpGet]
        public async Task SignOut()
        {
            if (User.Identity.IsAuthenticated)
            {
                await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
            }
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}