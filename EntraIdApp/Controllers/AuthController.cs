using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using SamlSSO.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace EntraIdApp.Controllers
{
    [Route("Auth")]
    public class AuthController : Controller
    {
        public IConfiguration Configuration { get; }
        private const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(IConfiguration configuration, IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
            Configuration = configuration;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("ACS")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            if (returnUrl == "app_desktop")
            {
                var sessionIndex = saml2AuthnResponse.SessionIndex;
                var userName = saml2AuthnResponse.NameId.Value;
                var displayName = saml2AuthnResponse.ClaimsIdentity.Claims.Where(f => f.Type == "http://schemas.microsoft.com/identity/claims/displayname").Select(s => s.Value).FirstOrDefault();

                return RedirectToAction("AppLoginSuccess", "Auth", new { auth_device = returnUrl, session_index = sessionIndex, user_name = userName, display_name = displayName });
            }
            else
            {
                return Redirect(returnUrl);
            }
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return Redirect("~/");
        }



        [Route("AppLogin")]
        public IActionResult AppLogIn(string auth_device)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, auth_device ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("AppLoginSuccess")]
        public IActionResult AppLoginSuccess(string auth_device, string session_index, string user_name, string display_name)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                RegistryKey key = Registry.ClassesRoot.CreateSubKey("HospitalPacs");
                key.SetValue("", "URL:HospitalPacs");
                key.SetValue("URL Protocol", "");

                RegistryKey shell = key.CreateSubKey(@"shell\open\command");
                shell.SetValue("", $"{Configuration["Saml2:HospitalPacsDesktopAppLocation"]} %1");
            }

            ViewBag.AuthDevice = auth_device;
            ViewBag.SessionIndex = session_index;
            ViewBag.UserName = user_name;
            ViewBag.DisplayName = display_name;

            return View();
        }
    }
}
