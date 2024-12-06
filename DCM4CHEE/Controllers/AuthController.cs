using DCM4CHEE.Helper;
using DCM4CHEE.Models;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace DCM4CHEE.Controllers
{
    [Route("Auth")]
    public class AuthController : Controller
    {
        private const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;
        private readonly AppSettings _appSettings;

        public AuthController(IOptions<Saml2Configuration> configAccessor, AppSettings appSettings)
        {
            config = configAccessor.Value;
            _appSettings = appSettings;
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

            var relayState = HttpUtility.UrlDecode(binding.RelayState);
            Uri.TryCreate(relayState, UriKind.RelativeOrAbsolute, out Uri relayStateUri);
            if (relayStateUri != null && relayStateUri.IsAbsoluteUri)
            {
                var session_token = saml2AuthnResponse.ClaimsIdentity.Claims.Where(c => c.Type == Saml2ClaimTypes.SessionIndex).FirstOrDefault().Value;
                var login_hint = saml2AuthnResponse.ClaimsIdentity.Claims.Where(c => c.Type == Saml2ClaimTypes.NameId).FirstOrDefault().Value;

                //var url = $"{relayStateUri.AbsoluteUri}" +
                //    $"?session_token={session_token}" +
                //    $"&login_hint={login_hint}";

                var url = relayStateUri.AbsoluteUri;

                return Redirect(url);
            }

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
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

        //[Route("GoToSP")]
        //[Authorize]
        //public IActionResult GoToSP()
        //{
        //    var email = User.Claims.Where(f => f.Type == Saml2ClaimTypes.NameId).Select(s => s.Value).FirstOrDefault();

        //    //var url = $"{_appSettings.SurgicalPreviewAppUrl}" +
        //    //    $"?sso_login={true}" +
        //    //    $"&login_hint={email}" +
        //    //    $"&idp_name=DCM4CHEE Local Saml IdP";

        //    var url = $"{_appSettings.SurgicalPreviewAppUrl}" +
        //        $"?hospital_name=DCM4CHEE Local Saml IdP";

        //    var url1 = "https://localhost:44325/Home/Index?hospital_name=Pacs SAML IdP";

        //    //var url = "https://localhost:44349/api/sso?name=DCM4CHEE SAML IdP";
        //    //var url = "https://localhost:44349/api/sso?name=DCM4CHEE Local Saml IdP";

        //    return Redirect(url);
        //}
    }
}
