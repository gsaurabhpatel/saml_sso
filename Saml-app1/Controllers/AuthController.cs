using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Saml_app1.Helper;
using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Threading.Tasks;
using System.Web;

namespace Saml_app1.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "https://localhost:44341";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("AssertionConsumerService")]
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

            //var relayState = HttpUtility.UrlDecode(binding.RelayState);
            //Uri relayStateUri;
            //Uri.TryCreate(relayState, UriKind.RelativeOrAbsolute, out relayStateUri);
            //if (relayStateUri != null && relayStateUri.IsAbsoluteUri)
            //{
            //    return Redirect(relayStateUri.AbsoluteUri);
            //}
            //else if (relayStateUri != null && !relayStateUri.IsAbsoluteUri)
            //{
            //    string uri = $"https://rapidai-poc.okta.com{relayStateUri}";
            //    var okta_key = HttpUtility.ParseQueryString(new Uri(uri).Query).Get("okta_key");
            //    string uri1 = $"https://localhost:44319/Account/CompleteSSOLogin?okta_key={okta_key}";
            //    return Redirect(uri1);
            //}

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

        [Route("GoToSP")]
        public IActionResult GoToSP()
        {
            string saml_session_index = string.Empty;
            foreach (var claim in User.Claims)
            {
                if (claim.Type == "http://schemas.itfoxtec.com/ws/2014/02/identity/claims/saml2sessionindex")
                {
                    saml_session_index = claim.Value;
                }
            }

            var uri = $"https://localhost:44391" +
                $"?sso_login=true" +
                $"&session_index={saml_session_index}" +
                $"&sso_login_hint={User.Identity.Name}";

            return this.Redirect(uri);
        }

        //[Route("GoToSP")]
        //public IActionResult GoToSP()
        //{
        //    //string clientId = "0oainjnz1yMbF35s6697";
        //    //string responseType = "id_token";
        //    //string responseMode = "form_post";
        //    //string scopes = "openid email profile EndoVantage";
        //    //string redirectUri = "https://localhost:44341/Auth/SSOCallback";
        //    //string state = Guid.NewGuid().ToString("N");
        //    //string nonce = Guid.NewGuid().ToString("N");

        //    //string uri = $"https://rapidai-poc.okta.com/oauth2/ausjbqlsb59tirj6U697/v1/authorize" +
        //    //    $"?idp=0oaldu8a15Aaw8JKO697" +
        //    //    $"&client_id={clientId}" +
        //    //    $"&response_type={responseType}" +
        //    //    $"&response_mode={responseMode}" +
        //    //    $"&scope={scopes}" +
        //    //    $"&redirect_uri={redirectUri}" +
        //    //    $"&state={state}" +
        //    //    $"&nonce={nonce}";

        //    //return this.Redirect(uri);
        //}

        //[Route("SSOCallback")]
        //public IActionResult SSOCallback()
        //{
        //    var state = this.HttpContext.Request.Form["state"];
        //    var nonce = this.HttpContext.Request.Form["nonce"];
        //    var id_token = this.HttpContext.Request.Form["id_token"];

        //    return null;
        //}
    }
}
