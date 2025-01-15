namespace KeycloakSamlAuth.Controllers
{
    using ITfoxtec.Identity.Saml2;
    using ITfoxtec.Identity.Saml2.MvcCore;
    using ITfoxtec.Identity.Saml2.Schemas;
    using KeycloakSamlAuth.Identity;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Mvc;
    using System.Diagnostics;
    using System.Security.Authentication;

    [AllowAnonymous]
    public class AuthController : Controller
    {
        const string _relayStateReturnUrl = "returnUrl";
        private readonly Saml2Configuration _config;

        public AuthController(Saml2Configuration config)
        {
            _config = config;
        }

        public IActionResult Login(string returnUrl)
        {
            var binding = new Saml2PostBinding();          
            binding.SetRelayStateQuery(new Dictionary<string, string> { { _relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });
            var authnReq = new Saml2AuthnRequest(_config);
            return binding.Bind(authnReq).ToActionResult();
        }

        [HttpPost]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var saml2AuthnResponse = new Saml2AuthnResponse(_config);

            httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(_relayStateReturnUrl) ? relayStateQuery[_relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }


        [HttpPost]
        public IActionResult LoggedOut()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            httpRequest.Binding.Unbind(httpRequest, new Saml2LogoutResponse(_config));

            return Redirect(Url.Content("~/"));
        }

        [HttpPost("logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(_config, User).DeleteSession(HttpContext);
            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }
    }

}
