using System;
using System.Web.Mvc;
using Devkeydet;

namespace OAuthMvc.Controllers
{
    public class OAuthRedirectController : Controller
    {
        // GET: OAuthRedirect
        public ActionResult Index(string code, string error, string error_description, string resource, string state)
        {
            var returnUrl = OAuthHelper.ProcessAccessTokenAndGetReturnUrl(code, error, error_description, state);

            return Redirect(returnUrl);
        }
    }
}