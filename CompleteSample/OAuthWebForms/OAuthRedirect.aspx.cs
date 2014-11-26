using System;
using Devkeydet;

namespace OAuthWebForms
{
    public partial class OAuth : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string code = Request.QueryString["code"];
            string error = Request.QueryString["error"];
// ReSharper disable once InconsistentNaming
            string error_description = Request.QueryString["error_description"];
            string state = Request.QueryString["state"];

            var returnUrl = OAuthHelper.ProcessAccessTokenAndGetReturnUrl(code, error, error_description, state);

            Response.Redirect(returnUrl);
        }
    }
}