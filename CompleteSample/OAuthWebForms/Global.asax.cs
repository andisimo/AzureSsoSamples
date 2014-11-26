using System;
using System.IdentityModel.Services;
using System.Web;
using System.Web.Optimization;
using System.Web.Routing;
using Devkeydet;

namespace OAuthWebForms
{
    public class Global : HttpApplication
    {
        void Application_Start(object sender, EventArgs e)
        {
            // Code that runs on application startup
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            IdentityConfig.ConfigureIdentity();
        }

// ReSharper disable once UnusedMember.Local
// ReSharper disable once UnusedParameter.Local
        void WSFederationAuthenticationModule_RedirectingToIdentityProvider(object sender, RedirectingToIdentityProviderEventArgs e)
        {
            if (!String.IsNullOrEmpty(IdentityConfig.Realm))
            {
                e.SignInRequestMessage.Realm = IdentityConfig.Realm;
            }
        }
    }
}