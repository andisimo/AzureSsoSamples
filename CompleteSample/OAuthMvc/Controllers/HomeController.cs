using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Web.Mvc;
using Devkeydet;

namespace OAuthMvc.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var accessToken = OAuthHelper.GetAccessTokenFromCacheOrRefreshToken();

            // If we don't have the access or refresh token cached, then we need to redirect to AAD to get a token THIS APP can use
            if (accessToken == null)
            {
                return Redirect(OAuthHelper.GetAuthorizationUrl());
            }

            // Use token to make web service calls

            var resourceId = ConfigurationManager.AppSettings["ida:ResourceId"];

            // A URL for an CRM OData query (http get)
            var odataSvc = resourceId + "/XRMServices/2011/OrganizationData.svc";
            var odataQueryUrl = odataSvc + "/AccountSet";

            // Build and send the raw HTTP request.
            var webClient = new WebClient();
            webClient.Headers[HttpRequestHeader.Authorization] = "Bearer " + accessToken;
            // ReSharper disable once UnusedVariable
            var downloadString = webClient.DownloadString(new Uri(odataQueryUrl));  // would normally do something with this data

            // No .NET developer who knows OData wants to program low level HTTP calls, so let's use LINQ to OData
            // USING THE TOKEN TO EXECUTE AN ODATA QUERY USING Visual Studio / .NET tooling / libraries for OData
            var dsContext = new DkdtLeoServiceReference.dkdtleoContext(new Uri(odataSvc));

            dsContext.SendingRequest2 += (s, a) => a.RequestMessage.SetHeader("Authorization", "Bearer " + accessToken);

            // NOTE that we get LINQ query capability
            var query = from a in dsContext.AccountSet
                        where a.Name.Contains("sample")
                        select a;

            // NOTE that we get productive early bound types, materialized from the raw payload, thanks to Visual Studio / .NET tooling / libraries for OData
            List<DkdtLeoServiceReference.Account> results = query.ToList(); // would normally do something with this data

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}