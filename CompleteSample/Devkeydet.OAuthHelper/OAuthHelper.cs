using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Security.Claims;
using System.Web;
using System.Web.SessionState;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Devkeydet
{
    public static class OAuthHelper
    {
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The App Key is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        private const string CachePrefix = "WindowsAzureAdCache#";
        private static readonly string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string AppKey = ConfigurationManager.AppSettings["ida:AppKey"];
        private static readonly string AadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static readonly string ResourceId = ConfigurationManager.AppSettings["ida:ResourceId"];

        private static HttpSessionState _session;
        private static HttpRequest _request;

        public static HttpSessionState Session
        {
            get
            {
                if (_session != null)
                {
                    return _session;
                }

                _session = HttpContext.Current.Session;
                return _session;
            }
            set { _session = value; }
        }

        private static HttpRequest Request
        {
            get
            {
                if (_request != null)
                {
                    return _request;
                }

                _request = HttpContext.Current.Request;
                return _request;
            }
// ReSharper disable once UnusedMember.Local
            set { _request = value; }
        }

// ReSharper disable once InconsistentNaming
        public static string ProcessAccessTokenAndGetReturnUrl(string code, string error, string error_description, string state)
        {
            //
            // NOTE: In production, OAuth must be done over a secure HTTPS connection.
            //
            if (Request.Url.Scheme != "https" && !Request.Url.IsLoopback)
            {
                //TODO: Throw a better exception
                throw new Exception("Must be https");
            }

            //
            // Ensure there is a state value on the request.  If there is none, stop OAuth processing and display an error.
            //
            if (state == null)
            {
                //TODO: Throw a better exception
                throw new Exception("Did not receive state query string parameter");
            }

            //
            // Ensure the saved state value matches the value from the response.  If it does not, stop OAuth processing and display an error.
            //
            if (!FindOAuthStateInCache(state))
            {
                RemoveOAuthStateFromCache(state);
                //TODO: Throw a better exception
                throw new Exception("state parameter was not the expected value");
            }

            RemoveOAuthStateFromCache(state);

            //
            // Handle errors from the OAuth response, if any.  If there are errors, stop OAuth processing and display an error.
            //
            if (error != null)
            {
                //TODO: Throw a better exception
                throw new Exception("OAuth response contained an error: " + Request.QueryString["error_description"]);
            }

            //
            // Redeem the authorization code from the response for an access token and refresh token.
            //
            var credential = new ClientCredential(ClientId, AppKey);
            var authority = string.Format(CultureInfo.InvariantCulture, AadInstance, "common");
            var authContext = new AuthenticationContext(authority);
            var redirectUrl = Request.Url.GetLeftPart(UriPartial.Authority) + ConfigurationManager.AppSettings["ida:OAuthRedirect"];
            var result = authContext.AcquireTokenByAuthorizationCode(code, new Uri(redirectUrl), credential);

            // Cache the access token and refresh token
            SaveAccessTokenInCache(ResourceId, result.AccessToken, (result.ExpiresOn.AddMinutes(-5)).ToString());
            SaveRefreshTokenInCache(result.RefreshToken);

            // Also save the Tenant ID for later use when calling the Graph API.
            SaveInCache("TenantId", result.TenantId);

            // Return to the originating page where the user triggered the sign-in
            var redirectTo = (Uri) GetFromCache("RedirectTo");
            // BUGBUG Removing the RedirectTo will cause multiple outstanding requests to fail.  It would be better if this was carried on the request URL somehow.
            // RemoveFromCache("RedirectTo");
            return redirectTo.ToString();
        }

        public static string GetAuthorizationUrl(string resourceId, HttpRequest request, string redirectUrl)
        {
            // To prevent Cross-Site Request Forgery attacks (http://tools.ietf.org/html/rfc6749 section 4.2.1),
            //     it is important to send a randomly-generated value as a state parameter.
            // This state parameter is saved in a cookie, so it can later be compared with the state
            //     parameter that we receive from the Authorization Server along with the Authorization Code.
            // The state cookie will also capture information about the resource ID and redirect-to URL,
            //     for use in the Index method (after the login page redirects back to this controller).
            var stateValue = Guid.NewGuid().ToString();

            AddOAuthStateToCache(stateValue);

            var authorizeUrl = string.Format(
                CultureInfo.InvariantCulture,
                AadInstance,
                "common/oauth2/authorize?response_type=code&client_id={0}&resource={1}&redirect_uri={2}&state={3}");

            // Construct the authorization request URL.
            return String.Format(CultureInfo.InvariantCulture,
                authorizeUrl,
                Uri.EscapeDataString(ClientId),
                Uri.EscapeDataString(resourceId),
                Uri.EscapeDataString(redirectUrl),
                Uri.EscapeDataString(stateValue));
        }

        public static string GetAccessTokenFromCacheOrRefreshToken()
        {
            var tenantId =
                ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            var token = GetAccessTokenFromCacheOrRefreshToken(tenantId, ResourceId);

            //
            // If the user doesn't have an access token, they need to re-authorize.
            //
            if (token == null)
            {
                //
                // The user needs to re-authorize.  Show them a message to that effect.
                // If the user still has a valid session with Azure AD, they will not be prompted for their credentials.
                //

                // Remember where to bring the user back to in the application after the authorization code response is handled.
                SaveInCache("RedirectTo", Request.Url);
            }

            return token;
        }

        public static string GetAuthorizationUrl(string redirectUrl)
        {
            return GetAuthorizationUrl(ResourceId, Request, redirectUrl);
        }

        public static string GetAuthorizationUrl()
        {
            var redirectUrl = Request.Url.GetLeftPart(UriPartial.Authority) + ConfigurationManager.AppSettings["ida:OAuthRedirect"];
            return GetAuthorizationUrl(ResourceId, Request, redirectUrl);
        }

        public static string GetAccessTokenFromCacheOrRefreshToken(string tenantId, string resourceId)
        {
            //
            // First try to get an access token for this resource from the cookie-based cache.
            // If there is no AT in the cache for this resource, see if there is a refresh token in the cache that can be used to get a new access token.
            // If all fails, return null signalling the caller to do the OAuth redirect.
            //
            var accessToken = (string) GetAccessTokenFromCache(resourceId);

            if (accessToken != null) return accessToken;

            accessToken = GetAccessTokenFromRefreshToken(tenantId, resourceId);

            if (accessToken != null) return accessToken;

            return null;
        }

        public static string GetAccessTokenFromRefreshToken(string tenantId, string resourceId)
        {
            //
            // Try to get a new access token for this resource using a refresh token.
            // If this fails, return null signalling the caller to do the OAuth redirect.
            //

            //
            // Fetch the refresh token from the cache
            //
            var refreshToken = (string) GetRefreshTokenFromCache();
            if (refreshToken == null)
            {
                //
                // No refresh token - the caller will need to send the user to get an auth code.  Return null.
                //
                return null;
            }

            try
            {
                //
                // Redeem the refresh token for an access token
                //
                var clientcred = new ClientCredential(ClientId, AppKey);
                var authority = string.Format(AadInstance, tenantId);
                var authcontext = new AuthenticationContext(authority);
                var result = authcontext.AcquireTokenByRefreshToken(refreshToken, ClientId, clientcred, resourceId);

                //
                // Save the authorization header for this resource and the refresh token in separate cookies
                //
                SaveAccessTokenInCache(resourceId, result.AccessToken, (result.ExpiresOn.AddMinutes(-5)).ToString());
                SaveRefreshTokenInCache(result.RefreshToken);

                return result.AccessToken;
            }
            catch
            {
                //
                // If the refresh token is also expired, remove it from the cache, and send the user off to do a new OAuth auth code request
                //
                RemoveRefreshTokenFromCache();

                return null;
            }
        }

        //
        // This sample uses ASP.Net session state to cache access tokens and refresh tokens for the user.
        // You can also cache these tokens in a database, keyed to the user's identity.
        // If cached in a database, the tokens can be stored across user sessions, and can be used when the user isn't present.
        //

        public static void SaveAccessTokenInCache(string resourceId, object value, object expiration)
        {
            Session[CachePrefix + "AccessToken#" + resourceId] = value;
            Session[CachePrefix + "AccessTokenExpiration#" + resourceId] = expiration;
        }

        public static object GetAccessTokenFromCache(string resourceId)
        {
            var accessToken = (string) Session[CachePrefix + "AccessToken#" + resourceId];

            if (accessToken != null)
            {
                var expiration =
                    (string) Session[CachePrefix + "AccessTokenExpiration#" + resourceId];
                var expirationTime = Convert.ToDateTime(expiration);

                if (expirationTime < DateTime.Now)
                {
                    RemoveAccessTokenFromCache(resourceId);
                    accessToken = null;
                }
            }

            return accessToken;
        }

        public static void RemoveAccessTokenFromCache(string resourceId)
        {
            Session.Remove(CachePrefix + "AccessToken#" + resourceId);
            Session.Remove(CachePrefix + "AccessTokenExpiration#" + resourceId);
        }

        public static void SaveRefreshTokenInCache(object value)
        {
            Session[CachePrefix + "RefreshToken"] = value;
        }

        public static object GetRefreshTokenFromCache()
        {
            return Session[CachePrefix + "RefreshToken"];
        }

        public static void RemoveRefreshTokenFromCache()
        {
            Session.Remove(CachePrefix + "RefreshToken");
        }

        public static void AddOAuthStateToCache(object value)
        {
            var currentTime = DateTime.Now;
            var expiration = currentTime.AddMinutes(10).ToString(CultureInfo.InvariantCulture);
            var currentTimeString = currentTime.ToString(CultureInfo.InvariantCulture);

            Session[CachePrefix + "OAuthState#" + currentTimeString] = value;
            Session[CachePrefix + "OAuthStateExpiration#" + currentTimeString] = expiration;
        }

        public static bool FindOAuthStateInCache(string state)
        {
            //
            // First, remove any old outstanding state values that have expired.
            //
            foreach (var sessionObject in Session)
            {
                var sessionName = (string) sessionObject;
                if (sessionName.StartsWith(CachePrefix + "OAuthStateExpiration#"))
                {
                    var expiration = Convert.ToDateTime(Session[sessionName]);
                    if (expiration < DateTime.Now)
                    {
                        // First, find the timestamp value in the session name.
                        var index = sessionName.LastIndexOf("#", StringComparison.Ordinal);
                        var timeStamp = sessionName.Substring(index + 1);

                        // Then, remove the corresponding OAuthState and Expiration values.
                        Session.Remove(CachePrefix + "OAuthState#" + timeStamp);
                        Session.Remove(CachePrefix + "OAuthStateExpiration#" + timeStamp);
                    }
                }
            }

            //
            // Finally, look for a corresponding state value, and if found, return true.
            //
// ReSharper disable once LoopCanBeConvertedToQuery
            foreach (var sessionObject in Session)
            {
                var sessionName = (string) sessionObject;
                if (sessionName.StartsWith(CachePrefix + "OAuthState#"))
                {
                    if ((string) Session[sessionName] == state) return true;
                }
            }

            return false;
        }

        public static void RemoveOAuthStateFromCache(string state)
        {
            foreach (var sessionObject in Session)
            {
                var sessionName = (string) sessionObject;
                if (sessionName.StartsWith(CachePrefix + "OAuthState#"))
                {
                    if ((string) Session[sessionName] == state)
                    {
                        // Find the timestamp value in the session name.
                        var index = sessionName.LastIndexOf("#", StringComparison.Ordinal);
                        var timeStamp = sessionName.Substring(index + 1);
                        Session.Remove(CachePrefix + "OAuthState#" + timeStamp);
                        Session.Remove(CachePrefix + "OAuthStateExpiration#" + timeStamp);
                        return;
                    }
                }
            }
        }

        public static void SaveInCache(string name, object value)
        {
            Session[CachePrefix + name] = value;
        }

        public static object GetFromCache(string name)
        {
            return Session[CachePrefix + name];
        }

        public static void RemoveFromCache(string name)
        {
            Session.Remove(CachePrefix + name);
        }

        public static void RemoveAllFromCache()
        {
            var keysToRemove = new List<string>();
// ReSharper disable once LoopCanBeConvertedToQuery
            foreach (var session in Session)
            {
                var sessionName = (string) session;
                if (sessionName.StartsWith(CachePrefix, StringComparison.Ordinal))
                {
                    keysToRemove.Add(sessionName);
                }
            }

            foreach (var key in keysToRemove)
            {
                Session.Remove(key);
            }
        }
    }
}