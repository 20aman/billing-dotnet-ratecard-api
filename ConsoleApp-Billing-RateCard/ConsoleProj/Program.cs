using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net;
using System.IO;
using Microsoft.Azure.Documents;
using Microsoft.Azure.Documents.Client;
using Microsoft.Azure.Documents.Linq;
using Newtonsoft.Json;
using System.Configuration;
using System.Security.Cryptography.X509Certificates; //BL

namespace ARMAPI_Test
{
#error Please update the appSettings section in app.config, then remove this statement

    class Program
    {
        //This is a sample console application that shows you how to grab a User token from AAD for the current user of the app
        //The same caveat remains, that the current user of the app needs to be part of either the Owner, Reader or Contributor role for the requested AzureSubID.
        static void Main(string[] args)
        {
            //Get the AAD User token to get authorized to make the call to the Usage API
            string token = GetOAuthTokenFromAAD();

            /*Setup API call to RateCard API
             Callouts:
             * See the App.config file for all AppSettings key/value pairs
             * You can get a list of offer numbers from this URL: http://azure.microsoft.com/en-us/support/legal/offer-details/
             * You can configure an OfferID for this API by updating 'MS-AZR-{Offer Number}'
             * The RateCard Service/API is currently in preview; please use 2016-06-01-preview for api-version
             */

            // Build up the HttpWebRequest
            string requestURL = String.Format("{0}/{1}/{2}/{3}",
                       ConfigurationManager.AppSettings["ARMBillingServiceURL"],
                       "subscriptions",
                       ConfigurationManager.AppSettings["SubscriptionID"],
                       "providers/Microsoft.Commerce/RateCard?api-version=2015-06-01-preview&$filter=OfferDurableId eq 'MS-AZR-0121p' and Currency eq 'USD' and Locale eq 'en-US' and RegionInfo eq 'US'");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(requestURL);

            // Add the OAuth Authorization header, and Content Type header
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + token);
            request.ContentType = "application/json";

            // Call the RateCard API, dump the output to the console window
            try
            {
                // Call the REST endpoint
                Console.WriteLine("Calling RateCard service...");
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Console.WriteLine(String.Format("RateCard service response status: {0}", response.StatusDescription));
                Stream receiveStream = response.GetResponseStream();

                // Pipes the stream to a higher level stream reader with the required encoding format. 
                StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8);
                var rateCardResponse = readStream.ReadToEnd();
                Console.WriteLine("RateCard stream received.  Press ENTER to continue with raw output.");
                Console.ReadLine();
                Console.WriteLine(rateCardResponse);
                Console.WriteLine("Raw output complete.  Press ENTER to continue with JSON output.");
                Console.ReadLine();

                // Convert the Stream to a strongly typed RateCardPayload object.  
                // You can also walk through this object to manipulate the individuals member objects. 
                RateCardPayload payload = JsonConvert.DeserializeObject<RateCardPayload>(rateCardResponse);

                #region Uncomment and Use this region to search for a meter ID
                ////Dynamically populate your Meter ID
                //string meterId = "";

                ////Iterating over all the meters
                //foreach (var meter in payload.Meters)
                //{
                //    if (meter.MeterId == meterId)
                //    {
                //        //you can access the meter information here
                //        //Console.WriteLine(meter.MeterCategory);
                //    }
                //}
                #endregion

                Console.WriteLine(rateCardResponse.ToString());
                response.Close();
                readStream.Close();
                Console.WriteLine("JSON output complete.  Press ENTER to close.");
                Console.ReadLine();
            }
            catch(Exception e)
            {
                Console.WriteLine(String.Format("{0} \n\n{1}", e.Message, e.InnerException != null ? e.InnerException.Message : ""));
                Console.ReadLine();
            }
        }


        public static string GetOAuthTokenFromAAD()
        {
            var authenticationContext = new AuthenticationContext(  String.Format("{0}/{1}",
                                                                    ConfigurationManager.AppSettings["ADALServiceURL"],
                                                                    ConfigurationManager.AppSettings["TenantDomain"]));

            //Ask the logged in user to authenticate, so that this client app can get a token on his behalf
            var result = authenticationContext.AcquireToken(String.Format("{0}/",ConfigurationManager.AppSettings["ARMBillingServiceURL"]),
                                                            ConfigurationManager.AppSettings["ClientID"],
                                                            new Uri(ConfigurationManager.AppSettings["ADALRedirectURL"]));

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            return result.AccessToken;
        }

        /// <summary>
        /// Method 2 - Fetches the Azure Authentication Token From Azure Active Directory using credentials
        /// Note: For this method to work follow the section "Authenticate with password - PowerShell" from the below URL
        /// https://azure.microsoft.com/en-us/documentation/articles/resource-group-authenticate-service-principal/
        /// </summary>
        /// <param name="TenanatID">Tenanat ID from your Azure Subscription</param>
        /// <param name="ClientID">GUID for AAD application configured as Native Client App in AAD tenant specified above</param>
        /// <param name="Password">Password configured for Service Principal</param>
        /// <returns>Authentication Token</returns>
        public static string GetOAuthTokenFromAAD_ByCredentials(string TenanatID, string ClientID, string Password)
        {
            //Creating the variable for result
            string token = string.Empty;

            //Creating the Authentication Context
            var authenticationContext = new AuthenticationContext("https://login.windows.net/" + TenanatID);
            //Creating Credentials
            var credential = new ClientCredential(clientId: ClientID, clientSecret: Password);
            //Fetching Token from Azure AD
            var result = authenticationContext.AcquireToken(resource: "https://management.core.windows.net/", clientCredential: credential);

            //Checking if data recieved from Azure AD
            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            //Getting token
            token = result.AccessToken;

            //Returning the token
            return token;
        }

        /// <summary>
        /// Method 3 - Fetches the Azure Authentication Token From Azure Active Directory using a Certificate
        /// Note: For this method to work follow the section "Authenticate with certificate - PowerShell" from the below URL
        /// https://azure.microsoft.com/en-us/documentation/articles/resource-group-authenticate-service-principal/
        /// </summary>
        /// <param name="TenanatID">Tenanat ID from your Azure Subscription</param>
        /// <param name="ClientID">GUID for AAD application configured as Native Client App in AAD tenant specified above</param>
        /// <param name="CertificateName">Name of certificate. This should be in your local user store on the computer where this tool is run.</param>
        /// <returns>Authentication Token</returns>
        public static string GetOAuthTokenFromAAD_ByCertificate(string TenanatID, string ClientID, string CertificateName)
        {
            //Creating the Authentication Context
            var authContext = new AuthenticationContext(string.Format("https://login.windows.net/{0}", TenanatID));

            //Creating the certificate object. This will be used to authenticate
            X509Certificate2 cert = null;

            //The Certificate should be already installed in personal store of the current user under 
            //the context of which the application is running.
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                //Trying to open and fetch the certificate
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates;
                var certs = certCollection.Find(X509FindType.FindBySubjectName, CertificateName, false);
                //Checking if certificate found
                if (certs == null || certs.Count <= 0)
                {
                    //Throwing error if certificate not found
                    throw new Exception("Certificate " + CertificateName + " not found.");
                }
                cert = certs[0];
            }
            finally
            {
                //Closing the certificate store
                store.Close();
            }

            //Creating Client Assertion Certificate object
            var certCred = new ClientAssertionCertificate(ClientID, cert);

            //Fetching the actual token for authentication of every request from Azure using the certificate
            var token = authContext.AcquireToken("https://management.core.windows.net/", certCred);

            //Optional steps if you need more than just a token from Azure AD
            //var creds = new TokenCloudCredentials(subscriptionId, token.AccessToken);
            //var client = new ResourceManagementClient(creds); 

            //Returning the token
            return token.AccessToken;
        }
    }
}

