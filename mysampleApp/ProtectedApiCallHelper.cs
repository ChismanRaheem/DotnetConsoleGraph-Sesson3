using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace mysampleApp
{
    /// <param name="httpClient">HttpClient used to call the protected API</param>
    internal class ProtectedApiCallHelper(HttpClient httpClient)
    {
        protected HttpClient HttpClient { get; private set; } = httpClient;

        /// <summary>

        /// Calls the protected web API and processes the result

        /// </summary>

        /// <param name="webApiUrl">URL of the web API to call (supposed to return Json)</param>

        /// <param name="accessToken">Access token used as a bearer security token to call the web API</param>

        /// <param name="processResult">Callback used to process the result of the call to the web API</param>

        public async Task CallWebApiAndProcessResultASync(string webApiUrl, string accessToken, Action<JObject> processResult)

        {

            if (!string.IsNullOrEmpty(accessToken))

            {

                var defaultRequestHeaders = HttpClient.DefaultRequestHeaders;

                if (defaultRequestHeaders.Accept == null || !defaultRequestHeaders.Accept.Any(m => m.MediaType == "application/json"))

                {

                    HttpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                }

                defaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                HttpResponseMessage response = await HttpClient.GetAsync(webApiUrl);

                if (response.IsSuccessStatusCode)

                {

                    string json = await response.Content.ReadAsStringAsync();

                    JObject? result = JsonConvert.DeserializeObject(json) as JObject;

                    Console.ForegroundColor = ConsoleColor.Gray;

                    processResult(result);

                }

                else

                {

                    Console.ForegroundColor = ConsoleColor.Red;

                    Console.WriteLine($"Failed to call the web API: {response.StatusCode}");

                    string content = await response.Content.ReadAsStringAsync();

                    // Note that if you got reponse.Code == 403 and reponse.content.code == "Authorization_RequestDenied"

                    // this is because the tenant admin as not granted consent for the application to call the Web API

                    Console.WriteLine($"Content: {content}");

                }

                Console.ResetColor();

            }

        }
    }
}
