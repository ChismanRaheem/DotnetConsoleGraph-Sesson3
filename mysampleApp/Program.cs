using Microsoft.Identity.Client;
using mysampleApp;
using Newtonsoft.Json.Linq;

internal class Program
{
    private static void Main(string[] args)
    {
        AuthenticationConfig config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");

        IConfidentialClientApplication app;

        app = ConfidentialClientApplicationBuilder.Create(config.ClientId)

        .WithClientSecret(config.ClientSecret)

        .WithAuthority(new Uri(config.Authority))

        .Build();


        //acquire token
        string[] scopes = new string[] { $"{config.ApiUrl}.default" };

        AuthenticationResult result = null;

        try

        {

            result = app.AcquireTokenForClient(scopes).ExecuteAsync().Result;

            Console.ForegroundColor = ConsoleColor.Green;

            Console.WriteLine("Token acquired");

            Console.ResetColor();

        }

        catch (MsalServiceException ex) when (ex.Message.Contains("AADSTS70011"))

        {

            // Invalid scope. The scope has to be of the form "https://resourceurl/.default"

            // Mitigation: change the scope to be as expected

            Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine("Scope provided is not supported");

            Console.ResetColor();

        }

        //Graph api call read all users.
        if (result != null)

        {

            var httpClient = new HttpClient();

            var apiCaller = new ProtectedApiCallHelper(httpClient);

            apiCaller.CallWebApiAndProcessResultASync($"{config.ApiUrl}v1.0/users", result.AccessToken, Display).Wait();

        }
    }

    private static void Display(JObject result)
    {

        foreach (JProperty child in result.Properties().Where(p => !p.Name.StartsWith("@")))

        {

            Console.WriteLine($"{child.Name} = {child.Value}");

        }

    }
}