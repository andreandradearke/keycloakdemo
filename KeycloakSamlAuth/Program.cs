namespace KeycloakSamlAuth
{
    using ITfoxtec.Identity.Saml2;
    using ITfoxtec.Identity.Saml2.MvcCore;
    using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
    using ITfoxtec.Identity.Saml2.Schemas.Metadata;
    using ITfoxtec.Identity.Saml2.Util;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Logging;
    using System.IO;

    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>();
    }
}
