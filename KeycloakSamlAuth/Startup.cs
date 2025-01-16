using System;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Util;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Hosting;
using System.Net.Http;
using Microsoft.IdentityModel.Logging;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Azure.Storage.Blobs;

namespace KeycloakSamlAuth
{
    public class Startup
    {
        public static IWebHostEnvironment AppEnvironment { get; private set; }

        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            AppEnvironment = env;
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;
            string configKey = "Saml2";
            services.BindConfig<Saml2Configuration>(Configuration, configKey, (serviceProvider, saml2Configuration) =>
            {
                // Load signing certificate
                
                if (AppEnvironment.IsEnvironment("Local"))
                {
                    saml2Configuration.SigningCertificate = CertificateUtil.Load(
                        AppEnvironment.MapToPhysicalFilePath(Configuration[$"{configKey}:CertificateFile"]),
                        Configuration[$"{configKey}:CertificatePassword"]
                    );
                }
                else
                {
                    string connectionString = Configuration[$"{configKey}:BlobStorage"];
                    string containerName = "kcdemo";
                    string blobName = "kcdemo_keystore.p12";
                    BlobServiceClient blobServiceClient = new BlobServiceClient(connectionString);
                    BlobClient blobClient = blobServiceClient.GetBlobContainerClient(containerName).GetBlobClient(blobName);
                    string signingCertificatePath = blobClient.Uri.AbsolutePath;

                    using (var ms = new MemoryStream())
                    {
                        blobClient.DownloadTo(ms);
                        byte[] certificate = ms.ToArray();
                        saml2Configuration.SigningCertificate = X509CertificateLoader.LoadPkcs12(
                            certificate,
                            Configuration[$"{configKey}:CertificatePassword"]
                        );
                    }


                }

                saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

                var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadIdPSsoDescriptorFromUrlAsync(httpClientFactory, new Uri(Configuration["Saml2:IdpMetadataUrl"])).GetAwaiter().GetResult();
                if (entityDescriptor.IdPSsoDescriptor != null)
                {
                    saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                    saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                    saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                    foreach (var signingCertificate in entityDescriptor.IdPSsoDescriptor.SigningCertificates)
                    {
                        if (signingCertificate.IsValidLocalTime())
                        {
                            saml2Configuration.SignatureValidationCertificates.Add(signingCertificate);
                        }
                    }

                    if (!saml2Configuration.SignatureValidationCertificates.Any())
                    {
                        throw new Exception("No valid signing certificates found in IdP metadata.");
                    }

                    if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                    {
                        saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
                    }                    
                }
                else
                {
                    throw new Exception("IdPSsoDescriptor not loaded from metadata.");
                }
                
                return saml2Configuration;
            });

            services.AddSaml2(slidingExpiration: true);
            services.AddHttpClient();
            services.AddControllersWithViews();
        }


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSaml2();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
