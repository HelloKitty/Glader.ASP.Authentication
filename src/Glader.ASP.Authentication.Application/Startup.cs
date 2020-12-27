using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Glader.ASP.Authentication
{
	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//https://stackoverflow.com/questions/4926676/mono-https-webrequest-fails-with-the-authentication-or-decryption-has-failed
			ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true;
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			ServicePointManager.CheckCertificateRevocationList = false;

			//Don't remember why this is needed, BUT old Auth service had it.
			services.Configure<IISOptions>(options =>
			{
				options.AutomaticAuthentication = false;
			});

			/*services.AddHttpsRedirection(options =>
			{
				options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
				options.HttpsPort = 5001;
			});*/

			services.AddDbContext<GladerIdentityDatabaseContext>(options =>
			{
				options.UseMySql("Server=127.0.0.1;Database=glader.auth.test;Uid=root;Pwd=test;", builder =>
				{
					//Required for external migrations to run.
					builder.MigrationsAssembly(GetType().Assembly.FullName);
				});

				options.UseOpenIddict<int>();
			});

			//Below is the OpenIddict registration
			//This is the recommended setup from the official Github: https://github.com/openiddict/openiddict-core
			services.AddIdentity<GladerIdentityApplicationUser, GladerIdentityApplicationRole>()
				.AddEntityFrameworkStores<GladerIdentityDatabaseContext>()
				.AddDefaultTokenProviders();

			//For some reason I can't figure out how to get the JWT middleware to spit out sub claims
			//so we need to map the Identity to expect nameidentifier

			// Configure Identity to use the same JWT claims as OpenIddict instead
			// of the legacy WS-Federation claims it uses by default (ClaimTypes),
			// which saves you from doing the mapping in your authorization controller.
			services.Configure<IdentityOptions>(options =>
			{
				options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
				options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
				options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;

				//TODO: We should expose these!
				//Password requirements.
				options.Password.RequireDigit = false;
				options.Password.RequiredLength = 1;
				options.Password.RequireUppercase = false;
				options.Password.RequireLowercase = false;
				options.Password.RequireNonAlphanumeric = false;
			});

			services.AddOpenIddict()
				.AddCore(options =>
				{
					// Configure OpenIddict to use the Entity Framework Core stores and models.
					// Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
					options.UseEntityFrameworkCore()
						.UseDbContext<GladerIdentityDatabaseContext>()
						.ReplaceDefaultEntities<int>();
				})
				.AddServer(options =>
				{
					// AddMvcBinders
					// AddMvcBinders() is now UseMvc().
					options.UseAspNetCore();

					// Enable the authorization, logout, token and userinfo endpoints.
					options.SetTokenEndpointUris("/api/auth");
					options.AllowPasswordFlow(); // Allow client applications to use the grant_type=password flow.
					options.AllowRefreshTokenFlow();

					//TODO: Support real certs.
					// Register the signing and encryption credentials.
					options.AddDevelopmentEncryptionCertificate()
						.AddDevelopmentSigningCertificate();

					//TODO: Reimplement issuer.
					//options.SetIssuer(new Uri(@"https://auth.vrguardians.net"));

					//Latest OpenIddict is WAYYY too complicated to deal with perms and everything. INSANE!
					options.IgnoreEndpointPermissions()
						.IgnoreGrantTypePermissions()
						.IgnoreScopePermissions();

					options.DisableAccessTokenEncryption();

					// Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
					options.UseAspNetCore()
						.EnableStatusCodePagesIntegration()
						.EnableTokenEndpointPassthrough()
						.DisableTransportSecurityRequirement(); // During development, you can disable the HTTPS requirement.

					// Note: if you don't want to specify a client_id when sending
					// a token or revocation request, uncomment the following line:
					//
					// options.AcceptAnonymousClients();

					// Note: if you want to process authorization and token requests
					// that specify non-registered scopes, uncomment the following line:
					//
					// options.DisableScopeValidation();

					// Note: if you don't want to use permissions, you can disable
					// permission enforcement by uncommenting the following lines:
					//
					// options.IgnoreEndpointPermissions()
					//        .IgnoreGrantTypePermissions()
					//        .IgnoreScopePermissions();

					// Note: when issuing access tokens used by third-party APIs
					// you don't own, you can disable access token encryption:
					//
					// options.DisableAccessTokenEncryption();
				})

				// Register the OpenIddict validation components.
				.AddValidation(options =>
				{
					// Configure the audience accepted by this resource server.
					// The value MUST match the audience associated with the
					// "demo_api" scope, which is used by ResourceController.
					options.AddAudiences("auth_server");

					// Import the configuration from the local OpenIddict server instance.
					options.UseLocalServer();

					// Register the ASP.NET Core host.
					options.UseAspNetCore();
				});

			services.AddControllers();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if(env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}

			app.UseHttpsRedirection();

			app.UseRouting();

			//THis was added, a call to UseAuthentication for authentication.
			app.UseAuthentication();
			app.UseAuthorization();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllers();
			});
		}
	}
}
