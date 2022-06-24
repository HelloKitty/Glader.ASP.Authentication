using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Glader.ASP.Authentication
{
	public static class IServiceCollectionExtensions
	{
		/// <summary>
		/// Registers other services related to Glader Identity.
		/// A call to UseAuthentication is still required in the request pipeline.
		/// </summary>
		/// <param name="services"></param>
		/// <param name="signingCert">The cert for signing. Otherwise will use temp dev cert.</param>
		/// <param name="requireClientId">Indicates if authentication should require the OpenIddict ClientId.</param>
		/// <returns></returns>
		public static IServiceCollection RegisterGladerIdentity(this IServiceCollection services, 
			X509Certificate2 signingCert = null,
			bool requireClientId = true)
		{
			if (services == null) throw new ArgumentNullException(nameof(services));

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
					options.SetAccessTokenLifetime(TimeSpan.FromDays(7));

					//TODO: Support real certs.
					// Register the signing and encryption credentials.
					if (signingCert != null)
						options.AddSigningCertificate(signingCert)
							.AddEncryptionCertificate(signingCert);
					else 
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

					if (!requireClientId)
						options.AcceptAnonymousClients();

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

			return services;
		}

		/// <summary>
		/// Registers a <see cref="GladerIdentityDatabaseContext"/> and Openiddict identity services.
		/// in the provided <see cref="services"/>.
		/// A call to UseAuthentication is still required in the request pipeline.
		/// </summary>
		/// <param name="services">Service container.</param>
		/// <param name="optionsAction">The DB context options action.</param>
		/// <returns></returns>
		public static IServiceCollection RegisterAuthenticationDatabase(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsAction)
		{
			if (services == null) throw new ArgumentNullException(nameof(services));
			if (optionsAction == null) throw new ArgumentNullException(nameof(optionsAction));

			//TODO: Add repository interface so consumers can access the Database indirectly.

			services.AddDbContext<GladerIdentityDatabaseContext>(options =>
			{
				//This should probably be the SQL store.
				optionsAction(options);
				
				//We need to also call our own thing here, so we nest the actions.
				//We need generic INT key registerations.
				options.UseOpenIddict<int>();
			});

			//Below is the OpenIddict registration
			//This is the recommended setup from the official Github: https://github.com/openiddict/openiddict-core
			services.AddIdentity<GladerIdentityApplicationUser, GladerIdentityApplicationRole>()
				.AddEntityFrameworkStores<GladerIdentityDatabaseContext>()
				.AddDefaultTokenProviders();

			//Example:
			//services.AddDbContext<ServiceDiscoveryDatabaseContext>(builder => { builder.UseMySql("server=127.0.0.1;port=3306;Database=guardians.global;Uid=root;Pwd=test;"); });
			return services;
		}
	}
}
