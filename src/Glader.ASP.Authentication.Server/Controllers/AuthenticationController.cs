using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Glader.ASP.Authentication;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Glader.ASP.Authentication
{
	//Copied from GladMMO.
	//From an old OpenIddict OAuth sample and a slightly modified version that I personally use
	//in https://github.com/GladLive/GladLive.Authentication/blob/master/src/GladLive.Authentication.OAuth/Controllers/AuthorizationController.cs
	[Route(AUTHENTICATION_ROUTE_VALUE)]
	public class AuthenticationController : Controller
	{
		internal const string AUTHENTICATION_ROUTE_VALUE = "api/auth";

		private IOptions<IdentityOptions> IdentityOptions { get; }

		private SignInManager<GladerIdentityApplicationUser> SignInManager { get; }

		private UserManager<GladerIdentityApplicationUser> UserManager { get; }

		private ILogger<AuthenticationController> Logger { get; }

		private IEnumerable<IAuthorizedClaimsAppender> ClaimsAppenders { get; }

		public AuthenticationController(
			IOptions<IdentityOptions> identityOptions,
			SignInManager<GladerIdentityApplicationUser> signInManager,
			UserManager<GladerIdentityApplicationUser> userManager, 
			ILogger<AuthenticationController> logger, 
			IEnumerable<IAuthorizedClaimsAppender> claimsAppenders)
		{
			IdentityOptions = identityOptions ?? throw new ArgumentNullException(nameof(identityOptions));
			SignInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
			UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
			Logger = logger ?? throw new ArgumentNullException(nameof(logger));
			ClaimsAppenders = claimsAppenders ?? throw new ArgumentNullException(nameof(claimsAppenders));
		}

		internal async Task<IActionResult> Authenticate(string username,
			string password,
			IEnumerable<string> scopes)
		{
			if (scopes == null) throw new ArgumentNullException(nameof(scopes));
			if (string.IsNullOrEmpty(username))
				throw new ArgumentException("Value cannot be null or empty.", nameof(username));
			if (string.IsNullOrEmpty(password))
				throw new ArgumentException("Value cannot be null or empty.", nameof(password));

			//We want to log this out for information purposes whenever an auth request begins
			if(Logger.IsEnabled(LogLevel.Information))
				Logger.LogInformation($"Auth Request: {username} {HttpContext.Connection.RemoteIpAddress}:{HttpContext.Connection.RemotePort}");

			var user = await UserManager.FindByNameAsync(username);
			if(user == null)
			{
				return BadRequest(new OpenIddictResponse
				{
					Error = OpenIddictConstants.Errors.InvalidClient,
					ErrorDescription = "The username/password couple is invalid."
				});
			}

			// Ensure the user is allowed to sign in.
			if(!await SignInManager.CanSignInAsync(user))
			{
				return BadRequest(new OpenIddictResponse
				{
					Error = OpenIddictConstants.Errors.InvalidGrant,
					ErrorDescription = "The specified user is not allowed to sign in."
				});
			}

			// Reject the token request if two-factor authentication has been enabled by the user.
			if(UserManager.SupportsUserTwoFactor && await UserManager.GetTwoFactorEnabledAsync(user))
			{
				return BadRequest(new OpenIddictResponse
				{
					Error = OpenIddictConstants.Errors.InvalidGrant,
					ErrorDescription = "The specified user is not allowed to sign in."
				});
			}

			// Ensure the user is not already locked out.
			if(UserManager.SupportsUserLockout && await UserManager.IsLockedOutAsync(user))
			{
				return BadRequest(new OpenIddictResponse
				{
					Error = OpenIddictConstants.Errors.InvalidGrant,
					ErrorDescription = "The username/password couple is invalid."
				});
			}

			// Ensure the password is valid.
			if(!await UserManager.CheckPasswordAsync(user, password))
			{
				if(UserManager.SupportsUserLockout)
				{
					await UserManager.AccessFailedAsync(user);
				}

				return BadRequest(new OpenIddictResponse
				{
					Error = OpenIddictConstants.Errors.InvalidGrant, 
					ErrorDescription = "The username/password couple is invalid."
				});
			}

			if(UserManager.SupportsUserLockout)
			{
				await UserManager.ResetAccessFailedCountAsync(user);
			}

			// Create a new authentication ticket.
			var ticket = await CreateTicketAsync(scopes, user);

			return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
		}

		[HttpPost]
		[Produces("application/json")]
		public async Task<IActionResult> Exchange()
		{
			//Change based on: https://github.com/openiddict/openiddict-core/blob/dev/samples/Mvc.Server/Controllers/AuthorizationController.cs#L59
			//If you try to do it as a parameter then you'll get a grant_type failure for some reason.
			OpenIddictRequest authRequest = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

			if (authRequest.IsPasswordGrantType())
			{
				return await Authenticate(authRequest.Username, authRequest.Password, authRequest.GetScopes());
			}

			return BadRequest(new OpenIddictResponse()
			{
				Error = OpenIddictConstants.Errors.UnsupportedGrantType,
				ErrorDescription = "The specified grant type is not supported."
			});
		}
		
		private async Task<AuthenticationTicket> CreateTicketAsync(IEnumerable<string> scopes, GladerIdentityApplicationUser user)
		{
			// Create a new ClaimsPrincipal containing the claims that
			// will be used to create an id_token, a token or a code.
			var principal = await SignInManager.CreateUserPrincipalAsync(user);

			// Create a new authentication ticket holding the user identity.
			AuthenticationTicket ticket = new AuthenticationTicket(principal,
				new Microsoft.AspNetCore.Authentication.AuthenticationProperties(),
				OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			// Set the list of scopes granted to the client application.
			ticket.Principal.SetScopes(new[]
			{
				OpenIddictConstants.Scopes.OpenId,
				OpenIddictConstants.Scopes.Profile,
				OpenIddictConstants.Scopes.Roles
			}.Intersect(scopes.Concat(new string[1] { OpenIddictConstants.Scopes.OpenId }))); //HelloKitty: Always include the OpenId, it's required for the Playfab authentication

			ticket.Principal.SetResources("auth-server");

			// Note: by default, claims are NOT automatically included in the access and identity tokens.
			// To allow OpenIddict to serialize them, you must attach them a destination, that specifies
			// whether they should be included in access tokens, in identity tokens or in both.
			foreach (var claim in ticket.Principal.Claims)
			{
				// Never include the security stamp in the access and identity tokens, as it's a secret value.
				if (claim.Type == IdentityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
				{
					continue;
				}

				var destinations = new List<string>
				{
					OpenIddictConstants.Destinations.AccessToken
				};

				// Only add the iterated claim to the id_token if the corresponding scope was granted to the client application.
				// The other claims will only be added to the access_token, which is encrypted when using the default format.
				if ((claim.Type == OpenIddictConstants.Claims.Name && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile)) ||
					(claim.Type == OpenIddictConstants.Claims.Email && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Email)) ||
					(claim.Type == OpenIddictConstants.Claims.Role && ticket.Principal.HasScope(OpenIddictConstants.Claims.Role)))
				{
					destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
				}

				claim.SetDestinations(destinations);
			}

			foreach (var appender in ClaimsAppenders)
				await appender.AppendClaimsAsync(new AuthorizationClaimsAppenderContext(Request, principal));

			return ticket;
		}
	}
}
