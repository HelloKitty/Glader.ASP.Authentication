using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// Base Authentication Controller implementation.
	/// </summary>
	[Route(AUTHENTICATION_ROUTE_VALUE)]
	public abstract class BaseAuthenticationController : Controller
	{
		internal const string AUTHENTICATION_ROUTE_VALUE = "api/auth";

		protected ILogger<DefaultAuthenticationController> Logger { get; }

		protected IEnumerable<IAuthorizedClaimsAppender> ClaimsAppenders { get; }

		protected BaseAuthenticationController(ILogger<DefaultAuthenticationController> logger, 
			IEnumerable<IAuthorizedClaimsAppender> claimsAppenders)
		{
			Logger = logger ?? throw new ArgumentNullException(nameof(logger));
			ClaimsAppenders = claimsAppenders ?? throw new ArgumentNullException(nameof(claimsAppenders));
		}

		/// <summary>
		/// Core implementation of authentication that takes input of <see cref="username"/>, <see cref="password"/> and requested <see cref="scopes"/>.
		/// </summary>
		/// <param name="username">The user name.</param>
		/// <param name="password">The password.</param>
		/// <param name="scopes">Requested scopes.</param>
		/// <returns></returns>
		protected internal abstract Task<IActionResult> Authenticate(string username, string password, IEnumerable<string> scopes);

		protected abstract Task<ClaimsPrincipal> CreateUserPrincipalAsync(GladerIdentityApplicationUser user);

		[HttpPost]
		[Produces("application/json")]
		public async Task<IActionResult> Exchange()
		{
			//Change based on: https://github.com/openiddict/openiddict-core/blob/dev/samples/Mvc.Server/Controllers/AuthorizationController.cs#L59
			//If you try to do it as a parameter then you'll get a grant_type failure for some reason.
			OpenIddictRequest authRequest = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

			if(authRequest.IsPasswordGrantType())
			{
				return await Authenticate(authRequest.Username, authRequest.Password, authRequest.GetScopes());
			}

			return BadRequest(new OpenIddictResponse()
			{
				Error = OpenIddictConstants.Errors.UnsupportedGrantType,
				ErrorDescription = "The specified grant type is not supported."
			});
		}

		protected virtual async Task<AuthenticationTicket> CreateTicketAsync(IEnumerable<string> scopes, GladerIdentityApplicationUser user)
		{
			// Create a new ClaimsPrincipal containing the claims that
			// will be used to create an id_token, a token or a code.
			var principal = await CreateUserPrincipalAsync(user);

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
			foreach(var claim in ticket.Principal.Claims)
			{
				// Never include the security stamp in the access and identity tokens, as it's a secret value.
				if(ShouldIncludeClaim(claim))
				{
					continue;
				}

				var destinations = new List<string>
				{
					OpenIddictConstants.Destinations.AccessToken
				};

				// Only add the iterated claim to the id_token if the corresponding scope was granted to the client application.
				// The other claims will only be added to the access_token, which is encrypted when using the default format.
				if((claim.Type == OpenIddictConstants.Claims.Name && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile)) ||
					(claim.Type == OpenIddictConstants.Claims.Email && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Email)) ||
					(claim.Type == OpenIddictConstants.Claims.Role && ticket.Principal.HasScope(OpenIddictConstants.Claims.Role)))
				{
					destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
				}

				claim.SetDestinations(destinations);
			}

			foreach(var appender in ClaimsAppenders)
				await appender.AppendClaimsAsync(new AuthorizationClaimsAppenderContext(Request, principal));

			return ticket;
		}

		protected abstract bool ShouldIncludeClaim(Claim claim);
	}
}
