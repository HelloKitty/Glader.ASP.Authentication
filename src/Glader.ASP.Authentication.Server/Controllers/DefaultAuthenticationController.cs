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
	[ApiController]
	[NonController]
	public class DefaultAuthenticationController : BaseAuthenticationController
	{
		private IOptions<IdentityOptions> IdentityOptions { get; }

		private SignInManager<GladerIdentityApplicationUser> SignInManager { get; }

		private UserManager<GladerIdentityApplicationUser> UserManager { get; }

		public DefaultAuthenticationController(
			IOptions<IdentityOptions> identityOptions,
			SignInManager<GladerIdentityApplicationUser> signInManager,
			UserManager<GladerIdentityApplicationUser> userManager, 
			ILogger<DefaultAuthenticationController> logger, 
			IEnumerable<IAuthorizedClaimsAppender> claimsAppenders)
			: base(logger, claimsAppenders)
		{
			IdentityOptions = identityOptions ?? throw new ArgumentNullException(nameof(identityOptions));
			SignInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
			UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
		}

		/// <inheritdoc />
		[NonAction]
		protected internal override async Task<IActionResult> Authenticate(string username,
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

		[NonAction]
		protected override bool ShouldIncludeClaim(Claim claim)
		{
			if(claim == null) throw new ArgumentNullException(nameof(claim));
			return claim.Type == IdentityOptions.Value.ClaimsIdentity.SecurityStampClaimType;
		}

		[NonAction]
		protected override async Task<ClaimsPrincipal> CreateUserPrincipalAsync(GladerIdentityApplicationUser user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			return await SignInManager.CreateUserPrincipalAsync(user);
		}
	}
}
