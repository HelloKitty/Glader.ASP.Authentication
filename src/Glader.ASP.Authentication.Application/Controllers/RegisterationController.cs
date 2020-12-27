using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Glader.ASP.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace GladMMO
{
	[Route("api/registration")]
	public class RegistrationController : Controller
	{
		private UserManager<GladerIdentityApplicationUser> UserManager { get; }

		private ILogger<RegistrationController> Logger { get; }

		/// <inheritdoc />
		public RegistrationController([NotNull] UserManager<GladerIdentityApplicationUser> userManager,
			[NotNull] ILogger<RegistrationController> logger)
		{
			UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
			Logger = logger ?? throw new ArgumentNullException(nameof(logger));
		}

#warning Dont ever deploy this for real
		[HttpPost]
		public async Task<IActionResult> RegisterDev([FromQuery] string username, [FromQuery] string password)
		{
			if(string.IsNullOrWhiteSpace(username))
				return BadRequest("Invalid username");

			if(string.IsNullOrWhiteSpace(password))
				return BadRequest("Invalid password.");

			//We want to log this out for information purposes whenever an auth request begins
			if(Logger.IsEnabled(LogLevel.Information))
				Logger.LogInformation($"Register Request: {username} {HttpContext.Connection.RemoteIpAddress}:{HttpContext.Connection.RemotePort}");

			GladerIdentityApplicationUser user = new GladerIdentityApplicationUser()
			{
				UserName = username,
				Email = "dev@dev.com"
			};

			IdentityResult identityResult = await UserManager.CreateAsync(user, password);

			if (identityResult.Succeeded)
			{
				return Ok();
			}
			else
				return BadRequest(identityResult.Errors.Aggregate("", (s, error) => $"{s} {error.Code}:{error.Description}"));
		}
	}
}
