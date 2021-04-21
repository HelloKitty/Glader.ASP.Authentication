using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Glader.ASP.Authentication
{
	public sealed class AuthorizationClaimsAppenderContext
	{
		/// <summary>
		/// The associated HTTP request for the authorization.
		/// </summary>
		public HttpRequest Request { get; private set; }

		/// <summary>
		/// The authorized principal.
		/// </summary>
		public ClaimsPrincipal Principal { get; private set; }

		public AuthorizationClaimsAppenderContext(HttpRequest request, ClaimsPrincipal principal)
		{
			Request = request ?? throw new ArgumentNullException(nameof(request));
			Principal = principal ?? throw new ArgumentNullException(nameof(principal));
		}
	}
}
