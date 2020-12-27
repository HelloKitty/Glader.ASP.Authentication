using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Glader.ASP.Authentication;
using Refit;

namespace GladMMO
{
	/// <summary>
	/// Proxy interface for Authentication Server RPCs.
	/// </summary>
	[Headers("User-Agent: Glader")]
	public interface IAuthenticationService
	{
		/// <summary>
		/// Authenticate request method. Sends the request model as a URLEncoded body.
		/// See the documentation for information about the endpoint.
		/// https://github.com/HaloLive/Documentation
		/// </summary>
		/// <param name="request">The request model.</param>
		/// <exception cref="ApiException">Thrown if authentication fails. This is part of the OAuth specification to return 400 BadRequest. Therefore Refit throws.</exception>
		/// <returns>The authentication result.</returns>
		//TODO: Refit doesn't support error code suppresion.
		//[SupressResponseErrorCodes((int)HttpStatusCode.BadRequest)] //OAuth spec returns 400 BadRequest on failed auth
		[Post("/api/auth")]
		Task<JWTModel> AuthenticateAsync([Body(BodySerializationMethod.UrlEncoded)] AuthenticationRequest request);
	}
}
