using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Glader.ASP.Authentication
{
	public sealed class SubAccountHeaderParser
	{
		/// <summary>
		/// Indicates if the request has a sub-account ID header.
		/// </summary>
		/// <param name="request"></param>
		/// <returns></returns>
		public bool HasHeader(HttpRequest request)
		{
			if (request == null) throw new ArgumentNullException(nameof(request));

			return request.Headers.ContainsKey(GladerASPAuthenticationConstants.SUBACCOUNT_ID_HEADER);
		}

		/// <summary>
		/// Parses the sub-account ID from the request.
		/// </summary>
		/// <param name="request"></param>
		/// <returns></returns>
		public int Parse(HttpRequest request)
		{
			if (request == null) throw new ArgumentNullException(nameof(request));

			string header = request.Headers[GladerASPAuthenticationConstants.SUBACCOUNT_ID_HEADER];

			return int.Parse(header);
		}
	}
}
