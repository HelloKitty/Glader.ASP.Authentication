using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// Contract for types that can append claims.
	/// </summary>
	public interface IAuthorizedClaimsAppender
	{
		/// <summary>
		/// Optionally appends new claims to the principal.
		/// </summary>
		/// <param name="context">The authorization context.</param>
		/// <param name="token">Cancel token.</param>
		/// <returns></returns>
		Task AppendClaimsAsync(AuthorizationClaimsAppenderContext context, CancellationToken token = default);
	}
}
