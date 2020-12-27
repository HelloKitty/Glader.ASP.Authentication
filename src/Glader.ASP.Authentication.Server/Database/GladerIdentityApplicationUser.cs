using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// OpenIddict app user.
	/// See Documentation for details: https://github.com/openiddict/openiddict-core
	/// </summary>
	public class GladerIdentityApplicationUser : IdentityUser<int> { } //we don't need any additional data; we rely directly on identity
}
