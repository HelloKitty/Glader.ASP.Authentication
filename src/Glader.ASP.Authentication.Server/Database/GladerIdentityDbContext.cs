using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// See Documentation for details: https://github.com/openiddict/openiddict-core
	/// </summary>
	public class GladerIdentityDatabaseContext : IdentityDbContext<GladerIdentityApplicationUser, GladerIdentityApplicationRole, int>
	{
		public GladerIdentityDatabaseContext(DbContextOptions<GladerIdentityDatabaseContext> options)
			: base(options)
		{

		}
	}
}
