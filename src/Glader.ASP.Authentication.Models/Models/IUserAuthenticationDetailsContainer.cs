﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// Contract for types that contain or expose user details.
	/// </summary>
	public interface IUserAuthenticationDetailsContainer
	{
		/// <summary>
		/// Username for the authentication request.
		/// </summary>
		string UserName { get; }

		/// <summary>
		/// Password for the authentication request.
		/// </summary>
		string Password { get; }
	}
}
