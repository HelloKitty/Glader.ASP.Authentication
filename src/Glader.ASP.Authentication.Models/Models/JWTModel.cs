using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// Generic JWT model.
	/// </summary>
	[JsonObject]
	public class JWTModel
	{
		/// <summary>
		/// JWT access token if authentication was successful.
		/// </summary>
		[JsonProperty(PropertyName = "access_token", Required = Required.Default)] //optional because could be an error
		public string AccessToken { get; private set; } //WARNING: Don't make these readonly. It breakes for some reason.

		/// <summary>
		/// Error type if an error was encountered.
		/// </summary>
		[JsonProperty(PropertyName = "error", Required = Required.Default)] //optional because could be a valid token
		public string Error { get; private set; } //WARNING: Don't make these readonly. It breakes for some reason.

		/// <summary>
		/// Humanreadable read description.
		/// </summary>
		[JsonProperty(PropertyName = "error_description", Required = Required.Default)] //optional because could be a valid token
		public string ErrorDescription { get; private set; } //WARNING: Don't make these readonly. It breakes for some reason.

		[JsonIgnore]
		private Lazy<bool> _isTokenValid { get; }

		/// <summary>
		/// Indicates if the model contains a valid <see cref="AccessToken"/>.
		/// </summary>
		[JsonIgnore]
		public bool isTokenValid => _isTokenValid.Value;

		/// <summary>
		/// Creates a PlayerAccountJWTModel that contains an valid non-null <see cref="AccessToken"/>.
		/// </summary>
		/// <param name="accessToken"></param>
		public JWTModel(string accessToken)
			: this()
		{
			if (string.IsNullOrWhiteSpace(accessToken)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(accessToken));

			AccessToken = accessToken;
		}

		/// <summary>
		/// Creates an invalid <see cref="JWTModel"/> that contains an <see cref="Error"/> and <see cref="ErrorDescription"/>.
		/// </summary>
		/// <param name="error"></param>
		/// <param name="errorDescription"></param>
		public JWTModel(string error, string errorDescription)
			: this()
		{
			if(string.IsNullOrWhiteSpace(error)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(error));
			if(string.IsNullOrWhiteSpace(errorDescription)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(errorDescription));

			Error = error;
			ErrorDescription = errorDescription;
		}

		/// <summary>
		/// Serializer ctor
		/// </summary>
		[JsonConstructor]
		protected JWTModel()
		{
			_isTokenValid = new Lazy<bool>(CheckIfTokenIsValid, true);
		}

		private bool CheckIfTokenIsValid()
		{
			return !String.IsNullOrEmpty(AccessToken) && String.IsNullOrEmpty(Error) && String.IsNullOrEmpty(ErrorDescription);
		}
	}
}
