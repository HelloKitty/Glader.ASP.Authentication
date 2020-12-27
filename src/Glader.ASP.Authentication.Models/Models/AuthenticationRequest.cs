using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Refit;

namespace Glader.ASP.Authentication
{
	/// <summary>
	/// The authentication request model.
	/// Refer to the OAuth specification to understand the meaning of the properties.
	/// </summary>
	[JsonObject]
	public sealed class AuthenticationRequest : IUserAuthenticationDetailsContainer
	{
		/// <summary>
		/// Username for the authentication request.
		/// </summary>
		[AliasAs("username")]
		[JsonProperty(PropertyName = "username", Required = Required.Always)]
		public string UserName { get; private set; } //setter required by refit

		/// <summary>
		/// Password for the authentication request.
		/// </summary>
		[AliasAs("password")]
		[JsonProperty(PropertyName = "password", Required = Required.Always)]
		public string Password { get; private set; } //setter required by refit

		/// <summary>
		/// The OAuth grant type.
		/// </summary>
		[AliasAs("grant_type")]
		[JsonProperty(PropertyName = "grant_type", Required = Required.Always)]
		public string GrantType { get; private set; } = "password"; //setter required by refit

		/// <summary>
		/// Unique value used to prevent replay attacks.
		/// </summary>
		[AliasAs("nonce")]
		[JsonProperty(PropertyName = "nonce", Required = Required.Default)]
		public string Nonce { get; private set; } = Guid.NewGuid().ToString(); //This isn't technically cryptographically secure, but it's enough.

		/// <summary>
		/// Represents the client application identifier.
		/// </summary>
		[AliasAs("client_id")]
		[JsonProperty(PropertyName = "client_id", Required = Required.Default)]
		public string ClientId { get; private set; }

		/// <summary>
		/// Creates a new Authentication Request Model.
		/// </summary>
		/// <param name="userName">The non-null username.</param>
		/// <param name="password">The non-null password.</param>
		public AuthenticationRequest(string userName, string password)
			: this(userName, password, "default")
		{
			if(string.IsNullOrWhiteSpace(userName)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(userName));
			if(string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(password));

			UserName = userName;
			Password = password;
		}

		/// <summary>
		/// Creates a new Authentication Request Model.
		/// </summary>
		/// <param name="userName">The non-null username.</param>
		/// <param name="password">The non-null password.</param>
		/// <param name="clientId">The non-null client identifier.</param>
		public AuthenticationRequest(string userName, string password, string clientId)
			: this(userName, password, clientId, "password")
		{

		}

		/// <summary>
		/// Creates a new Authentication Request Model.
		/// </summary>
		/// <param name="userName">The non-null username.</param>
		/// <param name="password">The non-null password.</param>
		/// <param name="clientId">The non-null client identifier.</param>
		/// <param name="grantType">The non-null grant type.</param>
		public AuthenticationRequest(string userName, string password, string clientId, string grantType)
		{
			if(string.IsNullOrWhiteSpace(userName)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(userName));
			if(string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(password));
			if(string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(clientId));
			if(string.IsNullOrWhiteSpace(grantType)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(grantType));

			UserName = userName;
			Password = password;
			ClientId = clientId;
			GrantType = grantType;
		}

		/// <summary>
		/// Serializer ctor
		/// </summary>
		[JsonConstructor]
		private AuthenticationRequest()
		{

		}

		/// <inheritdoc />
		public override string ToString()
		{
			//Just return the body that will likely be used for the auth
			return $"grant_type={GrantType}&username={UserName}&password={Password}&nonce={Nonce}";
		}
	}
}
