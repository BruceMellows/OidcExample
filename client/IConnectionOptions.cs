namespace Client;

/// <summary>
/// Package the endpoints that are needed in the OIDC Web application flow<br/><br/>
/// The comments here focus on the "Google Auth Platform" usage and configuration,
/// those comments should be applicable to other OIDC providers.<br/><br/>
/// The intent is that each implementation is specific to a service + OIDC combination.
/// </summary>
public interface IConnectionOptions
{
	/// <summary>
	/// This is the value you configured in your "Google Auth Platform / Clients / OAuth 2.0 Client IDs / Web application / Authorised redirect URIs"
	/// </summary>
	Uri LocalCallbackEndpoint { get; }

	/// <summary>
	/// The endpoint that you are going to use once the OIDC is complete<br/>
	/// While not essential in this interface, it is always going to be useful to have.<br/><br/>
	/// The endpoint must be a domain in the "Google Auth Platform / Branding / Authorised domains"
	/// </summary>
	Uri ServerBase { get; }

	/// <summary>
	/// This endpoint completes to flow and possibly returns the JWT to the caller.<br/>
	/// If the JWT is not returned, the caller should re-initiate the flow with "forced consent" enabled, unless it was already do, so the logic should be<br/><br/>
	/// jwt = get_jwt(options.GetServerLoginEndpoint(requestConsent: false)) ?? get_jwt(options.GetServerLoginEndpoint(requestConsent: true));
	/// </summary>
	Uri ServerCallbackEndpoint { get; }

	/// <summary>
	/// This endpoint returns an updated JWT, and should be called before the current JWT expires.
	/// </summary>
	Uri ServerRefreshEndpoint { get; }

	/// <summary>
	/// This endpoint initiates the OIDC flow by redirecting to the OIDC providers endpoint.<br/>
	/// Then the OIDC provider will redirect that to the LocalCallbackEndpoint.
	/// </summary>
	/// <param name="requestConsent">
	/// Instucts the web server to enable or disable the "consent request" in the OIDC provider.<br/>
	/// This might be required because the web server does not have the refresh token saved
	/// and the OIDC provider only provides the refresh token when consent it requested.<br/>
	/// Consent is also implied when the user is first redirected to the OIDC by the web server.
	/// </param>
	/// <returns></returns>
	Uri GetServerLoginEndpoint(bool requestConsent);
}
