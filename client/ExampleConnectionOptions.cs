namespace Client;

/// <summary>
/// This proxies the API that my backup tool web server exposes and the configuration for the OIDC that is used
/// </summary>
/// <param name="serverBase"></param>
public sealed class ExampleConnectionOptions(Uri serverBase) : IConnectionOptions
{
	public Uri LocalCallbackEndpoint => new("http://127.0.0.1:54321/");

	public Uri ServerBase => serverBase;

	public Uri ServerCallbackEndpoint => serverBase.BuildUri("open/oidc/callback");

	public Uri ServerRefreshEndpoint => serverBase.BuildUri("user/oidc/refresh");

	public Uri GetServerLoginEndpoint(bool requestConsent)
	{
		return requestConsent
			? serverBase.BuildUri("open/oidc/login", [("force_consent", "1")])
			: serverBase.BuildUri("open/oidc/login");
	}
}
