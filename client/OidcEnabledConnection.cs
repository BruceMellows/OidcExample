using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Client;

/// <summary>
/// This is a proof of concept, so don't expect miracles.<br/>
/// Use the static Create function to create a OidcEnabledConnection.<br/>
/// </summary>
public sealed class OidcEnabledConnection : IDisposable
{
	const string responseString =
		"""
			<!DOCTYPE html>
			<html lang="en">
			<head>
			  <meta charset="utf-8">
			  <title>Login Complete</title>
			  <style>
			    body {
			      font-family: sans-serif;
			      text-align: center;
			      margin-top: 20%;
			      color: Black;
			    }
			    h2 {
			      color: DodgerBlue;
			    }
			    button {
			      background-color: DodgerBlue;
			      color: white;
			      border: none;
			      padding: 10px 20px;
			      font-size: 1em;
			      border-radius: 5px;
			      cursor: pointer;
			    }
			    button:hover {
			      background-color: RoyalBlue;
			    }
			  </style>
			  <script>
			    function closeWindow() {
			      // Try to close the window (allowed if triggered by user)
			      window.open('', '_self');
			      window.close();
			    }

			    function tryAutoClose() {
			      try {
			        // Attempt automatic close (might be blocked)
			        window.open('', '_self');
			        window.close();
			      } catch (e) {
			        console.warn("Automatic close not permitted:", e);
			      }
			    }

			    window.onload = function() {
			      // Optional: if you have a custom URI scheme for your app, redirect here.
			      // Uncomment and set to your scheme, e.g.:
			      // window.location.href = "myapp://oidc-complete";

			      // Try to close automatically after a short delay
			      setTimeout(tryAutoClose, 1000);
			    };
			  </script>
			</head>
			<body>
			  <h2>Authentication Complete</h2>
			  <p>You can now return to the application.</p>
			  <p>If this window does not close automatically, please click below:</p>
			  <button onclick="closeWindow()">Close this window</button>
			</body>
			</html>
			""";

	OidcEnabledConnection(IConnectionOptions connectionOptions, string jwt)
	{
		this.connectionOptions = connectionOptions;
		SetJwt(jwt);
	}

	public static async Task<OidcEnabledConnection?> Create(IConnectionOptions connectionOptions, CancellationToken cancellationToken)
	{
		var jwt = await GetJwtAsync(connectionOptions, forceConsent: false, cancellationToken)
			?? await GetJwtAsync(connectionOptions, forceConsent: true, cancellationToken);

		return !string.IsNullOrEmpty(jwt)
			? new OidcEnabledConnection(connectionOptions, jwt)
			: null;
	}

	public Task<HttpResponseMessage> GetAsync(string relativePath) => SendAsync(HttpMethod.Get, relativePath, HttpCompletionOption.ResponseContentRead, CancellationToken.None);

	public void Dispose()
	{
		var cts = Interlocked.CompareExchange(ref cancellationTokenSource, null, cancellationTokenSource);
		var timer = Interlocked.CompareExchange(ref refreshTimer, null, refreshTimer);
		if (cts is not null)
		{
			cts.Cancel();
			cts.Dispose();
		}

		if (timer is not null)
		{
			timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
			timer.Dispose();
		}
	}

	static async Task<HttpListenerContext> GetContext(HttpListener listener, Func<HttpListenerContext, bool> predicate, CancellationToken cancellationToken)
	{
		do
		{
			cancellationToken.ThrowIfCancellationRequested();
			var context = await listener.GetContextAsync();

			cancellationToken.ThrowIfCancellationRequested();
			if (predicate(context))
			{
				return context;
			}
		} while (true);
	}

	async Task<HttpResponseMessage> SendAsync(HttpMethod httpMethod, string relativePath, HttpCompletionOption completionOption, CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(cancellationTokenSource is null, this);
		cancellationTokenSource!.Token.ThrowIfCancellationRequested();
		using var linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationTokenSource!.Token, cancellationToken);
		using var client = new HttpClient { BaseAddress = connectionOptions.ServerBase };
		var request = new HttpRequestMessage(httpMethod, relativePath);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
		return await client.SendAsync(request, completionOption, linkedCancellationTokenSource.Token);
	}

	void SetJwt(string jwt)
	{
		ObjectDisposedException.ThrowIf(cancellationTokenSource is null, this);

		this.jwt = jwt;
		expiration = GetExpiryFromJwt(jwt);

		// Schedule refresh 2 minutes before expiry
		var refreshIn = expiration - DateTime.UtcNow - TimeSpan.FromMinutes(2);
		if (refreshIn < TimeSpan.FromSeconds(30))
			refreshIn = TimeSpan.FromSeconds(30);

		Interlocked.CompareExchange(
			ref refreshTimer,
			new(async _ => await RefreshAsync(), null, refreshIn, Timeout.InfiniteTimeSpan),
			refreshTimer)?.Dispose();
	}

	async Task RefreshAsync()
	{
		var response = await GetAsync(connectionOptions.ServerRefreshEndpoint.AbsoluteUri.Substring(connectionOptions.ServerBase.AbsoluteUri.Length));
		response.EnsureSuccessStatusCode();

		var json = await response.Content.ReadAsStringAsync();
		using var doc = JsonDocument.Parse(json);
		var newJwt = doc.RootElement.GetProperty("token").GetString() ?? throw new NotImplementedException();

		SetJwt(newJwt);
	}

	static async Task<string?> GetJwtAsync(IConnectionOptions connectionOptions, bool forceConsent, CancellationToken cancellationToken)
	{
		using var httpClient = new HttpClient { BaseAddress = connectionOptions.ServerBase };

		// 1 Start login flow
		var loginUrl = connectionOptions.GetServerLoginEndpoint(forceConsent);

		Process.Start(new ProcessStartInfo
		{
			FileName = loginUrl.AbsoluteUri,
			UseShellExecute = true
		});

		// 2 Start local HTTP listener to capture callback
		using var listener = new HttpListener();
		listener.Prefixes.Add(connectionOptions.LocalCallbackEndpoint.AbsoluteUri); // temporary redirect URI for frontend
		listener.Start();

		var context = await GetContext(listener, c => c.Request.Url?.AbsolutePath.ToString() == "/", cancellationToken);
		var query = context.Request.QueryString;
		var code = query["code"] ?? throw new NotImplementedException();
		var state = query["state"] ?? throw new NotImplementedException();
		var buffer = Encoding.UTF8.GetBytes(responseString);
		context.Response.ContentLength64 = buffer.Length;
		await context.Response.OutputStream.WriteAsync(buffer, CancellationToken.None);
		context.Response.OutputStream.Close();
		listener.Stop();

		// 3 Exchange code for JWT (via backend callback endpoint)
		var callbackUrl = connectionOptions.ServerCallbackEndpoint.BuildUri([("code", code), ("state", state)]);
		var callbackResponse = await httpClient.GetStringAsync(callbackUrl);
		Console.WriteLine(callbackResponse);
		using var doc = JsonDocument.Parse(callbackResponse);
		var token = doc.RootElement.GetProperty("token").GetString();
		return !string.IsNullOrEmpty(token)
			? token
			: default;
	}

	static DateTime GetExpiryFromJwt(string jwt)
	{
		// JWT format: header.payload.signature
		var parts = jwt.Split('.');
		if (parts.Length != 3) throw new Exception("Invalid JWT");

		var payload = parts[1];
		var jsonBytes = Convert.FromBase64String(PadBase64(payload));
		using var doc = JsonDocument.Parse(jsonBytes);
		var exp = doc.RootElement.GetProperty("exp").GetInt64();
		return DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
	}

	static string PadBase64(string s)
	{
		switch (s.Length % 4)
		{
			case 2: s += "=="; break;
			case 3: s += "="; break;
		}
		return s.Replace('-', '+').Replace('_', '/');
	}

	readonly IConnectionOptions connectionOptions;

	string? jwt;
	Timer? refreshTimer;
	DateTime expiration;
	CancellationTokenSource? cancellationTokenSource = new();
}

//static string HttpListenerRequestAsString(HttpListenerContext context)
//{
//	var sb = new StringBuilder();
//	var request = context.Request;

//	// Method and URL
//	sb.AppendLine($"HTTP Method: {request.HttpMethod}");
//	sb.AppendLine($"URL: {request.Url}");

//	// Headers
//	sb.AppendLine("Headers:");
//	foreach (string key in request.Headers.AllKeys)
//	{
//		sb.AppendLine($"{key}: {request.Headers[key]}");
//	}

//	// Query String
//	sb.AppendLine("Query String:");
//	foreach (string key in request.QueryString.AllKeys)
//	{
//		sb.AppendLine($"{key}: {request.QueryString[key]}");
//	}

//	// Body
//	using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
//	{
//		string body = reader.ReadToEnd();
//		sb.AppendLine("Body:");
//		sb.AppendLine(body);
//	}

//	// Cookies
//	sb.AppendLine("Cookies:");
//	foreach (Cookie cookie in request.Cookies)
//	{
//		sb.AppendLine($"{cookie.Name}: {cookie.Value}");
//	}
//	return sb.ToString();
//}
