namespace Client;

internal class Program
{
	static async Task Main()
	{
		var connectionOptions = new ExampleConnectionOptions(new Uri("https://server.example.com/api/example/v1/"));
		using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(10));
		using var connection = await OidcEnabledConnection.Create(connectionOptions, cancellationTokenSource.Token);
		if (connection == null)
		{
			Console.WriteLine("Falied to create OidcEnabledConnection");
			return;
		}

		// now can use OIDC enabled connection to call protected API
		while (true)
		{
			using var userInfo = await connection.GetAsync("user/info");
			Console.WriteLine($"user/info response: {await userInfo.Content.ReadAsStringAsync()}");
			using var adminInfo = await connection.GetAsync("admin/info");
			Console.WriteLine($"admin/info response: {await adminInfo.Content.ReadAsStringAsync()}");
			Console.WriteLine("Waiting some time before next call...");
			await Task.Delay(TimeSpan.FromMinutes(25));
		}
	}
}
