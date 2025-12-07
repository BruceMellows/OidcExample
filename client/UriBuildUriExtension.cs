using System.Web;

namespace Client;

public static class UriBuildUriExtension
{
	public static Uri BuildUri(this Uri baseAddress, (string key, string value)[] paramArray) => baseAddress.BuildUri(string.Empty, paramArray);
	public static Uri BuildUri(this Uri baseAddress, string relativePath) => baseAddress.BuildUri(relativePath, []);
	public static Uri BuildUri(this Uri baseAddress, string relativePath, (string key, string value)[] paramArray)
	{
		var query = HttpUtility.ParseQueryString(string.Empty);
		foreach (var param in paramArray)
		{
			query[param.key] = param.value;
		}

		var builder = new UriBuilder(new Uri(baseAddress, relativePath)) { Query = query.ToString() };
		return builder.Uri;
	}
}
