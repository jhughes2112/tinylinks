using System.Text.RegularExpressions;

namespace Shared
{
	public static class RegexHelper
	{
		/// <summary>
		/// DNS hostnames start with alphanumeric, can have dash or numbers, but cannot end with a dash.
		/// </summary>
		static public Regex DnsName = new Regex(@"^[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]$");

		/// <summary>
		/// Prometheus has a specific requirement for its metrics.
		/// </summary>
		static public Regex PrometheusName = new Regex(@"^[a-zA-Z_][a-zA-Z0-9_]*$");

		private static Regex FileFullNameRegex   = new Regex(@"([^/\\]+$)");
		private static Regex FileNameRegex       = new Regex(@"[^/\\]+(?=\.)");
		private static Regex FileExtensionRegex  = new Regex(@"(?=[^/\\])\.(.\w+)$");
		private static Regex FileDirectoryRegex  = new Regex(@"^.+(?=\/|\\.+$)");

		/// <summary>
		/// Isolates the file name and extension from a path with either forward, back, or no slashes.
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns>"File.txt" from "Folder/SubFolder/File.txt"</returns>
		public static string GetFileNameFull(string filePath) { return FileFullNameRegex.Match(filePath).Value; }

		/// <summary>
		/// Isolates file name without extension from a path with either forward, back, or no slashes.
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns>"File" from "Folder/SubFolder/File.txt"</returns>
		public static string GetFileNameOnly(string filePath) { return FileNameRegex.Match(filePath).Value; }

		/// <summary>
		/// Isolates the file extension from a filename, or full file path.
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns>".txt" from "Folder/SubFolder/File.txt"</returns>
		public static string GetFileExtensionOnly(string filePath) { return FileExtensionRegex.Match(filePath).Value; }

		/// <summary>
		/// Isolates the directory of a file up to, but not including the last slash and full file name. Compatible with forward or back slashes.
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns>"Folder/SubFolder" from "Folder/SubFolder/File.txt"</returns>
		public static string GetFileDirectory(string filePath) { return FileDirectoryRegex.Match(filePath).Value; }
	}
}
