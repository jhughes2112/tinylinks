using Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Storage
{
	// Generic file storage that works with raw byte data
	// Writing a file atomically is... hard.  The best we can really do is write to a temp file, then MOVE it into place.  
	public class StorageFiles : IStorage
	{
		public string                   _dataFolder { get; private set; }
		private ILogging                _logger;

		public StorageFiles(string dataFolder, ILogging logger)
		{
			_dataFolder = Path.GetFullPath(dataFolder);
			_logger = logger;

			DirectoryInfo di = Directory.CreateDirectory(_dataFolder);
			_logger.Log(EVerbosity.Info, $"StorageFiles at {_dataFolder} {di.Exists}");
		}

		public void Dispose()
		{
			// No resources to dispose
		}

		public Task Shutdown()
		{
			return Task.CompletedTask;
		}

		// Atomic read
		public Task<byte[]?> Read(string key)
		{
			string filename = GetFullPath(key);
			if (filename.StartsWith(_dataFolder, StringComparison.OrdinalIgnoreCase))
			{
				for (int i = 0; i < 10;)  // if we have 10 exceptions, this isn't going to fix itself.
				{
					try
					{
						using (FileStream fs = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
						{
							byte[] data = new byte[fs.Length];
							int offset = 0;
							int remaining = data.Length;
							while (remaining > 0)
							{
								int read = fs.Read(data, offset, remaining);
								if (read == 0)
									throw new EndOfStreamException($"Unexpected end of stream while reading file: {filename}");
								offset += read;
								remaining -= read;
							}
							return Task.FromResult<byte[]?>(data);
						}
					}
					catch (ArgumentException) { return Task.FromResult<byte[]?>(null); }
					catch (NotSupportedException) { return Task.FromResult<byte[]?>(null); }
					catch (IOException ioe)  // some other process is writing/locking this file currently, try again
					{
						// FileNotFoundException happens a lot.  The others not so much.
						if ((ioe is FileNotFoundException) || (ioe is DriveNotFoundException) || (ioe is DirectoryNotFoundException) || (ioe is FileLoadException) || (ioe is PathTooLongException))
						{
							return Task.FromResult<byte[]?>(null);
						}
						_logger.Log(EVerbosity.Extreme, $"StorageFiles.Read {key} i/o exception {ioe}");  // we assume this will be fixed by retrying
						i++;
					}
				}
				_logger.Log(EVerbosity.Error, $"StorageFiles.Read {key} aborted after 10 exceptions");  // whatever happened here, it was really bad
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"StorageFiles.Read {key} -> {filename} attempts path traversal {_dataFolder}");
			}
			return Task.FromResult<byte[]?>(null);
		}

		// Atomic read of partial file data starting from offset
		public Task<byte[]?> ReadPartial(string key, int offset, int maxLength)
		{
			string filename = GetFullPath(key);
			if (filename.StartsWith(_dataFolder, StringComparison.OrdinalIgnoreCase))
			{
				for (int i = 0; i < 10;)  // if we have 10 exceptions, this isn't going to fix itself.
				{
					try
					{
						using (FileStream fs = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
						{
							// Check if offset is beyond file size
							if (offset >= fs.Length)
								return Task.FromResult<byte[]?>(new byte[0]);

							// Seek to the requested offset
							fs.Seek(offset, SeekOrigin.Begin);
						
							// Calculate actual read length (don't read beyond file end)
							int actualLength = Math.Min(maxLength, (int)(fs.Length - offset));
							byte[] data = new byte[actualLength];
						
							int totalRead = 0;
							while (totalRead < actualLength)
							{
								int read = fs.Read(data, totalRead, actualLength - totalRead);
								if (read == 0)
									break; // End of file reached
								totalRead += read;
							}
						
							// Return only the data that was actually read
							if (totalRead < actualLength)
							{
								byte[] trimmedData = new byte[totalRead];
								Array.Copy(data, 0, trimmedData, 0, totalRead);
								return Task.FromResult<byte[]?>(trimmedData);
							}
						
							return Task.FromResult<byte[]?>(data);
						}
					}
					catch (ArgumentException) { return Task.FromResult<byte[]?>(null); }
					catch (NotSupportedException) { return Task.FromResult<byte[]?>(null); }
					catch (IOException ioe)  // some other process is writing/locking this file currently, try again
					{
						// FileNotFoundException happens a lot.  The others not so much.
						if ((ioe is FileNotFoundException) || (ioe is DriveNotFoundException) || (ioe is DirectoryNotFoundException) || (ioe is FileLoadException) || (ioe is PathTooLongException))
						{
							return Task.FromResult<byte[]?>(null);
						}
						_logger.Log(EVerbosity.Extreme, $"StorageFiles.ReadPartial {key} i/o exception {ioe}");  // we assume this will be fixed by retrying
						i++;
					}
				}
				_logger.Log(EVerbosity.Error, $"StorageFiles.ReadPartial {key} aborted after 10 exceptions");  // whatever happened here, it was really bad
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"StorageFiles.ReadPartial {key} -> {filename} attempts path traversal {_dataFolder}");
			}
			return Task.FromResult<byte[]?>(null);
		}

		public async Task<bool> Write(string key, byte[] data)
		{
			string filename = GetFullPath(key);
			if (filename.StartsWith(_dataFolder, StringComparison.OrdinalIgnoreCase))
			{
				string? subfolder = Path.GetDirectoryName(filename);
				if (subfolder!=null && Directory.Exists(subfolder)==false)  // automatically make folders as needed to hold files.
				{
					DirectoryInfo di = Directory.CreateDirectory(subfolder);
				}

				for (int i = 0; i < 10; i++) // retry on I/O exceptions
				{
					// Temp files are not guaranteed to be on the same volume, so we make it in the same folder, even though it's pretty gross that a file might somehow escape and dangle here forever.
					string tempFilename = Path.Combine(subfolder ??  string.Empty, Path.GetRandomFileName());
					try
					{
						await File.WriteAllBytesAsync(tempFilename, data).ConfigureAwait(false);

						// Delete target file first (ignoring if it doesn't exist), then move temp file into place
						try { File.Delete(filename); } catch { /* ignore if file doesn't exist */ }
						File.Move(tempFilename, filename);
						return true;
					}
					catch (IOException ioe)
					{
						_logger.Log(EVerbosity.Warning, $"StorageFiles.Write {key} i/o exception {ioe}");
					}
					catch (Exception e)
					{
						_logger.Log(EVerbosity.Error, $"StorageFiles.Write {key} exception {e}");
					}
					finally
					{
						try { if (File.Exists(tempFilename)) File.Delete(tempFilename); }
						catch { /* swallow cleanup failures */ }
					}
				}
				_logger.Log(EVerbosity.Error, $"StorageFiles.Write {key} aborted after 10 exceptions");
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"StorageFiles.Write {key} -> {filename} attempts path traversal {_dataFolder}");
			}
			return false;
		}

		public Task<bool> Delete(string key)
		{
			string filename = GetFullPath(key);
			bool deleted = false;
			if (filename.StartsWith(_dataFolder, StringComparison.OrdinalIgnoreCase))
			{
				if (File.Exists(filename))
				{
					File.Delete(filename);
					deleted = true;
				}
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"StorageFiles.Delete {key} -> {filename} attempts path traversal {_dataFolder}");
			}
			return Task.FromResult(deleted);
		}

		public Task<List<string>> ListAllKeys()
		{
			List<string> keys = new List<string>();
			string searchPath = _dataFolder;
			
			if (Directory.Exists(searchPath))
			{
				string[] files = Directory.GetFiles(searchPath, "*", SearchOption.AllDirectories);
				foreach (string file in files)
				{
					// Get relative path from the data folder to use as key
					string filename = Path.GetFileName(file);
					string relativePath = Path.GetRelativePath(_dataFolder, file);
					keys.Add(relativePath);
				}
			}

			return Task.FromResult(keys);
		}

		//-------------------
		// Returns the full path for a given key, ensuring it stays within the data folder
		public string GetFullPath(string key)
		{
			// Remove any directory separators to prevent directory traversal
			char[] invalidChars = Path.GetInvalidFileNameChars();
			char[] directorySeparators = { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, '/', '\\' };
			char[] allInvalidChars = new char[invalidChars.Length + directorySeparators.Length];
			invalidChars.CopyTo(allInvalidChars, 0);
			directorySeparators.CopyTo(allInvalidChars, invalidChars.Length);

			string cleaned = key;
			for (;;)
			{
				int i = cleaned.IndexOfAny(allInvalidChars);
				if (i == -1)
					break;
				cleaned = cleaned.Replace(cleaned[i], '-');
			}

			// Combine with data folder and get the full path
			string combinedPath = Path.Combine(_dataFolder, cleaned);
			string fullPath = Path.GetFullPath(combinedPath);
			return fullPath;
		}

		// Get file information including size and last modified time without reading the entire file
		public Task<(long size, long lastModified)> GetFileInfo(string key)
		{
			long size = 0;
			long lastModified = 0;

			string filename = GetFullPath(key);
			if (filename.StartsWith(_dataFolder, StringComparison.OrdinalIgnoreCase))
			{
				try
				{
					if (File.Exists(filename))
					{
						System.IO.FileInfo fileInfo = new System.IO.FileInfo(filename);
						size = fileInfo.Length;
						lastModified = ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds();
					}
				}
				catch (Exception ex)
				{
					_logger.Log(EVerbosity.Warning, $"StorageFiles.GetFileInfo {key} exception {ex.Message}");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"StorageFiles.GetFileInfo {key} -> {filename} attempts path traversal {_dataFolder}");
			}
			return Task.FromResult((size, lastModified));
		}
	}
}
