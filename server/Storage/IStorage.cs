using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Storage
{
	// Generic storage interface for reading and writing byte data
	// This interface is not tied to any specific data format or object type
	public interface IStorage : IDisposable
	{
		// Shuts down the storage system
		Task Shutdown();

		// Read raw data by key. Returns null if the key doesn't exist.
		Task<byte[]?> Read(string key);

		// Read a portion of the data by key starting from offset. Returns null if the key doesn't exist.
		// If maxLength would exceed the file size, returns only the available data.
		Task<byte[]?> ReadPartial(string key, int offset, int maxLength);

		// Write raw data with the given key. Returns true if successful, false if failed.
		Task<bool> Write(string key, byte[] data);

		// Delete data by key. Returns true if the key existed and was deleted, false otherwise.
		Task<bool> Delete(string key);

		// List all keys in the storage system
		Task<List<string>> ListAllKeys();

		// Get file information including size and last modified time. Returns null if the key doesn't exist.  Last modified is UTC Epoch Seconds
		Task<(long size, long lastModified)> GetFileInfo(string key);
	}
}