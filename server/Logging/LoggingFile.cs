using Nito.AsyncEx;
using ReachableGames.RGWebSocket;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Logging
{
    public class LoggingFile : ILogging
    {
        public EVerbosity Verbosity { get; set; }
		
		private string                   _prefix;
		private Task?                    _asyncLogTask       = Task.CompletedTask;
		private long                     _startTime          = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
		private LockingList<string>      _logs               = new LockingList<string>();
		private AsyncAutoResetEvent      _logsAvailable      = new AsyncAutoResetEvent(false);
		private CancellationTokenSource? _cancellationSource = new CancellationTokenSource();

        public LoggingFile(string prefix, EVerbosity verbosity, string filepath)
        {
            Verbosity = verbosity;
			_prefix   = prefix;
			_asyncLogTask = Task.Run(async () => await AsyncLogTask(filepath + "/" + prefix + ".log", _cancellationSource.Token).ConfigureAwait(false));
        }

		public void Dispose()
		{
			_cancellationSource?.Cancel();
			_asyncLogTask?.GetAwaiter().GetResult();  // block until the thread exits
			_asyncLogTask = null;
			_cancellationSource?.Dispose();
			_cancellationSource = null;
		}

        public void Log(EVerbosity level, string msg)
        {
            if (Verbosity >= level)
			{
				long msFromStart = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _startTime;
				_logs.Add($"{TimeSpan.FromMilliseconds(msFromStart).ToString(@"hh\:mm\:ss\:fff")} V={(int)level} {_prefix} {msg}");
				_logsAvailable.Set();
			}
        }

		private async Task AsyncLogTask(string filepath, CancellationToken token)
		{
			try
			{
				List<string> logsToWrite = new List<string>();
				using (StreamWriter writer = new StreamWriter(filepath, false, System.Text.Encoding.UTF8))  // clobber whatever file was there each time you run.
				{
					while (token.IsCancellationRequested==false)
					{
						try
						{
							await _logsAvailable.WaitAsync(token).ConfigureAwait(false);  // new log showed up, send it to the file
							_logs.MoveTo(logsToWrite);
							foreach (string l in logsToWrite)
							{
								writer.WriteLine(l);
							}
							await writer.FlushAsync().ConfigureAwait(false);  // make sure stuff gets flushed to disk after each batch
							logsToWrite.Clear();
						}
						catch (OperationCanceledException)
						{
							// flow control
						}
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
		}
    }
}