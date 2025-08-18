using Logging;
using Shared;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DataCollection
{
	// Implements the metrics interface for Prometheus scraping, but does so as a stub.
    public class DataCollectionFake : IDataCollection
    {
		private class ValueDesc
		{
			public ValueDesc(long value, string description)
			{
				this.value = value;
				this.description = description;
			}
			public long   value;
			public string description;
		}

		private ThreadSafeDictionary<string, ValueDesc> _gauges        = new ThreadSafeDictionary<string, ValueDesc>();
		private ThreadSafeDictionary<string, ValueDesc> _counters      = new ThreadSafeDictionary<string, ValueDesc>();
		private Dictionary<string, string>              _labels;  // labels are added statically to all prometheus counters and gauges
		private ILogging                                _logger;

		public DataCollectionFake(Dictionary<string, string> labels, ILogging logger)
		{
			_labels = labels;
			_logger = logger;
		}

		public void Dispose()
		{
		}

		public void CreateGauge(string gaugeName, string description)
		{
			if (RegexHelper.PrometheusName.IsMatch(gaugeName)==false)
				throw new Exception($"DataCollection.CreateGauge Invalid name format (only letters, numbers, and underscores): {gaugeName}");
			if (_gauges.Add(gaugeName, new ValueDesc(0, description))==false)
				throw new Exception($"DataCollection.CreateGauge logic error {gaugeName} already exists.");
		}

		public void CreateCounter(string counterName, string description)
		{
			if (RegexHelper.PrometheusName.IsMatch(counterName)==false)
				throw new Exception($"DataCollection.CreateGauge Invalid name format (only letters, numbers, and underscores): {counterName}");
			_counters.GetOrAdd(counterName, () => new ValueDesc(0, description));
		}

		public void IncrementCounter(string counterName, double v)
		{
			if (_counters.TryGetValue(counterName, out ValueDesc vd)==false)
				throw new Exception($"DataCollection.IncrementCounter missing {counterName}");

			Interlocked.Add(ref vd.value, (int)v);
		}

		public void SetGauge(string gaugeName, double v)
		{
			if (_gauges.TryGetValue(gaugeName, out ValueDesc vd)==false)
				throw new Exception($"DataCollection.SetGauge missing {gaugeName}");

			vd.value = (long)v;  // if this fails, we just allow it to fail.  Gauges are just set, not additive.
		}

		public Task<byte[]> Generate()
		{
			using (MemoryStream ms = new MemoryStream())
			{
				using (StreamWriter sw = new StreamWriter(ms, System.Text.Encoding.UTF8))
				{
					_gauges.Foreach((string gaugeName, ValueDesc vd) =>
						{
							sw.WriteLine($"{gaugeName} = {vd.value}  -> {vd.description}");
						});
					_counters.Foreach((string counterName, ValueDesc vd) =>
						{
							sw.WriteLine($"{counterName} = {vd.value}  -> {vd.description}");
						});
				}
				return Task.FromResult(ms.ToArray());
			}
		}
    }
}
