using Logging;
using Prometheus;
using Shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace DataCollection
{
	// Implements the metrics interface for Prometheus scraping.
    public class DataCollectionPrometheus : IDataCollection
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

		private ThreadSafeDictionary<string, Gauge>     _gauges     = new ThreadSafeDictionary<string, Gauge>();
		private ThreadSafeDictionary<string, Counter>   _counters   = new ThreadSafeDictionary<string, Counter>();
		private ThreadSafeDictionary<string, Histogram> _histograms = new ThreadSafeDictionary<string, Histogram>();

		// Labels automatically tag all gauges and counters that are created so they can be easily queried, such as program->cluster or zone->tidesreach
		// Runtime stats (GC, threadpool, exceptions, sockets) come from prometheus-net's built-in default collectors
		// (process metrics + .NET event counters + meters).  prometheus-net.DotNetRuntime was dropped: it relies on
		// runtime reflection that breaks under NativeAOT, and its JIT stats are meaningless in an AOT binary anyway.
		public DataCollectionPrometheus(Dictionary<string, string> labels, ILogging logger)
		{
			Metrics.DefaultRegistry.SetStaticLabels(labels);
		}

		public void Dispose()
		{
		}

		public void CreateGauge(string gaugeName, string description)
		{
			if (RegexHelper.PrometheusName.IsMatch(gaugeName)==false)
				throw new Exception($"DataCollection.CreateGauge Invalid name format (only letters, numbers, and underscores): {gaugeName}");
			if (_gauges.Add(gaugeName, Metrics.CreateGauge(gaugeName, description))==false)
				throw new Exception($"DataCollectionPrometheus.CreateGauge Failed to add {gaugeName}.  Already exists?");
		}

		public void CreateCounter(string counterName, string description)
		{
			if (RegexHelper.PrometheusName.IsMatch(counterName)==false)
				throw new Exception($"DataCollection.CreateGauge Invalid name format (only letters, numbers, and underscores): {counterName}");
			_counters.GetOrAdd(counterName, () => Metrics.CreateCounter(counterName, description));
		}

		public void IncrementCounter(string counterName, double v)
		{
			if (_counters.TryGetValue(counterName, out Counter? c)==false)
				throw new Exception($"DataCollection.IncrementCounter missing {counterName}");
			c.Inc(v);
		}

		public void SetGauge(string gaugeName, double value)
		{
			if (_gauges.TryGetValue(gaugeName, out Gauge? g)==false)
				throw new Exception($"DataCollection.SetGauge missing {gaugeName}");
			g.Set(value);
		}

		public void CreateHistogram(string histogramName, string description, double[] bucketUpperBounds)
		{
			if (RegexHelper.PrometheusName.IsMatch(histogramName)==false)
				throw new Exception($"DataCollection.CreateHistogram Invalid name format (only letters, numbers, and underscores): {histogramName}");
			_histograms.GetOrAdd(histogramName, () => Metrics.CreateHistogram(histogramName, description, new HistogramConfiguration() { Buckets = bucketUpperBounds }));
		}

		public void ObserveHistogram(string histogramName, double value)
		{
			if (_histograms.TryGetValue(histogramName, out Histogram? h)==false)
				throw new Exception($"DataCollection.ObserveHistogram missing {histogramName}");
			h.Observe(value);
		}

		public async Task<byte[]> Generate()
		{
			using (MemoryStream ms = new MemoryStream())
			{
				await Metrics.DefaultRegistry.CollectAndExportAsTextAsync(ms).ConfigureAwait(false);
				return ms.ToArray();
			}
		}
    }
}
