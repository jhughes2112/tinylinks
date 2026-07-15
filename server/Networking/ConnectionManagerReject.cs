using System.Threading.Tasks;
using ReachableGames.RGWebSocket;
using System.Net;
using Logging;

namespace Networking
{
	// Whenever there's a new connection or a disconnection or indeed ANY message received, they all come through this object regardless of what websocket originates it.
	// ConnectionManagerReject, as a policy, rejects all connections.
	public class ConnectionManagerReject : RGConnectionManager
	{
		public ConnectionManagerReject(ILogging logger) : base(logger)  // raw mode: no message factory, since we never keep a connection long enough to speak a protocol
		{
		}

		public override Task OnConnection(RGWebSocket rgws, HttpListenerContext httpListenerContext)
		{
			_logger.Log(EVerbosity.Info, $"OnConnection called RGWSID={rgws.DisplayId}");
			rgws.Close(EDisconnectReason.LocalClose);  // queues the close frame; it goes out as soon as the pumps start
			return Task.CompletedTask;
		}

		public override Task OnDisconnect(RGWebSocket rgws)
		{
			return Task.CompletedTask;
		}

		public override Task OnMessage(RGWebSocket rgws, IRGMessage msg)
		{
			return Task.CompletedTask;  // never called in raw mode
		}

		protected override Task OnRawMessage(RGWebSocket rgws, PooledArray msg, bool isText)
		{
			return Task.CompletedTask;  // ignore anything that sneaks in before the close completes
		}

		public override Task Shutdown()
		{
			return Task.CompletedTask;
		}
	}
}
