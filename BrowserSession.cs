#if UNITY_WEBGL && !UNITY_EDITOR
using System;
using System.Runtime.InteropServices;
using CodeBoost.Performance;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// A client's WebTransport session in a WebGL build, run by the browser's own <c>WebTransport</c> through <c>WebTransport.jslib</c>.
    /// </summary>
    /// <remarks>
    /// The browser runs everything on the page's one thread and cannot call into C# cheaply, so it queues what arrives and
    /// <see cref="Poll"/> asks for it on every receive pass. Each received packet is copied straight into an array rented from
    /// <see cref="TrackedArrayPool{T0}"/>, and each sent packet is copied out of the engine's buffer before the call returns.
    /// </remarks>
    internal sealed class BrowserSession : WebTransportSession
    {
        /// <summary>
        /// Where the session reports.
        /// </summary>
        private readonly WebTransportEvents _events;
        /// <summary>
        /// The session's number on the JavaScript side.
        /// </summary>
        private readonly int _sessionId;
        /// <summary>
        /// Whether the session opening has been reported.
        /// </summary>
        private bool _isOpenReported;
        /// <summary>
        /// Whether the session closing has been reported.
        /// </summary>
        private bool _isCloseReported;
        /// <summary>
        /// The JavaScript state of a session still connecting.
        /// </summary>
        private const int ConnectingState = 0;
        /// <summary>
        /// The JavaScript state of an open session.
        /// </summary>
        private const int OpenState = 1;

        /// <summary>
        /// Creates a session for one the browser has started.
        /// </summary>
        /// <param name="events">Where the session reports.</param>
        /// <param name="sessionId">The session's number on the JavaScript side.</param>
        /// <param name="remoteHost">The server's host.</param>
        private BrowserSession(WebTransportEvents events, int sessionId, string remoteHost)
        {
            _events = events;
            _sessionId = sessionId;
            RemoteAddress = remoteHost;
        }

        /// <inheritdoc/>
        internal override bool TrySend(Channel channel, ArraySegment<byte> payload) => payload.Array is not null && WebTransportSend(_sessionId, payload.Array, payload.Offset, payload.Count, channel is Channel.Reliable ? 1 : 0) != 0;

        /// <inheritdoc/>
        /// <remarks>
        /// Every packet the browser has queued is taken before a close is reported, so the last ones, a kick's reason among them, reach the
        /// game first.
        /// </remarks>
        internal override void Poll()
        {
            int state = WebTransportGetState(_sessionId);

            if (!_isOpenReported && state == OpenState)
            {
                _isOpenReported = true;
                _events.EnqueueOpened(this);
            }

            int packetSize;

            while ((packetSize = WebTransportPeekSize(_sessionId)) >= 0)
            {
                byte[] payloadArray = TrackedArrayPool<byte>.Rent(Math.Max(packetSize, 1));
                Channel channel = WebTransportReceive(_sessionId, payloadArray, packetSize) == 1 ? Channel.Reliable : Channel.Unreliable;

                _events.EnqueueReceived(this, new(payloadArray, 0, packetSize), channel);
            }

            if (_isCloseReported || state is ConnectingState or OpenState)
                return;

            _isCloseReported = true;
            CloseReason = "the browser closed the WebTransport session; its console says why";
            _events.EnqueueClosed(this);
        }

        /// <inheritdoc/>
        /// <remarks>The browser has no way to hold a close until its reliable data is acknowledged, so this closes at once either way.</remarks>
        internal override void Close(bool isAfterDelivery) => WebTransportClose(_sessionId);

        /// <summary>
        /// Asks the browser to open a session to a server.
        /// </summary>
        /// <param name="events">Where the session reports.</param>
        /// <param name="remoteHost">The server's host name or IP address.</param>
        /// <param name="remotePort">The server's port.</param>
        /// <param name="pinnedCertificateHash">The hash the server's certificate must have, or <see langword="null"/> to rely on the browser's trust store.</param>
        /// <param name="browserSession">The session.</param>
        /// <returns>True when the browser started connecting.</returns>
        internal static bool TryConnect(WebTransportEvents events, string remoteHost, ushort remotePort, byte[] pinnedCertificateHash, out BrowserSession browserSession)
        {
            string host = remoteHost.IndexOf(':') >= 0 && !remoteHost.StartsWith("[", StringComparison.Ordinal) ? $"[{remoteHost}]" : remoteHost;
            string certificateHash = pinnedCertificateHash is null ? string.Empty : SelfSignedCertificate.ToHex(pinnedCertificateHash);

            browserSession = new(events, WebTransportConnect($"https://{host}:{remotePort}/", certificateHash), remoteHost);

            return true;
        }

        /// <summary>
        /// Starts a session and returns its number.
        /// </summary>
        [DllImport("__Internal")]
        private static extern int WebTransportConnect(string url, string certificateHash);

        /// <summary>
        /// Reads a session's state: connecting, open, or closed.
        /// </summary>
        [DllImport("__Internal")]
        private static extern int WebTransportGetState(int sessionId);

        /// <summary>
        /// Reads the size of the oldest packet received, or minus one when there is none.
        /// </summary>
        [DllImport("__Internal")]
        private static extern int WebTransportPeekSize(int sessionId);

        /// <summary>
        /// Copies the oldest packet received into a buffer and returns its channel: one for reliable, zero for unreliable.
        /// </summary>
        [DllImport("__Internal")]
        private static extern int WebTransportReceive(int sessionId, byte[] buffer, int capacity);

        /// <summary>
        /// Sends a packet, copying it first, and returns one when the browser took it.
        /// </summary>
        [DllImport("__Internal")]
        private static extern int WebTransportSend(int sessionId, byte[] buffer, int offset, int length, int isReliable);

        /// <summary>
        /// Closes a session and forgets it.
        /// </summary>
        [DllImport("__Internal")]
        private static extern void WebTransportClose(int sessionId);
    }
}
#endif
