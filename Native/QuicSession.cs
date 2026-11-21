#if !UNITY_WEBGL || UNITY_EDITOR
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CodeBoost.Logging;
using CodeBoost.Performance;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// A WebTransport session over one MsQuic connection, on either side.
    /// </summary>
    /// <remarks>
    /// <para>
    /// MsQuic raises every event for a connection and its streams on one worker thread at a time, so everything this session keeps about
    /// its streams is touched only there. The handles the network loop thread sends through are guarded by <see cref="_lock"/>, because
    /// the worker closes them; MsQuic's send and shutdown calls queue work and return, so holding the lock across them blocks nothing.
    /// </para>
    /// <para>
    /// Every buffer handed to MsQuic to send is allocated from native memory with the bytes copied in, because MsQuic reads it after the
    /// call returns, and is freed from the event that reports the send finished. The session object itself is kept alive by a
    /// <see cref="GCHandle"/> that MsQuic holds as the context of the connection and its streams, freed once the connection is closed.
    /// </para>
    /// </remarks>
    internal sealed unsafe class QuicSession : WebTransportSession
    {
        /// <summary>
        /// The MsQuic copy the connection was opened with.
        /// </summary>
        private readonly MsQuic _msQuic;
        /// <summary>
        /// Where this session reports opening, receiving and closing.
        /// </summary>
        private readonly WebTransportEvents _events;
        /// <summary>
        /// The listener that accepted this session and counts it until it is released, or <see langword="null"/> for a client's session.
        /// </summary>
        private readonly QuicListener _quicListener;
        /// <summary>
        /// Whether this is a server's session, which waits for the peer's CONNECT, rather than a client's, which sends it.
        /// </summary>
        private readonly bool _isServer;
        /// <summary>
        /// The largest reliable packet the peer may send.
        /// </summary>
        private readonly int _maximumReliablePacketSize;
        /// <summary>
        /// The SHA-256 the server's certificate must hash to, or <see langword="null"/> to validate it against the system's trust store.
        /// </summary>
        private readonly byte[] _pinnedCertificateHash;
        /// <summary>
        /// The host and port a client's CONNECT names.
        /// </summary>
        private readonly string _authority;
        /// <summary>
        /// Guards the handles and flags the network loop thread reads.
        /// </summary>
        private readonly object _lock = new();
        /// <summary>
        /// The streams of this connection, by handle.
        /// </summary>
        /// <remarks>Touched only on the MsQuic worker thread.</remarks>
        private readonly Dictionary<IntPtr, QuicStream> _streamsByHandle = new();
        /// <summary>
        /// The handle MsQuic holds as this session's context.
        /// </summary>
        private GCHandle _contextHandle;
        /// <summary>
        /// The connection, until it is closed.
        /// </summary>
        private IntPtr _connection;
        /// <summary>
        /// The stream reliable packets travel on, once there is one.
        /// </summary>
        private IntPtr _reliableStream;
        /// <summary>
        /// The session's identifier, which is the identifier of the stream its CONNECT was sent on.
        /// </summary>
        private long _sessionId = UnsetStreamId;
        /// <summary>
        /// The session a reliable stream named, held while a server still waits for that session's CONNECT.
        /// </summary>
        private long _reliableStreamSessionId = UnsetStreamId;
        /// <summary>
        /// Whether the session has opened and not yet closed, which is when packets may be sent.
        /// </summary>
        private bool _isOpen;
        /// <summary>
        /// Whether this side has begun shutting the connection down.
        /// </summary>
        private bool _isShutdownRequested;
        /// <summary>
        /// Whether the connection shuts down once the reliable stream has delivered everything queued on it.
        /// </summary>
        private bool _isClosingAfterDelivery;
        /// <summary>
        /// Whether the close has been queued, which happens once.
        /// </summary>
        /// <remarks>Touched only on the MsQuic worker thread.</remarks>
        private bool _isCloseReported;
        /// <summary>
        /// Whether an unreliable packet too large for a datagram has been logged, which happens once a session.
        /// </summary>
        private bool _isOversizedDatagramLogged;
        /// <summary>
        /// The largest datagram, its session prefix included, the connection can send now; zero while it can send none.
        /// </summary>
        private int _maximumDatagramSize;
        /// <summary>
        /// How many streams the peer has opened on this connection.
        /// </summary>
        /// <remarks>Touched only on the MsQuic worker thread.</remarks>
        private uint _peerStreamCount;
        /// <summary>
        /// The handler MsQuic calls for connection events, held so it is never collected.
        /// </summary>
        private static readonly MsQuic.ConnectionCallback ConnectionHandler = OnConnectionEvent;
        /// <summary>
        /// The handler MsQuic calls for stream events, held so it is never collected.
        /// </summary>
        private static readonly MsQuic.StreamCallback StreamHandler = OnStreamEvent;
        /// <summary>
        /// The native entry point for <see cref="ConnectionHandler"/>.
        /// </summary>
        private static readonly IntPtr ConnectionHandlerPointer = Marshal.GetFunctionPointerForDelegate(ConnectionHandler);
        /// <summary>
        /// The native entry point for <see cref="StreamHandler"/>.
        /// </summary>
        private static readonly IntPtr StreamHandlerPointer = Marshal.GetFunctionPointerForDelegate(StreamHandler);
        /// <summary>
        /// The value of a stream identifier not yet known.
        /// </summary>
        private const long UnsetStreamId = -1;
        /// <summary>
        /// The most bytes a request or its response may send before its headers are complete.
        /// </summary>
        private const int MaximumHeaderBytes = 16 * 1024;
        /// <summary>
        /// The most packets this session may have queued unread before a datagram is dropped, as a full socket drops one.
        /// </summary>
        /// <remarks>A network loop that keeps up never comes near it; a long stall loses the newest datagrams rather than holding everything.</remarks>
        private const int MaximumQueuedDatagramCount = 1024;
        /// <summary>
        /// The most packets this session may have queued unread before a reliable packet closes it.
        /// </summary>
        /// <remarks>
        /// A reliable packet cannot be dropped without breaking the stream, so the session closes instead. Far above
        /// <see cref="MaximumQueuedDatagramCount"/>, which datagrams therefore never fill it to: only a peer flooding reliable packets, or a
        /// network loop stalled for minutes, reaches it.
        /// </remarks>
        private const int MaximumQueuedReliablePacketCount = 16384;
        /// <summary>
        /// The most streams the peer may open over the connection's life, well past the ones a session opens: its control and QPACK streams,
        /// its CONNECT and its reliable stream.
        /// </summary>
        /// <remarks>
        /// MsQuic gives the peer room for another stream each time one closes, so the limit on streams open at once never stops a peer that
        /// resets every stream it opens; this one does, by closing the connection.
        /// </remarks>
        private const uint MaximumPeerStreamCount = 32;

        /// <summary>
        /// Creates a session and the handle MsQuic will hold as its context.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy the connection belongs to.</param>
        /// <param name="events">Where the session reports.</param>
        /// <param name="quicListener">The listener that accepted a server's session, or <see langword="null"/> for a client's.</param>
        /// <param name="isServer">Whether this is a server's session.</param>
        /// <param name="maximumReliablePacketSize">The largest reliable packet the peer may send.</param>
        /// <param name="pinnedCertificateHash">The hash a client requires of the server's certificate, or <see langword="null"/>.</param>
        /// <param name="authority">The host and port a client's CONNECT names, or <see langword="null"/> on a server.</param>
        private QuicSession(MsQuic msQuic, WebTransportEvents events, QuicListener quicListener, bool isServer, int maximumReliablePacketSize, byte[] pinnedCertificateHash, string authority)
        {
            _msQuic = msQuic;
            _events = events;
            _quicListener = quicListener;
            _isServer = isServer;
            _maximumReliablePacketSize = maximumReliablePacketSize;
            _pinnedCertificateHash = pinnedCertificateHash;
            _authority = authority;
            _contextHandle = GCHandle.Alloc(this);
        }

        /// <summary>
        /// Sends a packet: a datagram prefixed with the session, or a frame on the reliable stream prefixed with its length.
        /// </summary>
        /// <param name="channel">The channel the engine chose.</param>
        /// <param name="payload">The packet, copied before this returns.</param>
        /// <returns>True when MsQuic took the packet.</returns>
        internal override bool TrySend(Channel channel, ArraySegment<byte> payload)
        {
            if (payload.Array is null)
                return false;

            lock (_lock)
            {
                if (!_isOpen)
                    return false;

                bool isReliable = channel is Channel.Reliable;
                ulong prefix = isReliable ? (ulong)payload.Count : (ulong)(_sessionId >> 2);
                int prefixSize = Http3.GetVariableLengthIntegerSize(prefix);
                int dataLength = prefixSize + payload.Count;

                if (!isReliable && dataLength > _maximumDatagramSize)
                {
                    if (!_isOversizedDatagramLogged)
                    {
                        _isOversizedDatagramLogged = true;
                        Logger<QuicSession>.LogWarning($"An unreliable packet of [{payload.Count}] bytes does not fit the [{_maximumDatagramSize}] bytes a datagram to [{RemoteAddress}] can carry, so it was dropped. Lower the maximum transmission unit.");
                    }

                    return false;
                }

                IntPtr sendBlock = AllocateSendBlock(dataLength, out MsQuic.QuicBuffer* quicBuffer);
                Http3.WriteVariableLengthInteger(quicBuffer->Buffer, prefix);
                Marshal.Copy(payload.Array, payload.Offset, (IntPtr)(quicBuffer->Buffer + prefixSize), payload.Count);

                int sendStatus = isReliable ? _msQuic.StreamSend(_reliableStream, quicBuffer, 1, 0, sendBlock) : _msQuic.DatagramSend(_connection, quicBuffer, 1, 0, sendBlock);

                if (_msQuic.IsSucceeded(sendStatus))
                    return true;

                Marshal.FreeHGlobal(sendBlock);

                return false;
            }
        }

        /// <inheritdoc/>
        /// <remarks>
        /// After delivery, the reliable stream's sending side is finished cleanly and the connection is shut down once MsQuic reports the
        /// peer has acknowledged everything on it, so a kick's reason survives a lost datagram.
        /// </remarks>
        internal override void Close(bool isAfterDelivery)
        {
            lock (_lock)
            {
                _isOpen = false;

                if (_isShutdownRequested || _connection == IntPtr.Zero)
                    return;

                _isShutdownRequested = true;

                if (isAfterDelivery && _reliableStream != IntPtr.Zero && _msQuic.IsSucceeded(_msQuic.StreamShutdown(_reliableStream, MsQuic.StreamShutdownGracefulFlag, 0)))
                {
                    _isClosingAfterDelivery = true;

                    return;
                }

                _msQuic.ConnectionShutdown(_connection, 0, MsQuic.NoErrorCode);
            }
        }

        /// <summary>
        /// Shuts the connection down unless its session has opened, for a peer that has not opened one in time or a listener that is
        /// stopping.
        /// </summary>
        /// <remarks>
        /// Called from the network loop thread. The lock orders it against the worker opening the session, so the session is either opened
        /// and left alone, or shut down and never opened.
        /// </remarks>
        internal void CloseUnlessOpened()
        {
            lock (_lock)
            {
                if (_isOpen || _isShutdownRequested || _connection == IntPtr.Zero)
                    return;

                _isShutdownRequested = true;
                _msQuic.ConnectionShutdown(_connection, 0, MsQuic.NoErrorCode);
            }
        }

        /// <summary>
        /// Takes up a connection a server's listener has just accepted.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy the listener belongs to.</param>
        /// <param name="events">Where the session reports.</param>
        /// <param name="quicListener">The listener, which counts the session until it is released.</param>
        /// <param name="connection">The accepted connection.</param>
        /// <param name="configuration">The server configuration to hand it.</param>
        /// <param name="remoteAddress">The address the peer connected from.</param>
        /// <param name="maximumReliablePacketSize">The largest reliable packet the peer may send.</param>
        /// <param name="quicSession">The session, or <see langword="null"/> when the connection was refused.</param>
        /// <returns>The status for the listener to return; a failure refuses the connection.</returns>
        /// <remarks>Called from the listener's event, on an MsQuic worker thread. No event reaches the session until that event has returned.</remarks>
        internal static int Accept(MsQuic msQuic, WebTransportEvents events, QuicListener quicListener, IntPtr connection, IntPtr configuration, string remoteAddress, int maximumReliablePacketSize, out QuicSession quicSession)
        {
            quicSession = null;

            // Configured first, so a refused connection is never given a handler, MsQuic closing a refused connection itself.
            int configurationStatus = msQuic.ConnectionSetConfiguration(connection, configuration);

            if (!msQuic.IsSucceeded(configurationStatus))
                return configurationStatus;

            quicSession = new(msQuic, events, quicListener, isServer: true, maximumReliablePacketSize, pinnedCertificateHash: null, authority: null)
            {
                RemoteAddress = remoteAddress,
                _connection = connection,
            };

            msQuic.SetCallbackHandler(connection, ConnectionHandlerPointer, GCHandle.ToIntPtr(quicSession._contextHandle));

            return MsQuic.SuccessStatus;
        }

        /// <summary>
        /// Opens a client connection to a WebTransport server.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy to open it with.</param>
        /// <param name="events">Where the session reports.</param>
        /// <param name="configuration">The client configuration.</param>
        /// <param name="host">The server's host name or IP address.</param>
        /// <param name="port">The server's port.</param>
        /// <param name="pinnedCertificateHash">The hash the server's certificate must have, or <see langword="null"/> to validate it against the system's trust store.</param>
        /// <param name="quicSession">The session, which reports opening or closing through <paramref name="events"/>.</param>
        /// <returns>True when the connection was started.</returns>
        internal static bool TryConnect(MsQuic msQuic, WebTransportEvents events, IntPtr configuration, string host, ushort port, byte[] pinnedCertificateHash, out QuicSession quicSession)
        {
            quicSession = new(msQuic, events, quicListener: null, isServer: false, int.MaxValue, pinnedCertificateHash, authority: $"{host}:{port}") { RemoteAddress = host };

            IntPtr connection;
            int openStatus = msQuic.ConnectionOpen(msQuic.Registration, ConnectionHandlerPointer, GCHandle.ToIntPtr(quicSession._contextHandle), &connection);

            if (!msQuic.IsSucceeded(openStatus))
            {
                Logger<QuicSession>.LogError($"An MsQuic connection could not be opened: status [0x{openStatus:X8}].");
                quicSession._contextHandle.Free();
                quicSession = null;

                return false;
            }

            lock (quicSession._lock)
                quicSession._connection = connection;

            byte[] hostBytes = Encoding.ASCII.GetBytes($"{host}\0");
            int startStatus;

            fixed (byte* hostPointer = hostBytes)
                startStatus = msQuic.ConnectionStart(connection, configuration, MsQuic.UnspecifiedAddressFamily, hostPointer, port);

            if (msQuic.IsSucceeded(startStatus))
                return true;

            Logger<QuicSession>.LogError($"The connection to [{host}:{port}] could not be started: status [0x{startStatus:X8}].");

            lock (quicSession._lock)
                quicSession._connection = IntPtr.Zero;

            msQuic.ConnectionClose(connection);
            quicSession._contextHandle.Free();
            quicSession = null;

            return false;
        }

        /// <summary>
        /// Handles a connection event.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <param name="connectionEvent">The event.</param>
        /// <returns>The status MsQuic is answered with.</returns>
        private int HandleConnectionEvent(IntPtr connection, MsQuic.ConnectionEvent* connectionEvent)
        {
            switch (connectionEvent->Type)
            {
                case MsQuic.ConnectionEvent.ConnectedType:
                    OpenStream(connection, QuicStreamKind.Ignored, isUnidirectional: true, Http3.CreateControlStream());

                    if (!_isServer && OpenStream(connection, QuicStreamKind.Response, isUnidirectional: false, Http3.CreateConnectRequest(_authority)) == IntPtr.Zero)
                        ShutDown("the CONNECT request could not be sent");

                    break;
                case MsQuic.ConnectionEvent.ShutdownInitiatedByTransportType:
                    ReportClosed($"MsQuic status [0x{connectionEvent->ShutdownStatus:X8}]");

                    break;
                case MsQuic.ConnectionEvent.ShutdownInitiatedByPeerType:
                    ReportClosed($"the peer closed the connection with error code [0x{connectionEvent->PeerErrorCode:X}]");

                    break;
                case MsQuic.ConnectionEvent.ShutdownCompleteType:
                    ReportClosed("the connection shut down");

                    // A connection a failed connect closed itself is released by that connect, which still holds the handle.
                    if ((connectionEvent->ShutdownCompleteFlags & MsQuic.ConnectionEvent.AppCloseInProgressFlag) == 0)
                        Release(connection);

                    break;
                case MsQuic.ConnectionEvent.PeerStreamStartedType:
                {
                    bool isUnidirectional = (connectionEvent->PeerStreamFlags & MsQuic.ConnectionEvent.UnidirectionalStreamFlag) != 0;

                    // A server reads which kind of stream a two-way stream is from its first bytes; anything else the peer opens is read and dropped.
                    _streamsByHandle[connectionEvent->PeerStream] = new() { Kind = _isServer && !isUnidirectional ? QuicStreamKind.Unclassified : QuicStreamKind.Ignored };
                    _msQuic.SetCallbackHandler(connectionEvent->PeerStream, StreamHandlerPointer, GCHandle.ToIntPtr(_contextHandle));

                    if (++_peerStreamCount > MaximumPeerStreamCount)
                        ShutDown($"the peer opened more than the [{MaximumPeerStreamCount}] streams a session may");

                    break;
                }
                case MsQuic.ConnectionEvent.DatagramStateChangedType:
                    lock (_lock)
                        _maximumDatagramSize = connectionEvent->IsDatagramSendEnabled != 0 ? connectionEvent->MaximumDatagramSendLength : 0;

                    break;
                case MsQuic.ConnectionEvent.DatagramReceivedType:
                    ReceiveDatagram(connectionEvent->DatagramBuffer);

                    break;
                case MsQuic.ConnectionEvent.DatagramSendStateChangedType:
                    if (connectionEvent->DatagramSendState >= MsQuic.ConnectionEvent.FirstFinalDatagramSendState)
                        Marshal.FreeHGlobal(connectionEvent->DatagramClientContext);

                    break;
                case MsQuic.ConnectionEvent.PeerCertificateReceivedType:
                    return IsPinnedCertificate(connectionEvent->PeerCertificate) ? MsQuic.SuccessStatus : _msQuic.GetBadCertificateStatus();
            }

            return MsQuic.SuccessStatus;
        }

        /// <summary>
        /// Handles a stream event.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="streamEvent">The event.</param>
        private void HandleStreamEvent(IntPtr stream, MsQuic.StreamEvent* streamEvent)
        {
            _streamsByHandle.TryGetValue(stream, out QuicStream quicStream);

            switch (streamEvent->Type)
            {
                case MsQuic.StreamEvent.ReceiveType:
                    if (quicStream is null || quicStream.Kind is QuicStreamKind.Ignored or QuicStreamKind.Session)
                        return;

                    for (uint i = 0; i < streamEvent->ReceiveBufferCount; i++)
                        quicStream.Append(streamEvent->ReceiveBuffers[i].Buffer, (int)streamEvent->ReceiveBuffers[i].Length);

                    ProcessReceived(stream, quicStream);

                    return;
                case MsQuic.StreamEvent.SendCompleteType:
                    Marshal.FreeHGlobal(streamEvent->SendClientContext);

                    return;
                case MsQuic.StreamEvent.PeerSendShutdownType:
                case MsQuic.StreamEvent.PeerSendAbortedType:
                case MsQuic.StreamEvent.PeerReceiveAbortedType:
                    // The CONNECT stream ending ends the session, and so does the reliable stream ending, which can carry nothing more.
                    if (quicStream is { Kind: QuicStreamKind.Session or QuicStreamKind.Response or QuicStreamKind.Reliable })
                        ShutDown("the peer ended the session");

                    return;
                case MsQuic.StreamEvent.SendShutdownCompleteType:
                    lock (_lock)
                    {
                        if (!_isClosingAfterDelivery || stream != _reliableStream || _connection == IntPtr.Zero)
                            return;

                        _isClosingAfterDelivery = false;
                        _msQuic.ConnectionShutdown(_connection, 0, MsQuic.NoErrorCode);
                    }

                    return;
                case MsQuic.StreamEvent.ShutdownCompleteType:
                    lock (_lock)
                    {
                        if (stream == _reliableStream)
                            _reliableStream = IntPtr.Zero;
                    }

                    if (quicStream is not null)
                    {
                        quicStream.ReturnBuffer();
                        _streamsByHandle.Remove(stream);
                    }

                    // A stream this session closed itself, having never started it, is already being closed.
                    if ((streamEvent->ShutdownCompleteFlags & MsQuic.StreamEvent.AppCloseInProgressFlag) == 0)
                        _msQuic.StreamClose(stream);

                    return;
            }
        }

        /// <summary>
        /// Reads what has arrived on a stream as far as its kind allows.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="quicStream">What is kept about it.</param>
        private void ProcessReceived(IntPtr stream, QuicStream quicStream)
        {
            if (quicStream.Kind is QuicStreamKind.Unclassified)
                ClassifyPeerStream(stream, quicStream);

            switch (quicStream.Kind)
            {
                case QuicStreamKind.Request:
                    ProcessRequest(stream, quicStream);

                    break;
                case QuicStreamKind.Response:
                    ProcessResponse(stream, quicStream);

                    break;
                case QuicStreamKind.Reliable:
                    if (_isOpen)
                    {
                        ExtractReliablePackets(quicStream);
                    }
                    else if (quicStream.Count - Http3.MaximumVariableLengthIntegerSize > _maximumReliablePacketSize)
                    {
                        // Nothing is read off a reliable stream until its session opens, so a peer that never opens one is held to one packet.
                        quicStream.Kind = QuicStreamKind.Ignored;
                        quicStream.Count = 0;
                        ShutDown($"more than one packet of the [{_maximumReliablePacketSize}] bytes allowed arrived on the reliable stream before its session opened");
                    }

                    break;
            }
        }

        /// <summary>
        /// Reads whether a two-way stream a client opened is a request or a WebTransport stream, once its first bytes are in.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="quicStream">What is kept about it, whose kind is set here.</param>
        private void ClassifyPeerStream(IntPtr stream, QuicStream quicStream)
        {
            int offset = 0;

            if (!Http3.TryReadVariableLengthInteger(quicStream.Buffer, ref offset, quicStream.Count, out ulong signal))
                return;

            if (signal != Http3.BidirectionalStreamSignal)
            {
                quicStream.Kind = QuicStreamKind.Request;

                return;
            }

            if (!Http3.TryReadVariableLengthInteger(quicStream.Buffer, ref offset, quicStream.Count, out ulong sessionId))
                return;

            quicStream.Consume(offset);

            // One session carries one reliable stream; a second is refused rather than interleaved with the first.
            if (_reliableStreamSessionId != UnsetStreamId)
            {
                quicStream.Kind = QuicStreamKind.Ignored;
                _msQuic.StreamShutdown(stream, MsQuic.StreamShutdownAbortFlag, MsQuic.RequestRejectedErrorCode);

                return;
            }

            quicStream.Kind = QuicStreamKind.Reliable;
            _reliableStreamSessionId = (long)sessionId;

            lock (_lock)
                _reliableStream = stream;

            TryOpenServerSession();
        }

        /// <summary>
        /// Reads a client's CONNECT once its headers are in, accepting the first that asks for WebTransport and refusing anything else.
        /// </summary>
        /// <param name="stream">The request stream.</param>
        /// <param name="quicStream">What is kept about it.</param>
        private void ProcessRequest(IntPtr stream, QuicStream quicStream)
        {
            int offset = 0;

            if (!Http3.TryReadHeadersFrame(quicStream.Buffer, ref offset, quicStream.Count, out int fieldSectionOffset, out int fieldSectionEnd))
            {
                if (quicStream.Count > MaximumHeaderBytes)
                    RefuseRequest(stream, quicStream);

                return;
            }

            if (_sessionId != UnsetStreamId || !Http3.IsWebTransportConnectRequest(quicStream.Buffer, fieldSectionOffset, fieldSectionEnd))
            {
                RefuseRequest(stream, quicStream);

                return;
            }

            // Whatever follows the headers on a CONNECT stream is capsules this transport has no use for.
            quicStream.Kind = QuicStreamKind.Session;
            quicStream.Count = 0;
            _sessionId = _msQuic.GetStreamId(stream);

            if (!TrySendBytes(stream, Http3.CreateConnectResponse(), flags: 0))
            {
                ShutDown("the CONNECT response could not be sent");

                return;
            }

            TryOpenServerSession();
        }

        /// <summary>
        /// Reads the server's answer to this client's CONNECT, opening the reliable stream when the session was accepted.
        /// </summary>
        /// <param name="stream">The request stream.</param>
        /// <param name="quicStream">What is kept about it.</param>
        private void ProcessResponse(IntPtr stream, QuicStream quicStream)
        {
            int offset = 0;

            if (!Http3.TryReadHeadersFrame(quicStream.Buffer, ref offset, quicStream.Count, out int fieldSectionOffset, out int fieldSectionEnd))
            {
                if (quicStream.Count > MaximumHeaderBytes)
                {
                    quicStream.Kind = QuicStreamKind.Ignored;
                    quicStream.Count = 0;
                    ShutDown($"the server sent more than [{MaximumHeaderBytes}] bytes without finishing its response headers");
                }

                return;
            }

            bool isOkResponse = Http3.IsOkResponse(quicStream.Buffer, fieldSectionOffset, fieldSectionEnd);

            quicStream.Kind = QuicStreamKind.Session;
            quicStream.Count = 0;

            if (!isOkResponse)
            {
                ShutDown("the server refused the WebTransport session");

                return;
            }

            _sessionId = _msQuic.GetStreamId(stream);

            IntPtr reliableStream = OpenStream(_connection, QuicStreamKind.Reliable, isUnidirectional: false, Http3.CreateBidirectionalStreamHeader(_sessionId));

            if (reliableStream == IntPtr.Zero)
            {
                ShutDown("the reliable stream could not be opened");

                return;
            }

            lock (_lock)
            {
                _reliableStream = reliableStream;

                if (_isShutdownRequested)
                    return;

                _isOpen = true;
            }

            _events.EnqueueOpened(this);
        }

        /// <summary>
        /// Opens a server's session once both its CONNECT has been accepted and its reliable stream has arrived, which can happen in
        /// either order.
        /// </summary>
        private void TryOpenServerSession()
        {
            if (_sessionId == UnsetStreamId || _reliableStreamSessionId == UnsetStreamId)
                return;

            if (_reliableStreamSessionId != _sessionId)
            {
                ShutDown("the reliable stream named a session this connection does not carry");

                return;
            }

            IntPtr reliableStream;

            lock (_lock)
            {
                if (_isShutdownRequested)
                    return;

                _isOpen = true;
                reliableStream = _reliableStream;
            }

            _events.EnqueueOpened(this);

            // Anything that arrived on the reliable stream before the session opened was held, so it reaches the engine after the session does.
            if (_streamsByHandle.TryGetValue(reliableStream, out QuicStream reliableQuicStream))
                ExtractReliablePackets(reliableQuicStream);
        }

        /// <summary>
        /// Queues every whole reliable packet a stream holds, keeping any partial one for the next read.
        /// </summary>
        /// <param name="quicStream">The reliable stream.</param>
        private void ExtractReliablePackets(QuicStream quicStream)
        {
            int offset = 0;

            while (true)
            {
                int frameOffset = offset;

                if (!Http3.TryReadVariableLengthInteger(quicStream.Buffer, ref frameOffset, quicStream.Count, out ulong packetLength))
                    break;

                if (packetLength > (ulong)_maximumReliablePacketSize)
                {
                    quicStream.Count = 0;
                    ShutDown($"a reliable packet of [{packetLength}] bytes is larger than the [{_maximumReliablePacketSize}] allowed");

                    return;
                }

                if ((ulong)(quicStream.Count - frameOffset) < packetLength)
                    break;

                // An empty frame only announces the stream, so it carries nothing to deliver.
                if (packetLength > 0)
                {
                    byte[] payloadArray = TrackedArrayPool<byte>.Rent((int)packetLength);
                    Buffer.BlockCopy(quicStream.Buffer, frameOffset, payloadArray, 0, (int)packetLength);

                    if (!_events.TryEnqueueReceived(this, new(payloadArray, 0, (int)packetLength), Channel.Reliable, MaximumQueuedReliablePacketCount))
                    {
                        TrackedArrayPool<byte>.Return(payloadArray);
                        quicStream.Kind = QuicStreamKind.Ignored;
                        quicStream.Count = 0;
                        ShutDown($"more than [{MaximumQueuedReliablePacketCount}] packets arrived before they were read");

                        return;
                    }
                }

                offset = frameOffset + (int)packetLength;
            }

            quicStream.Consume(offset);
        }

        /// <summary>
        /// Queues a datagram that names this session.
        /// </summary>
        /// <param name="datagram">The datagram, valid only during the event.</param>
        private void ReceiveDatagram(MsQuic.QuicBuffer* datagram)
        {
            if (!_isOpen || datagram is null)
                return;

            int prefixSize = Http3.ReadVariableLengthInteger(datagram->Buffer, (int)datagram->Length, out ulong quarterStreamId);

            if (prefixSize == 0 || quarterStreamId != (ulong)(_sessionId >> 2))
                return;

            int payloadLength = (int)datagram->Length - prefixSize;

            if (payloadLength == 0)
                return;

            byte[] payloadArray = TrackedArrayPool<byte>.Rent(payloadLength);
            Marshal.Copy((IntPtr)(datagram->Buffer + prefixSize), payloadArray, 0, payloadLength);

            if (!_events.TryEnqueueReceived(this, new(payloadArray, 0, payloadLength), Channel.Unreliable, MaximumQueuedDatagramCount))
                TrackedArrayPool<byte>.Return(payloadArray);
        }

        /// <summary>
        /// Opens a stream and starts it with its first bytes.
        /// </summary>
        /// <param name="connection">The connection to open it on.</param>
        /// <param name="quicStreamKind">What the stream is for.</param>
        /// <param name="isUnidirectional">Whether the stream sends one way only.</param>
        /// <param name="firstBytes">The bytes it starts with.</param>
        /// <returns>The stream, or <see cref="IntPtr.Zero"/> when it could not be opened.</returns>
        private IntPtr OpenStream(IntPtr connection, QuicStreamKind quicStreamKind, bool isUnidirectional, byte[] firstBytes)
        {
            IntPtr stream;
            int openStatus = _msQuic.StreamOpen(connection, isUnidirectional ? MsQuic.StreamOpenUnidirectionalFlag : 0, StreamHandlerPointer, GCHandle.ToIntPtr(_contextHandle), &stream);

            if (!_msQuic.IsSucceeded(openStatus))
            {
                Logger<QuicSession>.LogError($"An MsQuic stream could not be opened: status [0x{openStatus:X8}].");

                return IntPtr.Zero;
            }

            _streamsByHandle[stream] = new() { Kind = quicStreamKind };

            if (TrySendBytes(stream, firstBytes, MsQuic.SendStartFlag))
                return stream;

            // Never started, so it can be closed outright.
            _streamsByHandle.Remove(stream);
            _msQuic.StreamClose(stream);

            return IntPtr.Zero;
        }

        /// <summary>
        /// Queues bytes on a stream from the MsQuic worker thread.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="bytes">The bytes.</param>
        /// <param name="flags">The send flags.</param>
        /// <returns>True when MsQuic took them.</returns>
        private bool TrySendBytes(IntPtr stream, byte[] bytes, int flags)
        {
            IntPtr sendBlock = AllocateSendBlock(bytes.Length, out MsQuic.QuicBuffer* quicBuffer);
            Marshal.Copy(bytes, 0, (IntPtr)quicBuffer->Buffer, bytes.Length);

            if (_msQuic.IsSucceeded(_msQuic.StreamSend(stream, quicBuffer, 1, flags, sendBlock)))
                return true;

            Marshal.FreeHGlobal(sendBlock);

            return false;
        }

        /// <summary>
        /// Refuses a request stream this server will not serve.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="quicStream">What is kept about it.</param>
        private void RefuseRequest(IntPtr stream, QuicStream quicStream)
        {
            quicStream.Kind = QuicStreamKind.Ignored;
            quicStream.Count = 0;
            _msQuic.StreamShutdown(stream, MsQuic.StreamShutdownAbortFlag, MsQuic.RequestRejectedErrorCode);
        }

        /// <summary>
        /// Reports the session closed and shuts the connection down, from the MsQuic worker thread.
        /// </summary>
        /// <param name="reason">Why, for the log.</param>
        private void ShutDown(string reason)
        {
            ReportClosed(reason);

            lock (_lock)
            {
                if (_isShutdownRequested || _connection == IntPtr.Zero)
                    return;

                _isShutdownRequested = true;
                _msQuic.ConnectionShutdown(_connection, 0, MsQuic.NoErrorCode);
            }
        }

        /// <summary>
        /// Stops sends and queues the close, once.
        /// </summary>
        /// <param name="reason">Why, for the log.</param>
        private void ReportClosed(string reason)
        {
            lock (_lock)
                _isOpen = false;

            if (_isCloseReported)
                return;

            _isCloseReported = true;
            CloseReason = reason;
            _events.EnqueueClosed(this);
        }

        /// <summary>
        /// Closes the connection once MsQuic has finished with it, and lets go of everything the session holds.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <remarks>The last event MsQuic raises for a connection, so freeing the context handle here is safe.</remarks>
        private void Release(IntPtr connection)
        {
            lock (_lock)
            {
                _isOpen = false;
                _connection = IntPtr.Zero;
                _reliableStream = IntPtr.Zero;
            }

            foreach (QuicStream quicStream in _streamsByHandle.Values)
                quicStream.ReturnBuffer();

            _streamsByHandle.Clear();
            _msQuic.ConnectionClose(connection);
            _contextHandle.Free();
            _quicListener?.NotifySessionReleased();
        }

        /// <summary>
        /// Returns whether the certificate a server presented hashes to the pinned value and is within the period it is valid for, or
        /// whether no value is pinned.
        /// </summary>
        /// <param name="certificate">The certificate's DER bytes.</param>
        /// <returns>True when the certificate is accepted.</returns>
        /// <remarks>
        /// A pinned certificate is not validated by MsQuic, so its validity is read here, as a browser reads the validity of a certificate it
        /// is given the hash of.
        /// </remarks>
        private bool IsPinnedCertificate(MsQuic.QuicBuffer* certificate)
        {
            if (_pinnedCertificateHash is null)
                return true;

            if (certificate is null || certificate->Length == 0)
                return false;

            byte[] certificateBytes = new byte[certificate->Length];
            Marshal.Copy((IntPtr)certificate->Buffer, certificateBytes, 0, certificateBytes.Length);

            byte[] certificateHash;

            using (SHA256 sha256 = SHA256.Create())
                certificateHash = sha256.ComputeHash(certificateBytes);

            bool isPinned = certificateHash.Length == _pinnedCertificateHash.Length;

            for (int i = 0; isPinned && i < certificateHash.Length; i++)
                isPinned = certificateHash[i] == _pinnedCertificateHash[i];

            if (!isPinned)
            {
                Logger<QuicSession>.LogError($"The server at [{_authority}] presented a certificate whose SHA-256 does not match the pinned certificate hash.");

                return false;
            }

            if (!SelfSignedCertificate.TryReadValidity(certificateBytes, out DateTime notBefore, out DateTime notAfter))
            {
                Logger<QuicSession>.LogError($"The server at [{_authority}] presented a pinned certificate whose validity could not be read.");

                return false;
            }

            DateTime utcNow = DateTime.UtcNow;

            if (utcNow >= notBefore && utcNow <= notAfter)
                return true;

            Logger<QuicSession>.LogError($"The server at [{_authority}] presented its pinned certificate outside the period it is valid for, [{notBefore:u}] to [{notAfter:u}]. A server that makes its own certificate must be restarted before it expires.");

            return false;
        }

        /// <summary>
        /// Allocates native memory holding a <see cref="MsQuic.QuicBuffer"/> followed by its bytes, freed when MsQuic reports the send done.
        /// </summary>
        /// <param name="dataLength">How many bytes the buffer holds.</param>
        /// <param name="quicBuffer">The buffer, pointing at the bytes that follow it.</param>
        /// <returns>The allocation, which is also the send's context.</returns>
        /// <remarks>ponytail: one native allocation per send; pool the blocks if a profile ever shows the allocator.</remarks>
        private static IntPtr AllocateSendBlock(int dataLength, out MsQuic.QuicBuffer* quicBuffer)
        {
            IntPtr sendBlock = Marshal.AllocHGlobal(sizeof(MsQuic.QuicBuffer) + dataLength);
            quicBuffer = (MsQuic.QuicBuffer*)sendBlock;
            quicBuffer->Length = (uint)dataLength;
            quicBuffer->Buffer = (byte*)sendBlock + sizeof(MsQuic.QuicBuffer);

            return sendBlock;
        }

        /// <summary>
        /// Receives MsQuic's connection events.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <param name="context">The session's handle.</param>
        /// <param name="connectionEvent">The event.</param>
        /// <returns>The status MsQuic is answered with.</returns>
        /// <remarks>An exception must never reach native code, so every one is logged here.</remarks>
        [MonoPInvokeCallback(typeof(MsQuic.ConnectionCallback))]
        private static int OnConnectionEvent(IntPtr connection, IntPtr context, MsQuic.ConnectionEvent* connectionEvent)
        {
            try
            {
                return ((QuicSession)GCHandle.FromIntPtr(context).Target).HandleConnectionEvent(connection, connectionEvent);
            }
            catch (Exception exception)
            {
                Logger<QuicSession>.LogError($"A WebTransport connection event caused an exception: {exception}");

                return MsQuic.SuccessStatus;
            }
        }

        /// <summary>
        /// Receives MsQuic's stream events.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="context">The session's handle.</param>
        /// <param name="streamEvent">The event.</param>
        /// <returns>The status MsQuic is answered with, which is always success: everything received is taken.</returns>
        [MonoPInvokeCallback(typeof(MsQuic.StreamCallback))]
        private static int OnStreamEvent(IntPtr stream, IntPtr context, MsQuic.StreamEvent* streamEvent)
        {
            try
            {
                ((QuicSession)GCHandle.FromIntPtr(context).Target).HandleStreamEvent(stream, streamEvent);
            }
            catch (Exception exception)
            {
                Logger<QuicSession>.LogError($"A WebTransport stream event caused an exception: {exception}");
            }

            return MsQuic.SuccessStatus;
        }

        /// <summary>
        /// What a stream is for.
        /// </summary>
        private enum QuicStreamKind : byte
        {
            /// <summary>
            /// Its bytes are dropped: a control or QPACK stream, a refused request, or this side's own control stream.
            /// </summary>
            Ignored = 0,
            /// <summary>
            /// A two-way stream a client opened whose first bytes have not yet said what it is.
            /// </summary>
            Unclassified = 1,
            /// <summary>
            /// A request whose headers a server is waiting on.
            /// </summary>
            Request = 2,
            /// <summary>
            /// A client's CONNECT whose response it is waiting on.
            /// </summary>
            Response = 3,
            /// <summary>
            /// The CONNECT stream of an accepted session, which stays open for as long as the session does.
            /// </summary>
            Session = 4,
            /// <summary>
            /// The stream reliable packets travel on.
            /// </summary>
            Reliable = 5,
        }

        /// <summary>
        /// What is kept about one stream: its kind and the bytes received on it that have not yet been read.
        /// </summary>
        private sealed class QuicStream
        {
            /// <summary>
            /// What the stream is for.
            /// </summary>
            public QuicStreamKind Kind;
            /// <summary>
            /// The bytes not yet read, over an array rented from <see cref="TrackedArrayPool{T0}"/>, or <see langword="null"/> before any arrived.
            /// </summary>
            public byte[] Buffer;
            /// <summary>
            /// How many bytes of <see cref="Buffer"/> are unread.
            /// </summary>
            public int Count;

            /// <summary>
            /// Appends received bytes, growing the buffer when they do not fit.
            /// </summary>
            /// <param name="source">The bytes, valid only during the receive event.</param>
            /// <param name="length">How many there are.</param>
            public void Append(byte* source, int length)
            {
                if (Buffer is null)
                    Buffer = TrackedArrayPool<byte>.Rent(Math.Max(length, 256));
                else if (Buffer.Length - Count < length)
                    TrackedArrayPool<byte>.ResizeWithoutClearing(ref Buffer, Math.Max(Buffer.Length * 2, Count + length));

                Marshal.Copy((IntPtr)source, Buffer, Count, length);
                Count += length;
            }

            /// <summary>
            /// Drops bytes that have been read from the front of the buffer.
            /// </summary>
            /// <param name="length">How many were read.</param>
            public void Consume(int length)
            {
                if (length == 0)
                    return;

                Count -= length;
                System.Buffer.BlockCopy(Buffer, length, Buffer, 0, Count);
            }

            /// <summary>
            /// Hands the buffer back.
            /// </summary>
            public void ReturnBuffer()
            {
                if (Buffer is not null)
                    TrackedArrayPool<byte>.Return(Buffer);

                Buffer = null;
                Count = 0;
            }
        }
    }
}
#endif
