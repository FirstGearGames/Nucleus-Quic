using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using CodeBoost.Logging;
using CodeBoost.Performance;
using Nucleus.Connections;
using Nucleus.Packets;
using Nucleus.Transports.Sockets;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// The server side of a <see cref="Quic"/>. Listens for WebTransport sessions on the configured port and treats each
    /// one as an ordinary Nucleus <see cref="Connection"/>.
    /// </summary>
    public class QuicServerSocket : CommonSocket
    {
        /// <inheritdoc/>
        public override bool IsServer { get; protected set; } = true;
        /// <inheritdoc/>
        public override bool IsEmulated { get; protected set; } = false;

        /// <summary>
        /// Assigns the per-socket ids remote clients are known by.
        /// </summary>
        /// <remarks>Swept once a frame by the TransportManager through <see cref="SweepIdPools"/>, so it runs no timer of its own.</remarks>
        private readonly DelayedUIntPool _idBySocketPool = new(isOwnTimerEnabled: false);
        /// <summary>
        /// Every admitted client's session, by the Connection the engine knows it as.
        /// </summary>
        /// <remarks>Each session names its Connection back through <see cref="WebTransportSession.NucleusConnection"/>; the two are only ever changed together.</remarks>
        private readonly Dictionary<Connection, WebTransportSession> _sessionsByConnection = new();
        /// <summary>
        /// Sessions opening, packets arriving and sessions closing, queued by MsQuic's threads and applied on the receive pass.
        /// </summary>
        private readonly WebTransportEvents _events = new();
        /// <summary>
        /// Clients this server dropped or whose sessions closed, whose departure the receive pass tells the engine once it has admitted every
        /// session that opened in it.
        /// </summary>
        /// <remarks>
        /// Held for the pass rather than told at once, so a drop requested from inside the engine never changes its roster under it, and
        /// held past the pass's admissions, so a departed Connection is never back in its pool while a newcomer is being given one.
        /// </remarks>
        private readonly Queue<Connection> _droppedConnections = new();
#if !UNITY_WEBGL || UNITY_EDITOR
        /// <summary>
        /// The MsQuic copy this socket opened, held until the socket is returned.
        /// </summary>
        private MsQuic _msQuic;
        /// <summary>
        /// The listener, while the server runs.
        /// </summary>
        private QuicListener _quicListener;
#endif
        /// <summary>
        /// This socket's entry for its own transport's client half while that half is paired in process, or null.
        /// </summary>
        /// <remarks>
        /// The client socket's own Connection, borrowed rather than minted, so every check asking whether a peer is this peer answers by
        /// identity. The client socket alone returns it to the pool; this socket only routes packets to it and releases it from the roster.
        /// </remarks>
        private Connection _pairedClientConnection;
        /// <summary>
        /// The socket id rented for <see cref="_pairedClientConnection"/>, held so it goes back to the pool when the pairing ends.
        /// </summary>
        private uint _pairedClientIdBySocket = Connection.UnsetId;
        /// <summary>
        /// Whether the server is listening.
        /// </summary>
        private bool _isListening;

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        public QuicServerSocket() { }

        /// <inheritdoc/>
        public override void Initialize(Transport transport)
        {
            base.Initialize(transport);

            InitializeConnection();

            LocalConnectionStateChanged += TransportManager_OnConnectionLocalStateChanged;

            _idBySocketPool.OnRent();
            _idBySocketPool.Initialize(returnMinutes: 5, firstRentedValue: Connection.UnsetId + 1);
        }

        /// <summary>
        /// Adopts this transport's own client half as a connected peer inside the process, without a WebTransport session or a Connection
        /// of this socket's own.
        /// </summary>
        /// <returns>True when the pairing was made.</returns>
        /// <remarks>
        /// The roster entry is the client socket's own Connection, so the pairing is provable by identity. The roster only borrows it:
        /// leaving the roster releases the server's role and nothing else, and the client socket pools the instance once its link drops.
        /// </remarks>
        internal bool EnsurePairLocalClient()
        {
            if (_pairedClientConnection is not null || State is not LocalConnectionState.Connected || Transport is not Quic { ClientSocket: { Connection: { } pairedClientConnection } })
                return false;

            if (IsConnectionCapReached() || !_idBySocketPool.EnsureRent(out uint idBySocket))
            {
                Logger<QuicServerSocket>.LogWarning("This transport's own client cannot be paired with its server: the server is full or has no id to give it.");

                return false;
            }

            pairedClientConnection.SetRemoteAddress(Quic.LoopbackAddress);

            /* Recorded before the peer is announced. Announcing it runs the authentication owed a new peer synchronously, and that is where
             * the engine asks this transport whether the peer is its own client half, and where the reply admitting it is sent. */
            _pairedClientConnection = pairedClientConnection;
            _pairedClientIdBySocket = idBySocket;

            ConnectionStateChangeResult connectionStateChangeResult = TransportManager.SetRemoteConnectionStateAsConnected(idBySocket, pairedClientConnection);

            if (connectionStateChangeResult is ConnectionStateChangeResult.Success)
                return true;

            Logger<QuicServerSocket>.LogError($"This transport's own client could not be registered: [{connectionStateChangeResult}].");

            _pairedClientConnection = null;
            _pairedClientIdBySocket = Connection.UnsetId;

            // Borrowed from the client socket, so it is released rather than pooled.
            _idBySocketPool.ReturnUnsafe(idBySocket);
            pairedClientConnection.ReleaseServerRole();

            return false;
        }

        /// <summary>
        /// Drops the in-process pairing, driving the departure an ordinary close would drive.
        /// </summary>
        /// <remarks>Idempotent, so a server stopping and a client disconnecting may both reach it.</remarks>
        internal void UnpairLocalClient()
        {
            if (_pairedClientConnection is null)
                return;

            Connection pairedClientConnection = _pairedClientConnection;

            // Cleared first, so a departure handler that sends reads this socket as no longer paired.
            _pairedClientConnection = null;

            if (_pairedClientIdBySocket != Connection.UnsetId)
            {
                _idBySocketPool.ReturnUnsafe(_pairedClientIdBySocket);
                _pairedClientIdBySocket = Connection.UnsetId;
            }

            /* The client socket is told before the departure rather than after, so a handler the departure raises cannot hand this socket
             * another packet for a pairing on its way out. */
            if (Transport is Quic quic)
                quic.ClientSocket?.NotifyLocalPairingEnded();

            SetRemoteConnectionStateAsDisconnected(pairedClientConnection);
        }

        /// <summary>
        /// Takes a packet this transport's own client half sent while paired in process.
        /// </summary>
        /// <param name="outgoingPacket">The packet the client half sent.</param>
        /// <remarks>
        /// Copied into a pooled array, because the sender returns the packet as soon as this comes back. The sender named is this socket's
        /// roster entry for the peer, which is what the receive pass attributes a server-inbound packet by.
        /// </remarks>
        internal void ReceiveLocalPacket(OutgoingPacket outgoingPacket)
        {
            if (State is not LocalConnectionState.Connected || _pairedClientConnection is null)
                return;

            ArraySegment<byte> outgoingPayload = outgoingPacket.Payload;

            if (outgoingPayload.Array is null)
                return;

            byte[] incomingPacketArray = TrackedArrayPool<byte>.Rent(outgoingPayload.Count);
            Array.Copy(outgoingPayload.Array, outgoingPayload.Offset, incomingPacketArray, 0, outgoingPayload.Count);

            IncomingPackets.Enqueue(new(new(incomingPacketArray, 0, outgoingPayload.Count), outgoingPacket.Channel, _pairedClientConnection));
        }

        /// <summary>
        /// Hands what this socket sent its paired client to that client's receive pass.
        /// </summary>
        /// <param name="receivedPackets">The client's received packets, which each handed-over packet is added to.</param>
        /// <remarks>Each packet is copied, the same hand-over an offline transport makes, so the Writer this socket still holds can go back.</remarks>
        internal void HandOverToPairedClient(List<IncomingPacket> receivedPackets)
        {
            while (OutgoingPackets.TryDequeue(out OutgoingPacket outgoingPacket))
            {
                if (TryCopyIntoIncomingPacket(outgoingPacket, out IncomingPacket incomingPacket))
                    receivedPackets.Add(incomingPacket);

                outgoingPacket.Return();
            }
        }

        /// <summary>
        /// Recycles this socket's Connection unless its server is running, for the client half starting or ending a link to another peer.
        /// </summary>
        /// <remarks>
        /// A socket that is not serving lends its Connection to the client half as the stand-in for the remote server, so each such link
        /// takes a fresh one. A running server's Connection describes this peer's own server and is kept.
        /// </remarks>
        internal void RecycleStandInUnlessHosting()
        {
            if (State is not LocalConnectionState.Connected)
                RecycleConnection();
        }

        /// <inheritdoc/>
        protected override void SweepIdPools() => _idBySocketPool.Sweep();

        /// <summary>
        /// Loads or makes the server's certificate and starts listening on the configured port.
        /// </summary>
        /// <returns>The result of the state change.</returns>
        protected override Task<ConnectionStateChangeResult> ConnectAsync()
        {
            if (_isListening)
                return GetResultTask(ConnectionStateChangeResult.AlreadyInState);

#if UNITY_WEBGL && !UNITY_EDITOR
            Logger<QuicServerSocket>.LogError("A WebGL build cannot be a WebTransport server, because a browser cannot accept connections. Only start the client.");

            return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);
#else
            Quic quic = (Quic)Transport;

            if (!TryLoadCertificate(quic, out byte[] certificate))
                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);

            if (_msQuic is null && !MsQuic.TryOpen(out _msQuic))
                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);

            Configuration configuration = quic.Configuration;

            if (!QuicListener.TryStart(_msQuic, _events, certificate, quic.CertificatePassword, configuration.BindAddress, configuration.Port, configuration.ConnectingTimeoutSeconds, configuration.ConnectedTimeoutSeconds, quic.MaximumReliablePacketSize, Transport.ServerConfiguration.MaximumConnections, quic.AllowedOrigins, out _quicListener))
                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);

            _isListening = true;

            if (!TryDriveLocalStateTo(Invoker.Server, LocalConnectionState.Connected))
            {
                StopListening();
                TransportManager.ChangeLocalConnectionState(Invoker.Server, LocalConnectionState.Disconnected, Connection);

                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);
            }

            return GetResultTask(ConnectionStateChangeResult.Success);
#endif
        }

        /// <inheritdoc/>
        protected override Task<ConnectionStateChangeResult> DisconnectAsync()
        {
            if (!_isListening)
                return GetResultTask(ConnectionStateChangeResult.AlreadyInState);

            /* The in-process pairing holds no session, so it appears in no map the walk below reads and is dropped on its own. Queued events
             * are settled next: a session that opened is refused and one that closed is let go, so nobody is admitted later onto a server
             * that has stopped. */
            UnpairLocalClient();
            SettleQueuedEvents();
            DisconnectRemoteClients();
            StopListening();

            return GetResultTask(TryDriveLocalStateTo(Invoker.Server, LocalConnectionState.Disconnected) ? ConnectionStateChangeResult.Success : ConnectionStateChangeResult.UnspecifiedError);
        }

        /// <inheritdoc/>
        protected override Task<ConnectionStateChangeResult> DisconnectRemoteClientAsync(Connection connection) => DisconnectRemoteClientCoreAsync(connection, isAfterDelivery: false);

        /// <inheritdoc/>
        /// <remarks>The session keeps its reliable stream open until the client has acknowledged everything already sent on it, a kick's reason among it, and then closes.</remarks>
        protected override Task<ConnectionStateChangeResult> DisconnectRemoteClientAfterDeliveryAsync(Connection connection) => DisconnectRemoteClientCoreAsync(connection, isAfterDelivery: true);

        /// <inheritdoc/>
        protected override void SendPacket(OutgoingPacket outgoingPacket)
        {
            /* Addressed to this transport's own client half, which holds no session while paired in process. The packet is queued for the
             * client socket's next receive, and its Writer travels with it and is returned there, so it is not offloaded here. */
            if (_pairedClientConnection is not null && ReferenceEquals(outgoingPacket.Receiver, _pairedClientConnection))
            {
                OutgoingPackets.Enqueue(outgoingPacket);

                return;
            }

            if (State is not LocalConnectionState.Connected || outgoingPacket.Receiver is null || !_sessionsByConnection.TryGetValue(outgoingPacket.Receiver, out WebTransportSession webTransportSession))
            {
                Nucleus.Managers.Transports.TransportManager.PacketFailed(outgoingPacket);

                return;
            }

            if (webTransportSession.TrySend(outgoingPacket.Channel, outgoingPacket.Payload))
                Nucleus.Managers.Transports.TransportManager.PacketOffloaded(outgoingPacket);
            else
                Nucleus.Managers.Transports.TransportManager.PacketFailed(outgoingPacket);
        }

        /// <inheritdoc/>
        /// <remarks>
        /// Called by the network loop, which is Unity's main thread under Unity. Every session opening and every packet MsQuic queued since
        /// the last pass is applied in the order it happened, so a client's first packets always find it registered. Departures are told
        /// after them, for the reason <see cref="_droppedConnections"/> records.
        /// </remarks>
        protected override void ReceivePackets(ref List<IncomingPacket> receivedPackets)
        {
#if !UNITY_WEBGL || UNITY_EDITOR
            _quicListener?.CloseLateSessions();
#endif

            while (_events.TryDequeue(out WebTransportEvent webTransportEvent))
            {
                WebTransportSession webTransportSession = webTransportEvent.Session;

                switch (webTransportEvent.Type)
                {
                    case WebTransportEventType.Opened:
                        TryAdmit(webTransportSession);

                        break;
                    case WebTransportEventType.Received:
                        if (webTransportSession.NucleusConnection is { } senderConnection)
                            receivedPackets.Add(new(webTransportEvent.Payload, webTransportEvent.Channel, senderConnection));
                        else
                            TrackedArrayPool<byte>.Return(webTransportEvent.Payload.Array);

                        break;
                    case WebTransportEventType.Closed:
                        if (webTransportSession.NucleusConnection is { } departedConnection)
                        {
                            Forget(webTransportSession);
                            _droppedConnections.Enqueue(departedConnection);
                        }

                        break;
                }
            }

            /* Told only now that every session which opened this pass has been admitted. A departure returns its Connection to a pool that
             * hands the same instance to the next client admitted, while the packets the departed client sent earlier in this pass still name
             * it as their sender, so they would be read as the newcomer's. Told here, that Connection is no longer Connected when the engine
             * reads them, and they are dropped. */
            while (_droppedConnections.TryDequeue(out Connection droppedConnection))
                NotifyDisconnected(droppedConnection, droppedConnection.IdBySocket);

            /* What this transport's own client half handed over in process, treated from here on exactly as a packet off the network. Each
             * payload array belongs to the Reader the engine initializes with it. */
            while (IncomingPackets.TryDequeue(out IncomingPacket locallyPairedIncomingPacket))
                receivedPackets.Add(locallyPairedIncomingPacket);
        }

        /// <summary>
        /// Registers a client whose session has opened, or closes the session when the server is full or stopping.
        /// </summary>
        /// <param name="webTransportSession">The session.</param>
        private void TryAdmit(WebTransportSession webTransportSession)
        {
            if (State is not LocalConnectionState.Connected || IsConnectionCapReached() || !_idBySocketPool.EnsureRent(out uint idBySocket))
            {
                Logger<QuicServerSocket>.LogWarning($"A WebTransport client from [{webTransportSession.RemoteAddress}] was refused: the server is full, stopping, or has no id to give it.");
                webTransportSession.Close(isAfterDelivery: false);

                return;
            }

            // The address the session was observed coming from, so an authenticator can tell who the peer is.
            Connection connection = ResettableObjectPool<Connection>.Rent();
            connection.Initialize(idBySocket, isEmulated: false, Transport, webTransportSession.RemoteAddress);

            webTransportSession.NucleusConnection = connection;
            _sessionsByConnection[connection] = webTransportSession;

            ConnectionStateChangeResult connectionStateChangeResult = TransportManager.SetRemoteConnectionStateAsConnected(idBySocket, connection);

            if (connectionStateChangeResult is ConnectionStateChangeResult.Success)
                return;

            Logger<QuicServerSocket>.LogError($"A WebTransport client could not be registered: [{connectionStateChangeResult}].");

            Forget(webTransportSession);
            webTransportSession.Close(isAfterDelivery: false);
            _idBySocketPool.ReturnUnsafe(idBySocket);
            ResettableObjectPool<Connection>.Return(connection);
        }

        /// <summary>
        /// Closes one client's session and queues its departure.
        /// </summary>
        /// <param name="connection">The client to drop.</param>
        /// <param name="isAfterDelivery">True to deliver the reliable data already sent before the session closes.</param>
        /// <returns>The result of the request.</returns>
        private Task<ConnectionStateChangeResult> DisconnectRemoteClientCoreAsync(Connection connection, bool isAfterDelivery)
        {
            if (State is not LocalConnectionState.Connected)
                return GetResultTask(ConnectionStateChangeResult.InvalidSocketState);

            // This transport's own client half has no session while paired; dropping the pairing is the whole of it.
            if (_pairedClientConnection is not null && ReferenceEquals(connection, _pairedClientConnection))
            {
                UnpairLocalClient();

                return GetResultTask(ConnectionStateChangeResult.Success);
            }

            if (connection is null || !_sessionsByConnection.TryGetValue(connection, out WebTransportSession webTransportSession))
                return GetResultTask(ConnectionStateChangeResult.InvalidConnection);

            Forget(webTransportSession);
            webTransportSession.Close(isAfterDelivery);
            _droppedConnections.Enqueue(connection);

            return GetResultTask(ConnectionStateChangeResult.Success);
        }

        /// <summary>
        /// Applies what MsQuic queued before the server stops: a session that opened is closed without being admitted, a packet is handed
        /// back, and a session that closed is let go.
        /// </summary>
        private void SettleQueuedEvents()
        {
            while (_droppedConnections.TryDequeue(out Connection droppedConnection))
                NotifyDisconnected(droppedConnection, droppedConnection.IdBySocket);

            while (_events.TryDequeue(out WebTransportEvent webTransportEvent))
            {
                WebTransportSession webTransportSession = webTransportEvent.Session;

                if (webTransportEvent.Type is WebTransportEventType.Received)
                    TrackedArrayPool<byte>.Return(webTransportEvent.Payload.Array);
                else if (webTransportEvent.Type is WebTransportEventType.Opened && webTransportSession.NucleusConnection is null)
                    webTransportSession.Close(isAfterDelivery: false);
                else if (webTransportEvent.Type is WebTransportEventType.Closed && webTransportSession.NucleusConnection is { } departedConnection)
                {
                    Forget(webTransportSession);
                    NotifyDisconnected(departedConnection, departedConnection.IdBySocket);
                }
            }
        }

        /// <summary>
        /// Closes every client's session and tells the engine each one has left.
        /// </summary>
        private void DisconnectRemoteClients()
        {
            if (_sessionsByConnection.Count == 0)
                return;

            List<Connection> departingConnections = ListPool<Connection>.Rent();

            foreach (KeyValuePair<Connection, WebTransportSession> sessionKeyValuePair in _sessionsByConnection)
            {
                sessionKeyValuePair.Value.Close(isAfterDelivery: false);
                sessionKeyValuePair.Value.NucleusConnection = null;
                departingConnections.Add(sessionKeyValuePair.Key);
            }

            _sessionsByConnection.Clear();

            foreach (Connection departingConnection in departingConnections)
                NotifyDisconnected(departingConnection, departingConnection.IdBySocket);

            ListPool<Connection>.ReturnAndNullifyReference(ref departingConnections);
        }

        /// <summary>
        /// Removes a session from the roster this socket keeps, so nothing more it receives reaches the engine.
        /// </summary>
        /// <param name="webTransportSession">The session.</param>
        private void Forget(WebTransportSession webTransportSession)
        {
            if (webTransportSession.NucleusConnection is { } connection)
                _sessionsByConnection.Remove(connection);

            webTransportSession.NucleusConnection = null;
        }

        /// <summary>
        /// Tells the engine a client has left, and returns its id once the engine has let it go.
        /// </summary>
        /// <param name="connection">The client's Connection.</param>
        /// <param name="idBySocket">The id it was admitted under.</param>
        /// <remarks>
        /// The engine refuses a client that was never registered or has already left, so no id is returned twice. A departure handler can
        /// remove this transport, which returns this socket, so the id is returned only while this socket still has its manager.
        /// </remarks>
        private void NotifyDisconnected(Connection connection, uint idBySocket)
        {
            if (SetRemoteConnectionStateAsDisconnected(connection) is ConnectionStateChangeResult.Success && TransportManager is not null)
                _idBySocketPool.ReturnUnsafe(idBySocket);
        }

        /// <summary>
        /// Returns whether the server already holds as many clients as it allows, its own paired client included.
        /// </summary>
        /// <returns>True when one more would pass the cap.</returns>
        private bool IsConnectionCapReached()
        {
            uint maximumConnections = Transport.ServerConfiguration.MaximumConnections;

            if (maximumConnections is ServerConfiguration.UnsetMaximumConnections)
                return false;

            int heldClientCount = _sessionsByConnection.Count + (_pairedClientConnection is null ? 0 : 1);

            return heldClientCount >= maximumConnections;
        }

        /// <summary>
        /// Stops accepting sessions. The MsQuic copy stays open until the socket is returned.
        /// </summary>
        private void StopListening()
        {
            _isListening = false;

#if !UNITY_WEBGL || UNITY_EDITOR
            _quicListener?.Stop();
            _quicListener = null;
#endif
        }

        /// <summary>
        /// Releases the roster entry for this transport's own client half when that half's link drops first.
        /// </summary>
        /// <param name="connectionStateChange">The change being reported.</param>
        /// <param name="localConnectionState">The state being reported.</param>
        /// <param name="isServerStarted">Whether this peer was running a server when the change was reported.</param>
        /// <remarks>
        /// The roster finds the entry by the id the client link clears as it finishes dropping. This is raised before that clear, so the
        /// entry is released here while the id still names it, the client's link going down before the server lets it go, as for a remote
        /// client.
        /// </remarks>
        private void TransportManager_OnConnectionLocalStateChanged(ConnectionStateChange connectionStateChange, LocalConnectionState localConnectionState, bool isServerStarted)
        {
            if (connectionStateChange.Invoker is not Invoker.Client || localConnectionState is not LocalConnectionState.Disconnected)
                return;

            Connection connection = connectionStateChange.Connection;

            if (connection is null || connection.Transport != Transport || connection.RemoteState is not RemoteConnectionState.Connected)
                return;

            if (ReferenceEquals(connection, _pairedClientConnection))
                UnpairLocalClient();
        }

#if !UNITY_WEBGL || UNITY_EDITOR
        /// <summary>
        /// Reads the server's certificate from <see cref="Quic.CertificatePath"/>, or makes one when that is empty.
        /// </summary>
        /// <param name="quic">The transport, whose <see cref="Quic.ServerCertificateHash"/> a made certificate is reported in.</param>
        /// <param name="certificate">The PKCS #12 bytes.</param>
        /// <returns>True when there is a certificate to serve.</returns>
        private static bool TryLoadCertificate(Quic quic, out byte[] certificate)
        {
            if (string.IsNullOrEmpty(quic.CertificatePath))
            {
                certificate = SelfSignedCertificate.CreatePkcs12("localhost", out byte[] certificateHash);
                quic.ServerCertificateHash = SelfSignedCertificate.ToHex(certificateHash);

                Logger<QuicServerSocket>.LogInformation($"The WebTransport server made its own certificate, valid for {SelfSignedCertificate.ValidityPeriod.TotalDays} days. Clients connect with certificate hash [{quic.ServerCertificateHash}].");

                return true;
            }

            quic.ServerCertificateHash = string.Empty;

            try
            {
                certificate = File.ReadAllBytes(quic.CertificatePath);

                return true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Logger<QuicServerSocket>.LogError($"The server certificate [{quic.CertificatePath}] could not be read: {exception.Message}");
                certificate = null;

                return false;
            }
        }
#endif

        /// <inheritdoc/>
        public override void OnReturn()
        {
            if (TransportManager is not null)
                LocalConnectionStateChanged -= TransportManager_OnConnectionLocalStateChanged;

            _idBySocketPool.OnReturn();

            /* Held rather than owned: a client's Connection goes back to its pool through the TransportManager, so these are cleared and
             * not drained. The host's own client is held on the same terms and more so, its Connection belonging to the client socket. */
            _pairedClientConnection = null;
            _pairedClientIdBySocket = Connection.UnsetId;

            foreach (WebTransportSession webTransportSession in _sessionsByConnection.Values)
                webTransportSession.NucleusConnection = null;

            _sessionsByConnection.Clear();
            _droppedConnections.Clear();
            StopListening();

#if !UNITY_WEBGL || UNITY_EDITOR
            // Closing MsQuic shuts every remaining connection down and waits for each, so nothing it holds outlives the socket.
            _msQuic?.Close();
            _msQuic = null;
#endif
            _events.Clear();

            base.OnReturn();
        }
    }
}
