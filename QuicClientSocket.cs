using System;
using System.Collections.Generic;
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
    /// The client side of a <see cref="Quic"/>. Opens a WebTransport session to
    /// <see cref="Quic.RemoteHost"/>, through MsQuic on a desktop and through the browser in a WebGL build, or pairs with
    /// this peer's own server inside the process when it hosts.
    /// </summary>
    public class QuicClientSocket : CommonSocket
    {
        /// <inheritdoc/>
        public override bool IsServer { get; protected set; } = false;
        /// <inheritdoc/>
        public override bool IsEmulated { get; protected set; } = false;

        /// <summary>
        /// The session opening, its packets arriving and its closing, queued by whatever runs the session and applied on the receive pass.
        /// </summary>
        private readonly WebTransportEvents _events = new();
        /// <summary>
        /// The session to the server, from the connect until the link is released.
        /// </summary>
        private WebTransportSession _webTransportSession;
#if !UNITY_WEBGL || UNITY_EDITOR
        /// <summary>
        /// The MsQuic copy this socket opened, held until the socket is returned so a reconnect reuses it.
        /// </summary>
        private MsQuic _msQuic;
#endif
        /// <summary>
        /// This transport's own server socket while this client is paired with it in process, or null.
        /// </summary>
        /// <remarks>A paired client opens no session: packets pass between the two sockets as pooled copies.</remarks>
        private QuicServerSocket _pairedServerSocket;
        /// <summary>
        /// Stands in as the sender on inbound packets.
        /// </summary>
        /// <remarks>
        /// The engine attributes a client's inbound packet through the transport, so the server socket's own Connection serves. That
        /// Connection holds this link's applied-tick watermarks, so it is recycled with the link unless this peer is hosting.
        /// </remarks>
        private Connection _serverStandIn;
#if !UNITY_WEBGL || UNITY_EDITOR
        /// <summary>
        /// How many two-way streams the server may open, which is none.
        /// </summary>
        private const ushort PeerBidirectionalStreamCount = 0;
        /// <summary>
        /// How many one-way streams the server may open: its control and QPACK streams, with room to spare.
        /// </summary>
        private const ushort PeerUnidirectionalStreamCount = 8;
#endif

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        public QuicClientSocket() { }

        /// <inheritdoc/>
        public override void Initialize(Transport transport)
        {
            base.Initialize(transport);

            InitializeConnection();
        }

        /// <summary>
        /// Called by the server socket when it ends the in-process pairing, by a kick, a refusal or the server stopping.
        /// </summary>
        /// <remarks>
        /// Nothing else would drop this link, so the drop is held for the loop as a close read off the network is. Idempotent, so a client
        /// disconnect and a server stop that both reach it leave this socket as either alone would.
        /// </remarks>
        internal void NotifyLocalPairingEnded()
        {
            _pairedServerSocket = null;

            if (State is LocalConnectionState.Connected)
                DeferLocalClientLinkDrop();
        }

        /// <summary>
        /// Pairs with this peer's own server when it hosts, or otherwise opens a session to the server and waits in Connecting until it
        /// opens.
        /// </summary>
        /// <returns>The result of the state change.</returns>
        /// <remarks>
        /// Returns once the connect has started rather than once it has finished. The receive pass takes this socket to Connected when the
        /// server accepts the session, or back to Disconnected when the handshake fails or times out.
        /// </remarks>
        protected override Task<ConnectionStateChangeResult> ConnectAsync()
        {
            // A link already up, or on its way up, is left as it is.
            if (State is LocalConnectionState.Connected or LocalConnectionState.Connecting)
                return GetResultTask(ConnectionStateChangeResult.AlreadyInState);

            Quic quic = (Quic)Transport;
            QuicServerSocket serverSocket = quic.ServerSocket;

            // A link the server closed is released here before the next one is made.
            ReleaseSession();

            /* Recycled rather than reused, so a new link carries none of the last one's identity, authentication or watermarks. The
             * stand-in is kept only by a host, whose server socket is live and whose Connection describes the server it is running. */
            RecycleConnection();

            bool isHosting = serverSocket.State is LocalConnectionState.Connected;

            serverSocket.RecycleStandInUnlessHosting();
            _serverStandIn = serverSocket.Connection;

            if (isHosting && quic.IsOwnServerTargeted())
                return GetResultTask(ConnectLocallyPaired(serverSocket));

            if (string.IsNullOrEmpty(quic.RemoteHost))
            {
                Logger<QuicClientSocket>.LogError($"No server to connect to. Set [{nameof(Quic)}.{nameof(Quic.RemoteHost)}] before connecting.");

                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);
            }

            byte[] pinnedCertificateHash = null;

            if (!string.IsNullOrEmpty(quic.CertificateHash) && !SelfSignedCertificate.TryParseHex(quic.CertificateHash, out pinnedCertificateHash))
            {
                Logger<QuicClientSocket>.LogError($"Certificate hash [{quic.CertificateHash}] is not a SHA-256 written as 64 hex characters.");

                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);
            }

            if (!TryStartSession(quic, pinnedCertificateHash, out _webTransportSession))
                return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);

            if (TransportManager.ChangeLocalConnectionState(Invoker.Client, LocalConnectionState.Connecting, Connection) is ConnectionStateChangeResult.Success)
                return GetResultTask(ConnectionStateChangeResult.Success);

            ReleaseSession();
            TransportManager.ChangeLocalConnectionState(Invoker.Client, LocalConnectionState.Disconnected, Connection);

            return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);
        }

        /// <inheritdoc/>
        protected override Task<ConnectionStateChangeResult> DisconnectAsync()
        {
            /* A paired link has no session to close and no far end to tell: the peer is this process. The server socket hears the drop and
             * unpairs while the link's id still names its roster entry, and the unpair below is a backstop. */
            if (_pairedServerSocket is not null)
            {
                QuicServerSocket pairedServerSocket = _pairedServerSocket;

                if (!TryDriveLocalStateTo(Invoker.Client, LocalConnectionState.Disconnected))
                    return GetResultTask(ConnectionStateChangeResult.UnspecifiedError);

                pairedServerSocket.UnpairLocalClient();

                // Only while still down: a handler raised by the drop may already have started the next link.
                if (State is LocalConnectionState.Disconnected)
                    RecycleConnection();

                return GetResultTask(ConnectionStateChangeResult.Success);
            }

            if (_webTransportSession is null)
                return GetResultTask(ConnectionStateChangeResult.AlreadyInState);

            ReleaseSession();

            ConnectionStateChangeResult connectionStateChangeResult = TryDriveLocalStateTo(Invoker.Client, LocalConnectionState.Disconnected) ? ConnectionStateChangeResult.Success : ConnectionStateChangeResult.UnspecifiedError;

            /* Recycled at the stop, after the walk, and only while still down, so nothing between two links reads a Connection carrying the
             * last one's state. The stand-in goes with it unless this peer is still hosting. */
            if (State is not LocalConnectionState.Disconnected)
                return GetResultTask(connectionStateChangeResult);

            RecycleConnection();
            ((Quic)Transport).ServerSocket.RecycleStandInUnlessHosting();

            return GetResultTask(connectionStateChangeResult);
        }

        /// <inheritdoc/>
        protected override void SendPacket(OutgoingPacket outgoingPacket)
        {
            if (_pairedServerSocket is not null)
            {
                if (State is not LocalConnectionState.Connected)
                {
                    Nucleus.Managers.Transports.TransportManager.PacketFailed(outgoingPacket);

                    return;
                }

                _pairedServerSocket.ReceiveLocalPacket(outgoingPacket);
                Nucleus.Managers.Transports.TransportManager.PacketOffloaded(outgoingPacket);

                return;
            }

            if (State is LocalConnectionState.Connected && _webTransportSession is not null && _webTransportSession.TrySend(outgoingPacket.Channel, outgoingPacket.Payload))
                Nucleus.Managers.Transports.TransportManager.PacketOffloaded(outgoingPacket);
            else
                Nucleus.Managers.Transports.TransportManager.PacketFailed(outgoingPacket);
        }

        /// <inheritdoc/>
        /// <remarks>
        /// Called by the network loop while this socket is Connecting as well as Connected, which is how a connect finishes. The session
        /// opening takes the socket to Connected before any packet is added. The session closing is held for the loop rather than applied
        /// here, so the packets read in the same pass, a kick's reason among them, reach the game first.
        /// </remarks>
        protected override void ReceivePackets(ref List<IncomingPacket> receivedPackets)
        {
            /* A paired link takes what its server socket queued for it, copying each packet so the Writer the server still holds can go
             * back, the same hand-over an offline transport makes. */
            if (_pairedServerSocket is not null)
            {
                if (State is LocalConnectionState.Connected)
                    _pairedServerSocket.HandOverToPairedClient(receivedPackets);

                return;
            }

            _webTransportSession?.Poll();

            while (_events.TryDequeue(out WebTransportEvent webTransportEvent))
            {
                // A late event from a link already released has nothing left to act on.
                if (webTransportEvent.Session != _webTransportSession)
                {
                    if (webTransportEvent.Payload.Array is not null)
                        TrackedArrayPool<byte>.Return(webTransportEvent.Payload.Array);

                    continue;
                }

                switch (webTransportEvent.Type)
                {
                    case WebTransportEventType.Opened:
                        if (State is LocalConnectionState.Connecting && TransportManager.ChangeLocalConnectionState(Invoker.Client, LocalConnectionState.Connected, Connection) is not ConnectionStateChangeResult.Success)
                            AbandonConnect();

                        break;
                    case WebTransportEventType.Received:
                        if (State is LocalConnectionState.Connected)
                            receivedPackets.Add(new(webTransportEvent.Payload, webTransportEvent.Channel, _serverStandIn));
                        else
                            TrackedArrayPool<byte>.Return(webTransportEvent.Payload.Array);

                        break;
                    case WebTransportEventType.Closed:
                        if (State is LocalConnectionState.Connecting)
                        {
                            Quic quic = (Quic)Transport;

                            Logger<QuicClientSocket>.LogError($"Could not connect to [{quic.RemoteHost}:{quic.RemotePort}]: {webTransportEvent.Session.CloseReason}.");
                            AbandonConnect();
                        }
                        else if (State is LocalConnectionState.Connected)
                        {
                            DeferLocalClientLinkDrop();
                        }

                        break;
                }
            }
        }

        /// <summary>
        /// Joins this peer's own server inside the process, without opening a session.
        /// </summary>
        /// <param name="serverSocket">This transport's server socket, already listening.</param>
        /// <returns>The result of the state change.</returns>
        /// <remarks>
        /// This socket's own Connection becomes the server's roster entry for it rather than a second one being minted, so every check
        /// asking whether the peer over there is this peer answers by identity. This socket stays that Connection's only owner.
        /// </remarks>
        private ConnectionStateChangeResult ConnectLocallyPaired(QuicServerSocket serverSocket)
        {
            if (!TryDriveLocalStateTo(Invoker.Client, LocalConnectionState.Connected))
            {
                TransportManager.ChangeLocalConnectionState(Invoker.Client, LocalConnectionState.Disconnected, Connection);

                return ConnectionStateChangeResult.UnspecifiedError;
            }

            /* Set before the pairing is made: making it runs this peer's whole authentication synchronously, and anything sent from inside
             * that must find this socket already paired. */
            _pairedServerSocket = serverSocket;

            if (serverSocket.EnsurePairLocalClient())
                return ConnectionStateChangeResult.Success;

            _pairedServerSocket = null;

            TransportManager.ChangeLocalConnectionState(Invoker.Client, LocalConnectionState.Disconnected, Connection);

            return ConnectionStateChangeResult.InvalidSocketState;
        }

        /// <summary>
        /// Starts a session to the server, through the browser in a WebGL build and through MsQuic everywhere else.
        /// </summary>
        /// <param name="quic">The transport, which names the server.</param>
        /// <param name="pinnedCertificateHash">The hash the server's certificate must have, or <see langword="null"/>.</param>
        /// <param name="webTransportSession">The session, or <see langword="null"/> when it could not be started.</param>
        /// <returns>True when the session was started.</returns>
        private bool TryStartSession(Quic quic, byte[] pinnedCertificateHash, out WebTransportSession webTransportSession)
        {
            webTransportSession = null;

#if UNITY_WEBGL && !UNITY_EDITOR
            if (!BrowserSession.TryConnect(_events, quic.RemoteHost, quic.RemotePort, pinnedCertificateHash, out BrowserSession browserSession))
                return false;

            webTransportSession = browserSession;

            return true;
#else
            if (_msQuic is null && !MsQuic.TryOpen(out _msQuic))
                return false;

            Configuration configuration = quic.Configuration;
            MsQuic.Settings settings = QuicListener.CreateSettings(configuration.ConnectingTimeoutSeconds, configuration.ConnectedTimeoutSeconds, PeerBidirectionalStreamCount, PeerUnidirectionalStreamCount);

            if (!QuicListener.TryOpenConfiguration(_msQuic, ref settings, out IntPtr quicConfiguration))
                return false;

            QuicSession quicSession = null;
            bool isStarted = TryLoadClientCredential(quicConfiguration, pinnedCertificateHash is not null) && QuicSession.TryConnect(_msQuic, _events, quicConfiguration, quic.RemoteHost, quic.RemotePort, pinnedCertificateHash, out quicSession);

            // A started connection holds its own reference to the configuration, so it is let go of either way.
            _msQuic.ConfigurationClose(quicConfiguration);
            webTransportSession = quicSession;

            return isStarted;
#endif
        }

#if !UNITY_WEBGL || UNITY_EDITOR
        /// <summary>
        /// Loads a client credential, which either validates the server's certificate against the system's trust store or hands the
        /// certificate over for its hash to be checked.
        /// </summary>
        /// <param name="quicConfiguration">The client configuration.</param>
        /// <param name="isCertificatePinned">Whether the server's certificate is checked against a pinned hash instead of the trust store.</param>
        /// <returns>True when the credential was loaded.</returns>
        private unsafe bool TryLoadClientCredential(IntPtr quicConfiguration, bool isCertificatePinned)
        {
            int credentialFlags = MsQuic.ClientCredentialFlag;

            if (isCertificatePinned)
                credentialFlags |= MsQuic.NoCertificateValidationCredentialFlag | MsQuic.IndicateCertificateReceivedCredentialFlag | MsQuic.UsePortableCertificatesCredentialFlag;

            MsQuic.CredentialConfig credentialConfig = new() { Type = MsQuic.NoneCredentialType, Flags = credentialFlags };
            int credentialStatus = _msQuic.ConfigurationLoadCredential(quicConfiguration, &credentialConfig);

            if (_msQuic.IsSucceeded(credentialStatus))
                return true;

            Logger<QuicClientSocket>.LogError($"The client credential could not be loaded: status [0x{credentialStatus:X8}].");

            return false;
        }
#endif

        /// <summary>
        /// Lets go of a connect that will never complete and brings this socket from Connecting back to Disconnected.
        /// </summary>
        private void AbandonConnect()
        {
            ReleaseSession();
            TryDriveLocalStateTo(Invoker.Client, LocalConnectionState.Disconnected);
        }

        /// <summary>
        /// Closes the session, telling the server, and drops what it queued.
        /// </summary>
        private void ReleaseSession()
        {
            _webTransportSession?.Close(isAfterDelivery: false);
            _webTransportSession = null;
            _events.Clear();
        }

        /// <inheritdoc/>
        /// <remarks>
        /// A paired link has already been dropped by the time a socket is returned, its disconnect being what ends the pairing, so it is
        /// only forgotten here. MsQuic is closed last, which waits for the session's connection to be released.
        /// </remarks>
        public override void OnReturn()
        {
            ReleaseSession();

#if !UNITY_WEBGL || UNITY_EDITOR
            _msQuic?.Close();
            _msQuic = null;
#endif
            _events.Clear();
            _pairedServerSocket = null;
            _serverStandIn = null;

            base.OnReturn();
        }
    }
}
