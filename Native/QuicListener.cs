#if !UNITY_WEBGL || UNITY_EDITOR
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using CodeBoost.Logging;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// A server's MsQuic listener and the configuration every connection it accepts is given.
    /// </summary>
    /// <remarks>
    /// Each accepted connection becomes a <see cref="QuicSession"/> reporting to the server socket's <see cref="WebTransportEvents"/>.
    /// Stopping the listener refuses new connections and leaves the accepted ones to their sessions, which the socket closes itself.
    /// </remarks>
    internal sealed unsafe class QuicListener
    {
        /// <summary>
        /// The MsQuic copy the listener was opened with.
        /// </summary>
        private readonly MsQuic _msQuic;
        /// <summary>
        /// Where every accepted session reports.
        /// </summary>
        private readonly WebTransportEvents _events;
        /// <summary>
        /// The largest reliable packet a client may send.
        /// </summary>
        private readonly int _maximumReliablePacketSize;
        /// <summary>
        /// The handle MsQuic holds as the listener's context.
        /// </summary>
        private GCHandle _contextHandle;
        /// <summary>
        /// The configuration every accepted connection is given.
        /// </summary>
        private IntPtr _configuration;
        /// <summary>
        /// The listener, until it is stopped.
        /// </summary>
        private IntPtr _listener;
        /// <summary>
        /// The certificate imported for the Schannel build on Windows, held until the listener stops; <see langword="null"/> elsewhere.
        /// </summary>
        private WindowsCertificate _windowsCertificate;
        /// <summary>
        /// The handler MsQuic calls for listener events, held so it is never collected.
        /// </summary>
        private static readonly MsQuic.ListenerCallback ListenerHandler = OnListenerEvent;
        /// <summary>
        /// The native entry point for <see cref="ListenerHandler"/>.
        /// </summary>
        private static readonly IntPtr ListenerHandlerPointer = Marshal.GetFunctionPointerForDelegate(ListenerHandler);
        /// <summary>
        /// How many two-way streams a client may have open: its CONNECT and its reliable stream, with room to spare.
        /// </summary>
        private const ushort PeerBidirectionalStreamCount = 4;
        /// <summary>
        /// How many one-way streams a client may have open: its control and QPACK streams, with room to spare.
        /// </summary>
        private const ushort PeerUnidirectionalStreamCount = 8;

        /// <summary>
        /// Creates a listener that has not yet been opened.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy to open it with.</param>
        /// <param name="events">Where every accepted session reports.</param>
        /// <param name="maximumReliablePacketSize">The largest reliable packet a client may send.</param>
        private QuicListener(MsQuic msQuic, WebTransportEvents events, int maximumReliablePacketSize)
        {
            _msQuic = msQuic;
            _events = events;
            _maximumReliablePacketSize = maximumReliablePacketSize;
            _contextHandle = GCHandle.Alloc(this);
        }

        /// <summary>
        /// Stops accepting connections and closes the configuration.
        /// </summary>
        /// <remarks>Blocks until MsQuic has stopped the listener, so it must not be called from an MsQuic callback. Connections already accepted keep the configuration they were given.</remarks>
        internal void Stop()
        {
            if (_listener != IntPtr.Zero)
            {
                _msQuic.ListenerClose(_listener);
                _listener = IntPtr.Zero;
            }

            if (_configuration != IntPtr.Zero)
            {
                _msQuic.ConfigurationClose(_configuration);
                _configuration = IntPtr.Zero;
            }

            _windowsCertificate?.Release();
            _windowsCertificate = null;

            if (_contextHandle.IsAllocated)
                _contextHandle.Free();
        }

        /// <summary>
        /// Opens a configuration with the server's certificate and starts listening.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy to listen with.</param>
        /// <param name="events">Where every accepted session reports.</param>
        /// <param name="certificate">The certificate and private key, as PKCS #12 bytes.</param>
        /// <param name="certificatePassword">The password protecting <paramref name="certificate"/>, or empty for none.</param>
        /// <param name="bindAddress">The local address to listen on, or empty for every interface.</param>
        /// <param name="port">The port to listen on.</param>
        /// <param name="connectingTimeoutSeconds">How long a handshake may go unanswered; zero uses <paramref name="connectedTimeoutSeconds"/>.</param>
        /// <param name="connectedTimeoutSeconds">How long a connection may go unanswered.</param>
        /// <param name="maximumReliablePacketSize">The largest reliable packet a client may send.</param>
        /// <param name="quicListener">The listener, or <see langword="null"/> when it could not be started.</param>
        /// <returns>True when the server is listening.</returns>
        internal static bool TryStart(MsQuic msQuic, WebTransportEvents events, byte[] certificate, string certificatePassword, string bindAddress, ushort port, ushort connectingTimeoutSeconds, ushort connectedTimeoutSeconds, int maximumReliablePacketSize, out QuicListener quicListener)
        {
            quicListener = null;

            if (!TryCreateAddress(msQuic, bindAddress, port, out MsQuic.QuicAddress localAddress))
            {
                Logger<QuicListener>.LogError($"Bind address [{bindAddress}] is not an IP address. Leave it empty to listen on every interface.");

                return false;
            }

            QuicListener startingQuicListener = new(msQuic, events, maximumReliablePacketSize);
            MsQuic.Settings settings = CreateSettings(connectingTimeoutSeconds, connectedTimeoutSeconds, PeerBidirectionalStreamCount, PeerUnidirectionalStreamCount);

            if (!TryOpenConfiguration(msQuic, ref settings, out startingQuicListener._configuration))
            {
                startingQuicListener.Stop();

                return false;
            }

            int credentialStatus;

            // The Schannel build on Windows takes a certificate context; the OpenSSL build everywhere else reads PKCS #12 itself.
            if (msQuic.IsWindows)
            {
                if (!WindowsCertificate.TryImport(certificate, certificatePassword, out startingQuicListener._windowsCertificate))
                {
                    startingQuicListener.Stop();

                    return false;
                }

                MsQuic.CredentialConfig credentialConfig = new() { Type = MsQuic.CertificateContextCredentialType, Certificate = (void*)startingQuicListener._windowsCertificate.CertificateContext };

                credentialStatus = msQuic.ConfigurationLoadCredential(startingQuicListener._configuration, &credentialConfig);
            }
            else
            {
                byte[] passwordBytes = string.IsNullOrEmpty(certificatePassword) ? null : Encoding.UTF8.GetBytes($"{certificatePassword}\0");

                fixed (byte* certificatePointer = certificate)
                fixed (byte* passwordPointer = passwordBytes)
                {
                    MsQuic.CertificatePkcs12 certificatePkcs12 = new() { Asn1Blob = certificatePointer, Asn1BlobLength = (uint)certificate.Length, PrivateKeyPassword = passwordPointer };
                    MsQuic.CredentialConfig credentialConfig = new() { Type = MsQuic.Pkcs12CredentialType, Certificate = &certificatePkcs12 };

                    credentialStatus = msQuic.ConfigurationLoadCredential(startingQuicListener._configuration, &credentialConfig);
                }
            }

            if (!msQuic.IsSucceeded(credentialStatus))
            {
                Logger<QuicListener>.LogError($"The server certificate could not be loaded: status [0x{credentialStatus:X8}]. It must be a PKCS #12 file holding the certificate and its private key, and the password must match.");
                startingQuicListener.Stop();

                return false;
            }

            IntPtr listener;
            int openStatus = msQuic.ListenerOpen(msQuic.Registration, ListenerHandlerPointer, GCHandle.ToIntPtr(startingQuicListener._contextHandle), &listener);

            if (!msQuic.IsSucceeded(openStatus))
            {
                Logger<QuicListener>.LogError($"An MsQuic listener could not be opened: status [0x{openStatus:X8}].");
                startingQuicListener.Stop();

                return false;
            }

            startingQuicListener._listener = listener;

            int startStatus;

            fixed (byte* alpnPointer = Encoding.ASCII.GetBytes(Http3.ApplicationProtocol))
            {
                MsQuic.QuicBuffer alpn = new() { Length = (uint)Http3.ApplicationProtocol.Length, Buffer = alpnPointer };

                startStatus = msQuic.ListenerStart(listener, &alpn, 1, &localAddress);
            }

            if (!msQuic.IsSucceeded(startStatus))
            {
                Logger<QuicListener>.LogError($"The server could not listen on UDP port [{port}]: status [0x{startStatus:X8}]. Another process may already be using it.");
                startingQuicListener.Stop();

                return false;
            }

            quicListener = startingQuicListener;

            return true;
        }

        /// <summary>
        /// Builds the settings shared by both sides: timeouts, keep-alives, how many streams the peer may open, and datagrams.
        /// </summary>
        /// <param name="connectingTimeoutSeconds">How long a handshake may go unanswered; zero uses <paramref name="connectedTimeoutSeconds"/>.</param>
        /// <param name="connectedTimeoutSeconds">How long a connection may go unanswered; one second is the least applied.</param>
        /// <param name="peerBidirectionalStreamCount">How many two-way streams the peer may open.</param>
        /// <param name="peerUnidirectionalStreamCount">How many one-way streams the peer may open.</param>
        /// <returns>The settings.</returns>
        /// <remarks>Keep-alives go out three times per timeout, so a link carrying nothing else is heard from twice before it is given up on.</remarks>
        internal static MsQuic.Settings CreateSettings(ushort connectingTimeoutSeconds, ushort connectedTimeoutSeconds, ushort peerBidirectionalStreamCount, ushort peerUnidirectionalStreamCount)
        {
            uint idleTimeoutMilliseconds = Math.Max(connectedTimeoutSeconds, (ushort)1) * 1000u;
            uint handshakeTimeoutMilliseconds = connectingTimeoutSeconds == 0 ? idleTimeoutMilliseconds : connectingTimeoutSeconds * 1000u;

            return new()
            {
                IsSetFlags = MsQuic.Settings.HandshakeIdleTimeoutIsSet | MsQuic.Settings.IdleTimeoutIsSet | MsQuic.Settings.KeepAliveIntervalIsSet | MsQuic.Settings.PeerBidirectionalStreamCountIsSet | MsQuic.Settings.PeerUnidirectionalStreamCountIsSet | MsQuic.Settings.DatagramReceiveEnabledIsSet,
                HandshakeIdleTimeoutMilliseconds = handshakeTimeoutMilliseconds,
                IdleTimeoutMilliseconds = idleTimeoutMilliseconds,
                KeepAliveIntervalMilliseconds = idleTimeoutMilliseconds / 3,
                PeerBidirectionalStreamCount = peerBidirectionalStreamCount,
                PeerUnidirectionalStreamCount = peerUnidirectionalStreamCount,
                Flags = MsQuic.Settings.DatagramReceiveEnabledFlag,
            };
        }

        /// <summary>
        /// Opens a configuration negotiating HTTP/3 with the given settings.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy to open it with.</param>
        /// <param name="settings">The settings.</param>
        /// <param name="configuration">The configuration, or <see cref="IntPtr.Zero"/> when it could not be opened.</param>
        /// <returns>True when it was opened.</returns>
        internal static bool TryOpenConfiguration(MsQuic msQuic, ref MsQuic.Settings settings, out IntPtr configuration)
        {
            IntPtr openedConfiguration;
            int openStatus;

            fixed (byte* alpnPointer = Encoding.ASCII.GetBytes(Http3.ApplicationProtocol))
            fixed (MsQuic.Settings* settingsPointer = &settings)
            {
                MsQuic.QuicBuffer alpn = new() { Length = (uint)Http3.ApplicationProtocol.Length, Buffer = alpnPointer };

                openStatus = msQuic.ConfigurationOpen(msQuic.Registration, &alpn, 1, settingsPointer, (uint)sizeof(MsQuic.Settings), IntPtr.Zero, &openedConfiguration);
            }

            configuration = msQuic.IsSucceeded(openStatus) ? openedConfiguration : IntPtr.Zero;

            if (configuration == IntPtr.Zero)
                Logger<QuicListener>.LogError($"An MsQuic configuration could not be opened: status [0x{openStatus:X8}].");

            return configuration != IntPtr.Zero;
        }

        /// <summary>
        /// Builds the native address to listen on.
        /// </summary>
        /// <param name="msQuic">The MsQuic copy, which knows the platform's IPv6 family number.</param>
        /// <param name="bindAddress">An IP address, <c>localhost</c>, or empty for every interface over both IPv4 and IPv6.</param>
        /// <param name="port">The port.</param>
        /// <param name="quicAddress">The address built.</param>
        /// <returns>True when <paramref name="bindAddress"/> could be read.</returns>
        private static bool TryCreateAddress(MsQuic msQuic, string bindAddress, ushort port, out MsQuic.QuicAddress quicAddress)
        {
            MsQuic.QuicAddress address = new() { Family = MsQuic.UnspecifiedAddressFamily, NetworkOrderPort = (ushort)(port >> 8 | port << 8) };
            quicAddress = address;

            if (string.IsNullOrEmpty(bindAddress))
                return true;

            IPAddress ipAddress;

            if (string.Equals(bindAddress, "localhost", StringComparison.OrdinalIgnoreCase))
                ipAddress = IPAddress.Loopback;
            else if (!IPAddress.TryParse(bindAddress, out ipAddress))
                return false;

            byte[] addressBytes = ipAddress.GetAddressBytes();
            bool isInterNetworkV6 = addressBytes.Length == 16;
            byte* addressPointer = isInterNetworkV6 ? &address.InterNetworkV6Address : &address.InterNetworkAddress;

            address.Family = isInterNetworkV6 ? msQuic.IsWindows ? MsQuic.WindowsInterNetworkV6AddressFamily : MsQuic.PosixInterNetworkV6AddressFamily : MsQuic.InterNetworkAddressFamily;
            Marshal.Copy(addressBytes, 0, (IntPtr)addressPointer, addressBytes.Length);
            quicAddress = address;

            return true;
        }

        /// <summary>
        /// Reads the address a peer connected from.
        /// </summary>
        /// <param name="quicAddress">The native address.</param>
        /// <returns>The address without its port, so a peer reconnecting from a new port keeps its identity, or <see langword="null"/> when it cannot be read.</returns>
        private static string ReadAddress(MsQuic.QuicAddress* quicAddress)
        {
            if (quicAddress is null)
                return null;

            bool isInterNetwork = quicAddress->Family == MsQuic.InterNetworkAddressFamily;
            byte[] addressBytes = new byte[isInterNetwork ? 4 : 16];
            Marshal.Copy((IntPtr)(isInterNetwork ? &quicAddress->InterNetworkAddress : &quicAddress->InterNetworkV6Address), addressBytes, 0, addressBytes.Length);
            IPAddress ipAddress = new(addressBytes);

            return (ipAddress.IsIPv4MappedToIPv6 ? ipAddress.MapToIPv4() : ipAddress).ToString();
        }

        /// <summary>
        /// Receives MsQuic's listener events, handing each new connection to a <see cref="QuicSession"/>.
        /// </summary>
        /// <param name="listener">The listener.</param>
        /// <param name="context">The listener's handle.</param>
        /// <param name="listenerEvent">The event.</param>
        /// <returns>The status MsQuic is answered with; a failure refuses the connection.</returns>
        [MonoPInvokeCallback(typeof(MsQuic.ListenerCallback))]
        private static int OnListenerEvent(IntPtr listener, IntPtr context, MsQuic.ListenerEvent* listenerEvent)
        {
            if (listenerEvent->Type != MsQuic.ListenerEvent.NewConnectionType)
                return MsQuic.SuccessStatus;

            QuicListener quicListener = (QuicListener)GCHandle.FromIntPtr(context).Target;

            try
            {
                string remoteAddress = ReadAddress(listenerEvent->NewConnectionInfo->RemoteAddress);

                return QuicSession.Accept(quicListener._msQuic, quicListener._events, listenerEvent->NewConnection, quicListener._configuration, remoteAddress, quicListener._maximumReliablePacketSize);
            }
            catch (Exception exception)
            {
                Logger<QuicListener>.LogError($"Accepting a WebTransport connection caused an exception, so it was refused: {exception}");

                return quicListener._msQuic.GetInternalErrorStatus();
            }
        }
    }
}
#endif
