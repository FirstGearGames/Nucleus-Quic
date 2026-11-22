using System;
using System.Net;
using CodeBoost.Logging;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// A <see cref="Transport"/> over WebTransport: HTTP/3 on QUIC, the one UDP transport a web browser can open, so a WebGL build can
    /// join the same server as every other platform.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unreliable packets travel as WebTransport datagrams, which are UDP datagrams with QUIC's encryption and congestion control and no
    /// retransmission. Reliable packets travel on one two-way stream the client opens, each prefixed with its length, so they arrive
    /// whole and in order whatever their size.
    /// </para>
    /// <para>
    /// The server and every desktop client run on MsQuic, loaded from <c>msquic.dll</c> on Windows or <c>libmsquic.so</c> on Linux. A
    /// WebGL build connects through the browser's own <c>WebTransport</c>, and cannot be a server: a browser cannot accept connections.
    /// </para>
    /// <para>
    /// A browser only connects to a server whose certificate it can trust. Give the server a certificate for its domain from a public
    /// authority in <see cref="CertificatePath"/>, or leave that empty and the server makes its own short-lived certificate on every
    /// start, whose SHA-256 it reports in <see cref="ServerCertificateHash"/> for each client to be given as <see cref="CertificateHash"/>.
    /// </para>
    /// <para>
    /// A host's own client is paired with its server inside the process and never touches the network, as Synapse's local pairing is: the
    /// client does this on its own when its server is running and <see cref="RemoteHost"/> names this machine on the server's port.
    /// </para>
    /// </remarks>
    public class Quic : SocketPairTransport<QuicServerSocket, QuicClientSocket>
    {
        /// <summary>
        /// The host a client connects to: a host name or an IP address, without a port.
        /// </summary>
        /// <remarks>
        /// Read when the client connects. A browser checks the server's certificate against this name unless it was given
        /// <see cref="CertificateHash"/>. Empty, <c>localhost</c> or a loopback address on the server's own port connects a host's client to
        /// its own server inside the process.
        /// </remarks>
        public string RemoteHost = "127.0.0.1";
        /// <summary>
        /// The port a client connects to.
        /// </summary>
        /// <remarks>Read when the client connects. <see cref="SetPort"/> and the <see cref="Transport.PortArgument"/> launch argument set it with the server's port.</remarks>
        public ushort RemotePort;
        /// <summary>
        /// The server's certificate and private key, as a PKCS #12 (<c>.pfx</c>) file, or empty for the server to make its own on every
        /// start.
        /// </summary>
        /// <remarks>Read when the server starts.</remarks>
        public string CertificatePath = string.Empty;
        /// <summary>
        /// The password protecting <see cref="CertificatePath"/>, or empty for none.
        /// </summary>
        public string CertificatePassword = string.Empty;
        /// <summary>
        /// The SHA-256 a client requires of the server's certificate, as 64 hex characters, or empty to trust only certificates the
        /// system or browser already trusts.
        /// </summary>
        /// <remarks>
        /// Read when the client connects. Set it to the <see cref="ServerCertificateHash"/> a server reported, to reach a server that made
        /// its own certificate. Colons and spaces between the bytes are allowed.
        /// </remarks>
        public string CertificateHash = string.Empty;
        /// <summary>
        /// The largest reliable packet the server accepts from a client; a client that sends a larger one is disconnected.
        /// </summary>
        /// <remarks>Read when the server starts. It bounds the memory one client can make the server hold for a packet it has not finished sending.</remarks>
        public int MaximumReliablePacketSize = 1024 * 1024;
        /// <summary>
        /// The origins of the web pages a browser may connect from, such as <c>https://game.example.com</c>, or empty to accept a
        /// connection from any page.
        /// </summary>
        /// <remarks>
        /// Read when the server starts. A browser names the page that opened a connection, and the page cannot change what is named, so
        /// listing the game's own pages stops another site's page from connecting through its visitors' browsers. Each entry is a scheme, a
        /// host and a port only when it is not the scheme's default, as a browser names them; letter case does not matter. A native client
        /// names no page and is accepted whatever the list holds, so the list guards against pages, not against programs, which can name
        /// any page they like.
        /// </remarks>
        public string[] AllowedOrigins = Array.Empty<string>();

        /// <summary>
        /// The SHA-256 of the certificate the server made for itself on its last start, as 64 lowercase hex characters, or empty when it
        /// was given one in <see cref="CertificatePath"/> or has not started.
        /// </summary>
        /// <remarks>
        /// Hand it to every client as <see cref="CertificateHash"/>. A browser accepts a certificate of this kind for two weeks at most,
        /// so a server that runs longer than <see cref="SelfSignedCertificate.ValidityPeriod"/> must be restarted, or given a certificate
        /// from a public authority instead.
        /// </remarks>
        public string ServerCertificateHash { get; internal set; } = string.Empty;

        /// <inheritdoc/>
        /// <remarks>
        /// QUIC's own short header, packet number and authentication tag, the DATAGRAM frame, and the session prefix WebTransport puts on
        /// every datagram, rounded up. Reported so the engine keeps its unreliable packets inside the datagram QUIC can carry at the
        /// smallest path it allows.
        /// </remarks>
        public override uint DatagramOverheadBytes => 64;

        /// <summary>
        /// The launch-argument flag which sets <see cref="RemoteHost"/>.
        /// </summary>
        /// <seealso cref="Transport.ApplyCommandLineArguments()"/>
        public const string AddressArgument = "address";
        /// <summary>
        /// The address a host's own client is recorded as having connected from.
        /// </summary>
        internal const string LoopbackAddress = "127.0.0.1";

        /// <inheritdoc/>
        /// <remarks>QUIC traffic always crosses a real socket, even between two peers on one machine, so the security checks stay on.</remarks>
        public override bool IsLocalTransport() => false;

        /// <inheritdoc/>
        /// <remarks>Sets both halves: <see cref="Configuration"/>.Port, which the server listens on, and <see cref="RemotePort"/>, which the client dials.</remarks>
        public override void SetPort(ushort port)
        {
            Configuration.Port = port;
            RemotePort = port;
        }

        /// <inheritdoc/>
        /// <remarks>Applied at the next server start. A client past the cap is closed as soon as its session opens, and a connection past twice the cap, counting those still opening, is refused at its handshake.</remarks>
        public override void SetMaximumConnections(uint maximumConnections) => ServerConfiguration.MaximumConnections = maximumConnections;

        /// <inheritdoc/>
        /// <remarks>Used by the server only, read when it starts. A client always lets the system choose.</remarks>
        public override bool SetBindAddress(string bindAddress)
        {
            if (!string.IsNullOrEmpty(bindAddress) && !string.Equals(bindAddress, "localhost", StringComparison.OrdinalIgnoreCase) && !IPAddress.TryParse(bindAddress, out _))
            {
                Logger<Quic>.LogError($"Bind address [{bindAddress}] is not an IP address or [localhost]; the bind address is unchanged.");

                return false;
            }

            Configuration.BindAddress = string.IsNullOrEmpty(bindAddress) ? null : bindAddress;

            return true;
        }

        /// <summary>
        /// Returns whether the client's target is this peer's own server: this machine, on the port the server listens on.
        /// </summary>
        /// <returns>True when <see cref="RemoteHost"/> is empty, <c>localhost</c> or a loopback address and <see cref="RemotePort"/> is the server's port.</returns>
        /// <remarks>A host name that happens to resolve to this machine is not looked up, and is connected to over the network.</remarks>
        internal bool IsOwnServerTargeted() => RemotePort == Configuration.Port && (string.IsNullOrEmpty(RemoteHost) || string.Equals(RemoteHost, "localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(RemoteHost, out IPAddress remoteIpAddress) && IPAddress.IsLoopback(remoteIpAddress));

        /// <inheritdoc/>
        /// <remarks>
        /// Applies <see cref="Transport.PortArgument"/> to <see cref="RemotePort"/> as well, so the client dials the port the server
        /// listens on, and adds <see cref="AddressArgument"/>, which sets <see cref="RemoteHost"/>.
        /// </remarks>
        protected override void OnApplyCommandLineArguments(CommandLineArguments commandLineArguments)
        {
            base.OnApplyCommandLineArguments(commandLineArguments);

            if (commandLineArguments.TryGetUInt16(PortArgument, out ushort port))
                RemotePort = port;

            if (commandLineArguments.TryGetValue(AddressArgument, out string address))
                RemoteHost = address;
        }
    }
}
