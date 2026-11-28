#if UNITY_5_3_OR_NEWER
using System.Threading.Tasks;
using Nucleus.Integrations.Unity.Managers.Transports;
using Nucleus.Managers.Core;
using Nucleus.Transports;
using UnityEngine;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// Inspector-configurable component for the WebTransport transport, which a WebGL build can join as well as every desktop platform.
    /// Place it on the UnityCoreManager's GameObject; the <see cref="UnityTransportManager"/> adds it to the CoreManager with these settings
    /// applied.
    /// </summary>
    /// <remarks>
    /// The server and desktop clients need MsQuic: <c>msquic.dll</c> ships in this folder for Windows, and a Linux server needs
    /// <c>libmsquic</c> installed. Leave the certificate empty and the server makes its own on every start and logs its hash; a client,
    /// a browser above all, connects with that hash in <see cref="CertificateHash"/>.
    /// </remarks>
    [DisallowMultipleComponent]
    [NucleusHelpUrl(typeof(QuicTransport))]
    public class QuicTransport : NetworkTransport
    {
        /// <summary>
        /// The port the server listens on and the client connects to.
        /// </summary>
        /// <remarks>Accepted at any time and applied at the next start, including to the transport an earlier start built.</remarks>
        public ushort Port
        {
            get => _port;
            set
            {
                _port = value;

                if (_quic is not null)
                    _quic.SetPort(value);
            }
        }
        /// <summary>
        /// The host name or IP address a client connects to, without a port.
        /// </summary>
        /// <remarks>Accepted at any time and applied at the next client start, including to the transport an earlier start built.</remarks>
        public string RemoteHost
        {
            get => _remoteHost;
            set
            {
                _remoteHost = value;

                if (_quic is not null)
                    _quic.RemoteHost = value;
            }
        }
        /// <summary>
        /// The SHA-256 a client requires of the server's certificate, as 64 hex characters, or empty to trust only certificates the system
        /// or browser already trusts.
        /// </summary>
        /// <remarks>
        /// Accepted at any time and applied at the next client start, including to the transport an earlier start built. Set it to the
        /// server's <see cref="ServerCertificateHash"/>, handed over however the game finds its servers.
        /// </remarks>
        public string CertificateHash
        {
            get => _certificateHash;
            set
            {
                _certificateHash = value;

                if (_quic is not null)
                    _quic.CertificateHash = value;
            }
        }
        /// <summary>
        /// The SHA-256 of the certificate the server made for itself on its last start, or empty.
        /// </summary>
        /// <seealso cref="Quic.ServerCertificateHash"/>
        public string ServerCertificateHash => _quic is null ? string.Empty : _quic.ServerCertificateHash;

        /// <summary>
        /// The port the server listens on and the client connects to.
        /// </summary>
        [SerializeField]
        [Tooltip("UDP port the server listens on and the client connects to.")]
        private ushort _port = 7777;
        /// <summary>
        /// The host a client connects to.
        /// </summary>
        [SerializeField]
        [Tooltip("Host name or IP address a client connects to, without a port. A host's own client joins its server inside the process when this is this machine.")]
        private string _remoteHost = "127.0.0.1";
        /// <summary>
        /// The local address the server listens on.
        /// </summary>
        [SerializeField]
        [Tooltip("Local address the server listens on: an IP address or localhost. Empty listens on every interface.")]
        private string _bindAddress = string.Empty;
        /// <summary>
        /// The server's certificate file.
        /// </summary>
        [SerializeField]
        [Tooltip("Server only. A PKCS #12 (.pfx) file holding the server's certificate and private key. Empty makes a new certificate on every start, valid for 13 days, and logs its hash.")]
        private string _certificatePath = string.Empty;
        /// <summary>
        /// The password protecting the certificate file.
        /// </summary>
        [SerializeField]
        [Tooltip("Server only. The password protecting the certificate file, or empty for none.")]
        private string _certificatePassword = string.Empty;
        /// <summary>
        /// The hash a client requires of the server's certificate.
        /// </summary>
        [SerializeField]
        [Tooltip("Client only. The SHA-256 of the server's certificate as 64 hex characters, which the server logs when it makes its own. Empty trusts only certificates the system or browser trusts.")]
        private string _certificateHash = string.Empty;
        /// <summary>
        /// Whether a client refuses a pinned certificate valid for more than 14 days in total, as a browser does.
        /// </summary>
        [SerializeField]
        [Tooltip("Client only. Refuse a server whose pinned certificate is valid for more than 14 days in total, as a browser does. Leave off to pin a long-lived certificate file.")]
        private bool _pinnedCertificateValidityLimitEnabled;
        /// <summary>
        /// The most clients the server accepts at once.
        /// </summary>
        [SerializeField]
        [Tooltip("Server only. Most clients the server accepts at once. Zero accepts any number. Connections past twice this are refused at their handshake.")]
        private uint _maximumConnections = ServerConfiguration.UnsetMaximumConnections;
        /// <summary>
        /// The largest packet to build before it is split.
        /// </summary>
        /// <remarks>Firefox silently drops a datagram larger than 1024 bytes, so raising this loses the largest unreliable packets to and from Firefox players.</remarks>
        [SerializeField]
        [Tooltip("Largest packet to build before it is split. QUIC needs about 64 bytes of each datagram for itself. Firefox silently drops datagrams over 1024 bytes, so raise this only when no player uses Firefox.")]
        private ushort _maximumTransmissionUnit = Quic.DefaultMaximumTransmissionUnit;
        /// <summary>
        /// The largest reliable packet the server accepts from a client.
        /// </summary>
        [SerializeField]
        [Tooltip("Server only. Largest reliable packet in bytes a client may send; a client that sends a larger one is disconnected.")]
        private int _maximumReliablePacketSize = 1024 * 1024;
        /// <summary>
        /// The origins of the web pages a browser may connect from, or empty to accept every page.
        /// </summary>
        [SerializeField]
        [Tooltip("Server only. Origins of the web pages a browser may connect from, such as https://game.example.com. Empty accepts every page. Native clients name no page and are always accepted.")]
        private string[] _allowedOrigins = new string[0];
        /// <summary>
        /// Seconds a client waits for the server to answer a connect, and a server waits for a new connection to open its session.
        /// </summary>
        [SerializeField]
        [Tooltip("Seconds a client waits for the server to answer its connect, and a server gives a new connection to open its session, before giving up. Zero uses the idle timeout.")]
        private ushort _connectingTimeoutSeconds = 10;
        /// <summary>
        /// Seconds a connected peer waits without hearing from the other side before it drops the link.
        /// </summary>
        [SerializeField]
        [Tooltip("Seconds a peer waits without hearing from the other side before dropping the link. One second is the least applied.")]
        private ushort _idleTimeoutSeconds = 15;
        /// <summary>
        /// The transport this component built, or <see langword="null"/> before it has.
        /// </summary>
        /// <remarks>Held so a setting changed after the first start reaches the transport every later start reuses.</remarks>
        private Quic _quic;

        /// <inheritdoc/>
        public override async Task<Transport> AddToAsync(CoreManager coreManager)
        {
            _quic = (Quic)await coreManager.TransportManager.AddTransportAsync<Quic>();

            _quic.SetPort(_port);
            _quic.RemoteHost = _remoteHost;
            _quic.SetBindAddress(_bindAddress);
            _quic.CertificatePath = _certificatePath;
            _quic.CertificatePassword = _certificatePassword;
            _quic.CertificateHash = _certificateHash;
            _quic.PinnedCertificateValidityLimitEnabled = _pinnedCertificateValidityLimitEnabled;
            _quic.SetMaximumConnections(_maximumConnections);
            _quic.MaximumReliablePacketSize = _maximumReliablePacketSize;
            _quic.AllowedOrigins = _allowedOrigins;
            _quic.Configuration.MaximumTransmissionUnit = _maximumTransmissionUnit;
            _quic.Configuration.ConnectingTimeoutSeconds = _connectingTimeoutSeconds;
            _quic.Configuration.ConnectedTimeoutSeconds = _idleTimeoutSeconds;

            return _quic;
        }
    }
}
#endif
