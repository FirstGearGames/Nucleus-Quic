#if !UNITY_WEBGL || UNITY_EDITOR
using System;
using System.Runtime.InteropServices;
using System.Text;
using CodeBoost.Logging;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// One opened copy of the MsQuic function table, with the registration every listener and connection of its owner is opened under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// MsQuic counts its opens, so each socket opens its own copy and closes it when the socket is returned, and nothing about MsQuic is
    /// held statically. Only the calls this transport makes are bound; each is turned into a delegate once, when the table is opened.
    /// </para>
    /// <para>
    /// The native library is <c>msquic.dll</c> on Windows and <c>libmsquic.so</c> on Linux, both x64. MsQuic reports its status codes
    /// differently on each: an HRESULT on Windows, where a failure is negative, and an errno on Linux, where a failure is positive.
    /// </para>
    /// </remarks>
    internal sealed unsafe class MsQuic
    {
        /// <summary>
        /// The handler for listener events.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ListenerCallback(IntPtr listener, IntPtr context, ListenerEvent* listenerEvent);

        /// <summary>
        /// The handler for connection events.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ConnectionCallback(IntPtr connection, IntPtr context, ConnectionEvent* connectionEvent);

        /// <summary>
        /// The handler for stream events.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int StreamCallback(IntPtr stream, IntPtr context, StreamEvent* streamEvent);

        /// <summary>
        /// <c>SetCallbackHandler</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void SetCallbackHandlerFunction(IntPtr handle, IntPtr handler, IntPtr context);

        /// <summary>
        /// <c>SetParam</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int SetParamFunction(IntPtr handle, uint parameter, uint bufferLength, void* buffer);

        /// <summary>
        /// <c>GetParam</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int GetParamFunction(IntPtr handle, uint parameter, uint* bufferLength, void* buffer);

        /// <summary>
        /// <c>RegistrationOpen</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int RegistrationOpenFunction(RegistrationConfig* registrationConfig, IntPtr* registration);

        /// <summary>
        /// Every call that takes one handle and returns nothing: the close calls.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void CloseFunction(IntPtr handle);

        /// <summary>
        /// <c>RegistrationShutdown</c> and <c>ConnectionShutdown</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void ShutdownFunction(IntPtr handle, int flags, ulong errorCode);

        /// <summary>
        /// <c>ConfigurationOpen</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ConfigurationOpenFunction(IntPtr registration, QuicBuffer* alpnBuffers, uint alpnBufferCount, Settings* settings, uint settingsSize, IntPtr context, IntPtr* configuration);

        /// <summary>
        /// <c>ConfigurationLoadCredential</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ConfigurationLoadCredentialFunction(IntPtr configuration, CredentialConfig* credentialConfig);

        /// <summary>
        /// <c>ListenerOpen</c> and <c>ConnectionOpen</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int OpenFunction(IntPtr registration, IntPtr handler, IntPtr context, IntPtr* handle);

        /// <summary>
        /// <c>ListenerStart</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ListenerStartFunction(IntPtr listener, QuicBuffer* alpnBuffers, uint alpnBufferCount, QuicAddress* localAddress);

        /// <summary>
        /// <c>ConnectionStart</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ConnectionStartFunction(IntPtr connection, IntPtr configuration, ushort addressFamily, byte* serverName, ushort serverPort);

        /// <summary>
        /// <c>ConnectionSetConfiguration</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ConnectionSetConfigurationFunction(IntPtr connection, IntPtr configuration);

        /// <summary>
        /// <c>StreamOpen</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int StreamOpenFunction(IntPtr connection, int flags, IntPtr handler, IntPtr context, IntPtr* stream);

        /// <summary>
        /// <c>StreamShutdown</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int StreamShutdownFunction(IntPtr stream, int flags, ulong errorCode);

        /// <summary>
        /// <c>StreamSend</c> and <c>DatagramSend</c>.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int SendFunction(IntPtr handle, QuicBuffer* buffers, uint bufferCount, int flags, IntPtr clientSendContext);

        /// <summary>
        /// The registration every listener and connection of this copy belongs to.
        /// </summary>
        internal readonly IntPtr Registration;

        /// <summary>
        /// Whether this process runs on Windows, which decides how a status code is read.
        /// </summary>
        internal readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        /// <summary>
        /// Sets the callback handler and its context on a listener, connection or stream handle.
        /// </summary>
        internal readonly SetCallbackHandlerFunction SetCallbackHandler;

        /// <summary>
        /// Writes a parameter on a handle.
        /// </summary>
        internal readonly SetParamFunction SetParam;

        /// <summary>
        /// Reads a parameter from a handle.
        /// </summary>
        internal readonly GetParamFunction GetParam;

        /// <summary>
        /// Closes a registration, blocking until every connection opened under it has been closed.
        /// </summary>
        internal readonly CloseFunction RegistrationClose;

        /// <summary>
        /// Shuts down every connection opened under a registration.
        /// </summary>
        internal readonly ShutdownFunction RegistrationShutdown;

        /// <summary>
        /// Opens a configuration holding the ALPN, the settings and later the credential.
        /// </summary>
        internal readonly ConfigurationOpenFunction ConfigurationOpen;

        /// <summary>
        /// Closes a configuration.
        /// </summary>
        internal readonly CloseFunction ConfigurationClose;

        /// <summary>
        /// Loads the TLS credential into a configuration.
        /// </summary>
        internal readonly ConfigurationLoadCredentialFunction ConfigurationLoadCredential;

        /// <summary>
        /// Opens a listener.
        /// </summary>
        internal readonly OpenFunction ListenerOpen;

        /// <summary>
        /// Closes a listener, blocking until it has stopped.
        /// </summary>
        internal readonly CloseFunction ListenerClose;

        /// <summary>
        /// Starts a listener on an address and port.
        /// </summary>
        internal readonly ListenerStartFunction ListenerStart;

        /// <summary>
        /// Opens a client connection.
        /// </summary>
        internal readonly OpenFunction ConnectionOpen;

        /// <summary>
        /// Closes a connection handle, which is the last call any handle may take.
        /// </summary>
        internal readonly CloseFunction ConnectionClose;

        /// <summary>
        /// Begins shutting a connection down.
        /// </summary>
        internal readonly ShutdownFunction ConnectionShutdown;

        /// <summary>
        /// Starts a client connection to a host and port.
        /// </summary>
        internal readonly ConnectionStartFunction ConnectionStart;

        /// <summary>
        /// Hands an accepted connection the server configuration.
        /// </summary>
        internal readonly ConnectionSetConfigurationFunction ConnectionSetConfiguration;

        /// <summary>
        /// Opens a stream on a connection.
        /// </summary>
        internal readonly StreamOpenFunction StreamOpen;

        /// <summary>
        /// Closes a stream handle once the stream has shut down.
        /// </summary>
        internal readonly CloseFunction StreamClose;

        /// <summary>
        /// Begins shutting a stream down, gracefully or not.
        /// </summary>
        internal readonly StreamShutdownFunction StreamShutdown;

        /// <summary>
        /// Queues bytes on a stream.
        /// </summary>
        internal readonly SendFunction StreamSend;

        /// <summary>
        /// Queues one unreliable datagram on a connection.
        /// </summary>
        internal readonly SendFunction DatagramSend;

        /// <summary>
        /// The success status, which reads the same on every platform.
        /// </summary>
        internal const int SuccessStatus = 0;

        /// <summary>
        /// The HTTP/3 error code for a clean close, sent with every connection this transport shuts down.
        /// </summary>
        internal const ulong NoErrorCode = 0x100;

        /// <summary>
        /// The HTTP/3 error code for a request this server will not serve.
        /// </summary>
        internal const ulong RequestRejectedErrorCode = 0x10B;

        /// <summary>
        /// Reads a stream's identifier.
        /// </summary>
        internal const uint StreamIdParameter = 0x08000000;

        /// <summary>
        /// Shuts a connection down without telling the peer.
        /// </summary>
        internal const int ConnectionShutdownSilentFlag = 0x1;

        /// <summary>
        /// Opens a stream that sends one way only.
        /// </summary>
        internal const int StreamOpenUnidirectionalFlag = 0x1;

        /// <summary>
        /// Closes the sending direction of a stream cleanly, once everything queued has been delivered.
        /// </summary>
        internal const int StreamShutdownGracefulFlag = 0x1;

        /// <summary>
        /// Closes both directions of a stream at once.
        /// </summary>
        internal const int StreamShutdownAbortFlag = 0x6;

        /// <summary>
        /// Closes the receiving direction of a stream at once, asking the peer to stop sending on it.
        /// </summary>
        internal const int StreamShutdownAbortReceiveFlag = 0x4;

        /// <summary>
        /// Starts a stream with the bytes being sent.
        /// </summary>
        internal const int SendStartFlag = 0x2;

        /// <summary>
        /// Marks the bytes being sent as the last on the stream, closing its sending direction cleanly once they are delivered.
        /// </summary>
        internal const int SendFinFlag = 0x4;

        /// <summary>
        /// Marks received stream data as the last the peer will send.
        /// </summary>
        internal const int ReceiveFinFlag = 0x2;

        /// <summary>
        /// Lets an outbound connection pick its own address family.
        /// </summary>
        internal const ushort UnspecifiedAddressFamily = 0;

        /// <summary>
        /// The IPv4 address family, which is the same number everywhere.
        /// </summary>
        internal const ushort InterNetworkAddressFamily = 2;

        /// <summary>
        /// The IPv6 address family on Windows.
        /// </summary>
        internal const ushort WindowsInterNetworkV6AddressFamily = 23;

        /// <summary>
        /// The IPv6 address family on Linux.
        /// </summary>
        internal const ushort PosixInterNetworkV6AddressFamily = 10;

        /// <summary>
        /// Loads no certificate, for a client.
        /// </summary>
        internal const int NoneCredentialType = 0;

        /// <summary>
        /// Loads a certificate and its key from a Windows certificate context, which is how the Schannel build takes one.
        /// </summary>
        internal const int CertificateContextCredentialType = 3;

        /// <summary>
        /// Loads a certificate and its key from a PKCS #12 blob.
        /// </summary>
        internal const int Pkcs12CredentialType = 6;

        /// <summary>
        /// Marks a credential as a client's.
        /// </summary>
        internal const int ClientCredentialFlag = 0x1;

        /// <summary>
        /// Skips validating the peer's certificate, for a client that checks its hash itself.
        /// </summary>
        internal const int NoCertificateValidationCredentialFlag = 0x4;

        /// <summary>
        /// Raises an event with the peer's certificate.
        /// </summary>
        internal const int IndicateCertificateReceivedCredentialFlag = 0x10;

        /// <summary>
        /// Hands the peer's certificate over as DER bytes rather than a platform object.
        /// </summary>
        internal const int UsePortableCertificatesCredentialFlag = 0x4000;

        /// <summary>
        /// The function table, kept so it can be handed back.
        /// </summary>
        private readonly IntPtr _functionTable;

        /// <summary>
        /// The version of the function table asked for.
        /// </summary>
        private const uint ApiVersion = 2;

        /// <summary>
        /// The Windows status for a certificate the peer presented being refused.
        /// </summary>
        private const int WindowsBadCertificateStatus = unchecked((int)0x8041012A);

        /// <summary>
        /// The Linux status for a certificate the peer presented being refused.
        /// </summary>
        private const int PosixBadCertificateStatus = 0xBEBC32A;

        /// <summary>
        /// The Windows status for an internal failure.
        /// </summary>
        private const int WindowsInternalErrorStatus = unchecked((int)0x80410003);

        /// <summary>
        /// The Linux status for an internal failure, which is <c>EIO</c>.
        /// </summary>
        private const int PosixInternalErrorStatus = 5;

        /// <summary>
        /// The library name, which the runtime maps to <c>msquic.dll</c> or <c>libmsquic.so</c>.
        /// </summary>
        private const string LibraryName = "msquic";

        /// <summary>
        /// Binds the calls this transport makes from an opened function table and opens a registration.
        /// </summary>
        /// <param name="functionTable">The table <c>MsQuicOpenVersion</c> returned.</param>
        /// <param name="registration">The registration opened from it.</param>
        private MsQuic(IntPtr functionTable, IntPtr registration)
        {
            _functionTable = functionTable;
            Registration = registration;

            IntPtr* functions = (IntPtr*)functionTable;

            SetCallbackHandler = Marshal.GetDelegateForFunctionPointer<SetCallbackHandlerFunction>(functions[2]);
            SetParam = Marshal.GetDelegateForFunctionPointer<SetParamFunction>(functions[3]);
            GetParam = Marshal.GetDelegateForFunctionPointer<GetParamFunction>(functions[4]);
            RegistrationClose = Marshal.GetDelegateForFunctionPointer<CloseFunction>(functions[6]);
            RegistrationShutdown = Marshal.GetDelegateForFunctionPointer<ShutdownFunction>(functions[7]);
            ConfigurationOpen = Marshal.GetDelegateForFunctionPointer<ConfigurationOpenFunction>(functions[8]);
            ConfigurationClose = Marshal.GetDelegateForFunctionPointer<CloseFunction>(functions[9]);
            ConfigurationLoadCredential = Marshal.GetDelegateForFunctionPointer<ConfigurationLoadCredentialFunction>(functions[10]);
            ListenerOpen = Marshal.GetDelegateForFunctionPointer<OpenFunction>(functions[11]);
            ListenerClose = Marshal.GetDelegateForFunctionPointer<CloseFunction>(functions[12]);
            ListenerStart = Marshal.GetDelegateForFunctionPointer<ListenerStartFunction>(functions[13]);
            ConnectionOpen = Marshal.GetDelegateForFunctionPointer<OpenFunction>(functions[15]);
            ConnectionClose = Marshal.GetDelegateForFunctionPointer<CloseFunction>(functions[16]);
            ConnectionShutdown = Marshal.GetDelegateForFunctionPointer<ShutdownFunction>(functions[17]);
            ConnectionStart = Marshal.GetDelegateForFunctionPointer<ConnectionStartFunction>(functions[18]);
            ConnectionSetConfiguration = Marshal.GetDelegateForFunctionPointer<ConnectionSetConfigurationFunction>(functions[19]);
            StreamOpen = Marshal.GetDelegateForFunctionPointer<StreamOpenFunction>(functions[21]);
            StreamClose = Marshal.GetDelegateForFunctionPointer<CloseFunction>(functions[22]);
            StreamShutdown = Marshal.GetDelegateForFunctionPointer<StreamShutdownFunction>(functions[24]);
            StreamSend = Marshal.GetDelegateForFunctionPointer<SendFunction>(functions[25]);
            DatagramSend = Marshal.GetDelegateForFunctionPointer<SendFunction>(functions[28]);
        }

        /// <summary>
        /// Returns whether a status MsQuic returned means success.
        /// </summary>
        /// <param name="status">The status.</param>
        /// <returns>True for success, including a pending operation.</returns>
        internal bool IsSucceeded(int status) => IsWindows ? status >= 0 : status <= 0;

        /// <summary>
        /// Returns the status that refuses a certificate the peer presented.
        /// </summary>
        /// <returns>The platform's bad certificate status.</returns>
        internal int GetBadCertificateStatus() => IsWindows ? WindowsBadCertificateStatus : PosixBadCertificateStatus;

        /// <summary>
        /// Returns the status that reports an internal failure, which refuses a connection a listener could not take up.
        /// </summary>
        /// <returns>The platform's internal error status.</returns>
        internal int GetInternalErrorStatus() => IsWindows ? WindowsInternalErrorStatus : PosixInternalErrorStatus;

        /// <summary>
        /// Reads a stream's identifier.
        /// </summary>
        /// <param name="stream">The stream handle.</param>
        /// <returns>The identifier, or -1 when it could not be read.</returns>
        internal long GetStreamId(IntPtr stream)
        {
            ulong streamId = 0;
            uint length = sizeof(ulong);

            return IsSucceeded(GetParam(stream, StreamIdParameter, &length, &streamId)) ? (long)streamId : -1;
        }

        /// <summary>
        /// Shuts every connection down at once, closes the registration and hands the function table back.
        /// </summary>
        /// <remarks>
        /// Blocks until every connection opened under the registration has been closed, which each does from its own shutdown callback, so
        /// it must never be called from an MsQuic callback. Connections are shut down silently first, so nothing waits on a peer to answer.
        /// </remarks>
        internal void Close()
        {
            RegistrationShutdown(Registration, ConnectionShutdownSilentFlag, 0);
            RegistrationClose(Registration);
            MsQuicClose(_functionTable);
        }

        /// <summary>
        /// Opens the function table and a registration.
        /// </summary>
        /// <param name="msQuic">The opened copy, or <see langword="null"/> when MsQuic could not be loaded or opened.</param>
        /// <returns>True when MsQuic was opened.</returns>
        /// <remarks>A missing native library is logged with where to get one, because it is the one setup step this transport cannot do itself.</remarks>
        internal static bool TryOpen(out MsQuic msQuic)
        {
            msQuic = null;

            IntPtr functionTable;

            try
            {
                int openStatus = MsQuicOpenVersion(ApiVersion, out functionTable);

                if (openStatus != SuccessStatus || functionTable == IntPtr.Zero)
                {
                    Logger<MsQuic>.LogError($"MsQuic could not be opened: status [0x{openStatus:X8}].");

                    return false;
                }
            }
            catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
            {
                Logger<MsQuic>.LogError($"The MsQuic library could not be loaded. Windows needs msquic.dll (2.2 or later) beside the plugin, and Linux needs libmsquic.so from packages.microsoft.com. {exception.Message}");

                return false;
            }

            RegistrationOpenFunction registrationOpen = Marshal.GetDelegateForFunctionPointer<RegistrationOpenFunction>(((IntPtr*)functionTable)[5]);
            byte[] appName = Encoding.ASCII.GetBytes("nucleus\0");
            IntPtr registration;
            int registrationStatus;

            fixed (byte* appNamePointer = appName)
            {
                RegistrationConfig registrationConfig = new() { AppName = appNamePointer, ExecutionProfile = 0 };

                registrationStatus = registrationOpen(&registrationConfig, &registration);
            }

            if (registrationStatus != SuccessStatus)
            {
                Logger<MsQuic>.LogError($"An MsQuic registration could not be opened: status [0x{registrationStatus:X8}].");
                MsQuicClose(functionTable);

                return false;
            }

            msQuic = new(functionTable, registration);

            return true;
        }

        /// <summary>
        /// Opens the function table.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int MsQuicOpenVersion(uint version, out IntPtr functionTable);

        /// <summary>
        /// Hands a function table back.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void MsQuicClose(IntPtr functionTable);

        /// <summary>
        /// <c>QUIC_BUFFER</c>: a length and a pointer.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct QuicBuffer
        {
            /// <summary>
            /// The number of bytes.
            /// </summary>
            public uint Length;
            /// <summary>
            /// The bytes.
            /// </summary>
            public byte* Buffer;
        }

        /// <summary>
        /// <c>QUIC_REGISTRATION_CONFIG</c>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct RegistrationConfig
        {
            /// <summary>
            /// The application name, as a null-terminated ASCII string.
            /// </summary>
            public byte* AppName;
            /// <summary>
            /// The execution profile, where zero favours latency.
            /// </summary>
            public int ExecutionProfile;
        }

        /// <summary>
        /// <c>QUIC_ADDR</c>: a Windows <c>SOCKADDR_INET</c>, or the Linux union of <c>sockaddr_in</c> and <c>sockaddr_in6</c>, which share
        /// this layout.
        /// </summary>
        [StructLayout(LayoutKind.Explicit, Size = 28)]
        internal struct QuicAddress
        {
            /// <summary>
            /// The address family.
            /// </summary>
            [FieldOffset(0)]
            public ushort Family;
            /// <summary>
            /// The port, in network byte order.
            /// </summary>
            [FieldOffset(2)]
            public ushort NetworkOrderPort;
            /// <summary>
            /// Where the four bytes of an IPv4 address start.
            /// </summary>
            [FieldOffset(4)]
            public byte InterNetworkAddress;
            /// <summary>
            /// Where the sixteen bytes of an IPv6 address start.
            /// </summary>
            [FieldOffset(8)]
            public byte InterNetworkV6Address;
        }

        /// <summary>
        /// <c>QUIC_SETTINGS</c> for MsQuic 2.4, of which only the fields this transport sets are named.
        /// </summary>
        [StructLayout(LayoutKind.Explicit, Size = 144)]
        internal struct Settings
        {
            /// <summary>
            /// One bit per field that is set, in declaration order.
            /// </summary>
            [FieldOffset(0)]
            public ulong IsSetFlags;
            /// <summary>
            /// How long a handshake may go unanswered.
            /// </summary>
            [FieldOffset(16)]
            public ulong HandshakeIdleTimeoutMilliseconds;
            /// <summary>
            /// How long a connection may go unanswered.
            /// </summary>
            [FieldOffset(24)]
            public ulong IdleTimeoutMilliseconds;
            /// <summary>
            /// How often a quiet connection is kept alive.
            /// </summary>
            [FieldOffset(88)]
            public uint KeepAliveIntervalMilliseconds;
            /// <summary>
            /// How many two-way streams the peer may open.
            /// </summary>
            [FieldOffset(94)]
            public ushort PeerBidirectionalStreamCount;
            /// <summary>
            /// How many one-way streams the peer may open.
            /// </summary>
            [FieldOffset(96)]
            public ushort PeerUnidirectionalStreamCount;
            /// <summary>
            /// Bit fields, of which bit three accepts datagrams.
            /// </summary>
            [FieldOffset(106)]
            public byte Flags;

            /// <summary>
            /// The set bit for <see cref="HandshakeIdleTimeoutMilliseconds"/>.
            /// </summary>
            public const ulong HandshakeIdleTimeoutIsSet = 1UL << 1;
            /// <summary>
            /// The set bit for <see cref="IdleTimeoutMilliseconds"/>.
            /// </summary>
            public const ulong IdleTimeoutIsSet = 1UL << 2;
            /// <summary>
            /// The set bit for <see cref="KeepAliveIntervalMilliseconds"/>.
            /// </summary>
            public const ulong KeepAliveIntervalIsSet = 1UL << 16;
            /// <summary>
            /// The set bit for <see cref="PeerBidirectionalStreamCount"/>.
            /// </summary>
            public const ulong PeerBidirectionalStreamCountIsSet = 1UL << 18;
            /// <summary>
            /// The set bit for <see cref="PeerUnidirectionalStreamCount"/>.
            /// </summary>
            public const ulong PeerUnidirectionalStreamCountIsSet = 1UL << 19;
            /// <summary>
            /// The set bit for accepting datagrams.
            /// </summary>
            public const ulong DatagramReceiveEnabledIsSet = 1UL << 27;
            /// <summary>
            /// The bit in <see cref="Flags"/> that accepts datagrams.
            /// </summary>
            public const byte DatagramReceiveEnabledFlag = 1 << 3;
        }

        /// <summary>
        /// <c>QUIC_CERTIFICATE_PKCS12</c>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct CertificatePkcs12
        {
            /// <summary>
            /// The PKCS #12 bytes.
            /// </summary>
            public byte* Asn1Blob;
            /// <summary>
            /// How many bytes <see cref="Asn1Blob"/> holds.
            /// </summary>
            public uint Asn1BlobLength;
            /// <summary>
            /// The private key's password as a null-terminated string, or null for none.
            /// </summary>
            public byte* PrivateKeyPassword;
        }

        /// <summary>
        /// <c>QUIC_CREDENTIAL_CONFIG</c>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct CredentialConfig
        {
            /// <summary>
            /// What kind of credential is loaded.
            /// </summary>
            public int Type;
            /// <summary>
            /// How it is loaded and how the peer is validated.
            /// </summary>
            public int Flags;
            /// <summary>
            /// The credential itself, whose type <see cref="Type"/> names: a <see cref="CertificatePkcs12"/>, or a Windows certificate
            /// context.
            /// </summary>
            public void* Certificate;
            /// <summary>
            /// Unused.
            /// </summary>
            public IntPtr Principal;
            /// <summary>
            /// Unused.
            /// </summary>
            public IntPtr Reserved;
            /// <summary>
            /// Unused, the credential being loaded synchronously.
            /// </summary>
            public IntPtr AsyncHandler;
            /// <summary>
            /// Unused.
            /// </summary>
            public int AllowedCipherSuites;
            /// <summary>
            /// Unused.
            /// </summary>
            public IntPtr CaCertificateFile;
        }

        /// <summary>
        /// <c>QUIC_NEW_CONNECTION_INFO</c>, of which only the addresses are read.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct NewConnectionInfo
        {
            /// <summary>
            /// The address the peer reached this listener on.
            /// </summary>
            [FieldOffset(8)]
            public QuicAddress* LocalAddress;
            /// <summary>
            /// The address the peer connected from.
            /// </summary>
            [FieldOffset(16)]
            public QuicAddress* RemoteAddress;
        }

        /// <summary>
        /// <c>QUIC_LISTENER_EVENT</c>.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct ListenerEvent
        {
            /// <summary>
            /// What happened: zero for a new connection.
            /// </summary>
            [FieldOffset(0)]
            public int Type;
            /// <summary>
            /// The new connection's details.
            /// </summary>
            [FieldOffset(8)]
            public NewConnectionInfo* NewConnectionInfo;
            /// <summary>
            /// The new connection.
            /// </summary>
            [FieldOffset(16)]
            public IntPtr NewConnection;

            /// <summary>
            /// A peer has connected.
            /// </summary>
            public const int NewConnectionType = 0;
        }

        /// <summary>
        /// <c>QUIC_CONNECTION_EVENT</c>, with each union member this transport reads named on its own.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct ConnectionEvent
        {
            /// <summary>
            /// What happened.
            /// </summary>
            [FieldOffset(0)]
            public int Type;
            /// <summary>
            /// Why the transport shut the connection down.
            /// </summary>
            [FieldOffset(8)]
            public int ShutdownStatus;
            /// <summary>
            /// The error code the peer closed the connection with.
            /// </summary>
            [FieldOffset(8)]
            public ulong PeerErrorCode;
            /// <summary>
            /// The stream the peer opened.
            /// </summary>
            [FieldOffset(8)]
            public IntPtr PeerStream;
            /// <summary>
            /// The flags the peer opened its stream with.
            /// </summary>
            [FieldOffset(16)]
            public int PeerStreamFlags;
            /// <summary>
            /// Whether datagrams may now be sent.
            /// </summary>
            [FieldOffset(8)]
            public byte IsDatagramSendEnabled;
            /// <summary>
            /// The largest datagram that may now be sent.
            /// </summary>
            [FieldOffset(10)]
            public ushort MaximumDatagramSendLength;
            /// <summary>
            /// A received datagram.
            /// </summary>
            [FieldOffset(8)]
            public QuicBuffer* DatagramBuffer;
            /// <summary>
            /// The context a sent datagram was queued with.
            /// </summary>
            [FieldOffset(8)]
            public IntPtr DatagramClientContext;
            /// <summary>
            /// Where a sent datagram has got to.
            /// </summary>
            [FieldOffset(16)]
            public int DatagramSendState;
            /// <summary>
            /// The certificate the peer presented, as a <see cref="QuicBuffer"/> of DER bytes when portable certificates are asked for.
            /// </summary>
            [FieldOffset(8)]
            public QuicBuffer* PeerCertificate;
            /// <summary>
            /// The bit fields of a completed shutdown, of which <see cref="AppCloseInProgressFlag"/> says the handle is already being
            /// closed.
            /// </summary>
            [FieldOffset(8)]
            public byte ShutdownCompleteFlags;

            /// <summary>
            /// The handshake has completed.
            /// </summary>
            public const int ConnectedType = 0;
            /// <summary>
            /// The transport began shutting the connection down, for an idle timeout or a failed handshake among others.
            /// </summary>
            public const int ShutdownInitiatedByTransportType = 1;
            /// <summary>
            /// The peer closed the connection.
            /// </summary>
            public const int ShutdownInitiatedByPeerType = 2;
            /// <summary>
            /// The connection has shut down and its handle may be closed.
            /// </summary>
            public const int ShutdownCompleteType = 3;
            /// <summary>
            /// The peer opened a stream.
            /// </summary>
            public const int PeerStreamStartedType = 6;
            /// <summary>
            /// Whether datagrams can be sent, and how large, has changed.
            /// </summary>
            public const int DatagramStateChangedType = 10;
            /// <summary>
            /// A datagram has arrived.
            /// </summary>
            public const int DatagramReceivedType = 11;
            /// <summary>
            /// A sent datagram has moved on.
            /// </summary>
            public const int DatagramSendStateChangedType = 12;
            /// <summary>
            /// The peer presented its certificate.
            /// </summary>
            public const int PeerCertificateReceivedType = 15;
            /// <summary>
            /// The first datagram send state MsQuic stops tracking at: lost and given up on.
            /// </summary>
            public const int FirstFinalDatagramSendState = 3;
            /// <summary>
            /// The peer's stream sends one way only.
            /// </summary>
            public const int UnidirectionalStreamFlag = 0x1;
            /// <summary>
            /// The bit in <see cref="ShutdownCompleteFlags"/> set when the application closing the handle raised the shutdown, so the
            /// handle must not be closed again.
            /// </summary>
            public const byte AppCloseInProgressFlag = 0x4;
        }

        /// <summary>
        /// <c>QUIC_STREAM_EVENT</c>, with each union member this transport reads named on its own.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct StreamEvent
        {
            /// <summary>
            /// What happened.
            /// </summary>
            [FieldOffset(0)]
            public int Type;
            /// <summary>
            /// How many bytes arrived across every buffer.
            /// </summary>
            [FieldOffset(16)]
            public ulong ReceiveTotalBufferLength;
            /// <summary>
            /// The buffers that arrived.
            /// </summary>
            [FieldOffset(24)]
            public QuicBuffer* ReceiveBuffers;
            /// <summary>
            /// How many buffers arrived.
            /// </summary>
            [FieldOffset(32)]
            public uint ReceiveBufferCount;
            /// <summary>
            /// The receive flags, among them the peer's FIN.
            /// </summary>
            [FieldOffset(36)]
            public int ReceiveFlags;
            /// <summary>
            /// The context a completed send was queued with.
            /// </summary>
            [FieldOffset(16)]
            public IntPtr SendClientContext;
            /// <summary>
            /// The bit fields of a completed shutdown, of which <see cref="AppCloseInProgressFlag"/> says the handle is already being
            /// closed.
            /// </summary>
            [FieldOffset(9)]
            public byte ShutdownCompleteFlags;

            /// <summary>
            /// Data has arrived.
            /// </summary>
            public const int ReceiveType = 1;
            /// <summary>
            /// A send has completed, delivered or cancelled.
            /// </summary>
            public const int SendCompleteType = 2;
            /// <summary>
            /// The peer has finished sending.
            /// </summary>
            public const int PeerSendShutdownType = 3;
            /// <summary>
            /// The peer abandoned its sending direction.
            /// </summary>
            public const int PeerSendAbortedType = 4;
            /// <summary>
            /// The peer abandoned its receiving direction.
            /// </summary>
            public const int PeerReceiveAbortedType = 5;
            /// <summary>
            /// The sending direction has finished, with everything sent acknowledged when it was graceful.
            /// </summary>
            public const int SendShutdownCompleteType = 6;
            /// <summary>
            /// The stream has shut down and its handle may be closed.
            /// </summary>
            public const int ShutdownCompleteType = 7;
            /// <summary>
            /// The bit in <see cref="ShutdownCompleteFlags"/> set when the application closing the handle raised the shutdown, so the
            /// handle must not be closed again.
            /// </summary>
            public const byte AppCloseInProgressFlag = 0x1;
        }
    }
}
#endif
