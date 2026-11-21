using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Nucleus.Connections;
using Nucleus.Managers.Core;
using Nucleus.Managers.Messages;
using Nucleus.Transports;
using Xunit;

namespace Nucleus.Integrations.Unity.Transports.Tests;

// The hostile peers are System.Net.Quic, which runs where MsQuic does.
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public partial class QuicLiveTests
{
    /// <summary>
    /// How long a test waits on something MsQuic does on its own threads before it fails.
    /// </summary>
    private static readonly TimeSpan BackgroundWaitTimeout = TimeSpan.FromSeconds(10);
    /// <summary>
    /// The largest reliable packet a server under attack allows, small so a flood passes it quickly.
    /// </summary>
    private const int HostileMaximumReliablePacketSize = 64 * 1024;
    /// <summary>
    /// The most a hostile peer sends before a test decides nothing will stop it.
    /// </summary>
    private const int HostileByteBudget = 16 * 1024 * 1024;
    /// <summary>
    /// The size of each write a hostile peer floods with.
    /// </summary>
    private const int HostileWriteSize = 16 * 1024;
    /// <summary>
    /// How many packets a flooding peer sends between two of the server's passes, well past either cap below.
    /// </summary>
    private const int FloodPacketCount = 40_000;
    /// <summary>
    /// The most packets a session may have queued unread before its datagrams are dropped, as the transport sets it.
    /// </summary>
    private const int MaximumQueuedDatagramCount = 1024;
    /// <summary>
    /// The most packets a session may have queued unread before a reliable one closes it, as the transport sets it.
    /// </summary>
    private const int MaximumQueuedReliablePacketCount = 16384;
    /// <summary>
    /// The HTTP/3 error code for a clean close.
    /// </summary>
    private const long NoErrorCode = 0x100;
    /// <summary>
    /// The HTTP/3 error code for a request abandoned by the side that made it.
    /// </summary>
    private const long RequestCancelledErrorCode = 0x10C;

    /// <summary>
    /// A client whose last packet, departure and successor's arrival all reach the server in one pass has that packet read as its own or
    /// not at all, never as the newcomer's, although the newcomer is handed the departed client's pooled Connection.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AClientLeavingInThePassAnotherJoins_HasNoPacketReadAsTheNewcomers()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);
        (CoreManager departingClient, Quic departingClientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await DriveUntilAsync(server, departingClient, () => IsClientAuthenticated(departingClient));

        List<Connection> probeSenders = new();
        server.MessageManager.RegisterMessageHandler((in MessageContext messageContext, ProbeMessage probeMessage) => probeSenders.Add(messageContext.SenderConnection));

        // The server is not driven again until the last step, so the probe, the departure and the arrival all land in one pass.
        Assert.True(departingClient.TransportManager.TryGetServerConnection(out Connection serverConnection));
        serverConnection.SendMessage(Channel.Reliable, new ProbeMessage(51, new byte[] { 5 }));
        DriveFullTick(departingClient);

        await WaitUntilAsync(() => ReadQueuedServerEvents(serverTransport).Exists(queuedEvent => queuedEvent is { Type: "Received", Channel: Channel.Reliable }), "the departing client's probe to reach the server");
        Assert.Equal(ConnectionStateChangeResult.Success, await departingClientTransport.DisconnectLocalConnectionAsync(Invoker.Client));
        await WaitUntilAsync(() => ReadQueuedServerEvents(serverTransport).Exists(queuedEvent => queuedEvent.Type == "Closed"), "the departing client's close to reach the server");

        (CoreManager joiningClient, Quic joiningClientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await WaitUntilAsync(() => ReadQueuedServerEvents(serverTransport).Exists(queuedEvent => queuedEvent.Type == "Opened"), "the joining client's session to open");

        DriveFullTick(server);

        Connection joinedClient = Assert.Single(server.TransportManager.ActiveConnections);
        Assert.DoesNotContain(probeSenders, probeSender => ReferenceEquals(probeSender, joinedClient));

        await joiningClientTransport.ShutdownAsync();
        await departingClientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A client that opens a reliable stream naming a session no CONNECT has opened, and floods it, is cut off once it has sent more than
    /// the largest reliable packet, rather than having everything held for a session that never opens.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AReliableStreamOpenedBeforeAnyConnect_IsCutOffPastTheLargestPacket()
    {
        ushort port = ProbeFreeUdpPort();
        (_, Quic serverTransport) = await CreateServerAsync(port);
        serverTransport.MaximumReliablePacketSize = HostileMaximumReliablePacketSize;

        Assert.Equal(ConnectionStateChangeResult.Success, await serverTransport.ConnectAsync(Invoker.Server));

        await using QuicConnection hostileConnection = await ConnectRawClientAsync(port);
        await using QuicStream reliableStream = await hostileConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        // The two-way stream signal, then session zero, which no CONNECT has opened.
        await reliableStream.WriteAsync(new byte[] { 0x40, 0x41, 0x00 });

        Assert.True(await IsFloodCutOffAsync(reliableStream), $"The server held [{HostileByteBudget}] bytes on a reliable stream whose session never opened, past the [{HostileMaximumReliablePacketSize}] byte limit, without closing the connection.");

        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A server that answers the client's CONNECT with headers that never end is dropped once it has sent more header bytes than a request
    /// may, and the client falls back to Disconnected, rather than holding everything while it waits in Connecting.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AServerWhoseResponseHeadersNeverEnd_IsDroppedByTheClient()
    {
        using X509Certificate2 certificate = CreateRawServerCertificate(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(13));
        await using QuicListener hostileListener = await ListenRawServerAsync(certificate);
        (CoreManager client, Quic clientTransport) = await ConnectClientAsync((ushort)hostileListener.LocalEndPoint.Port, Convert.ToHexString(SHA256.HashData(certificate.RawData)));

        await using QuicConnection hostileConnection = await hostileListener.AcceptConnectionAsync();
        await using QuicStream connectStream = await AcceptBidirectionalStreamAsync(hostileConnection);

        // A HEADERS frame announced as a gigabyte long, which never ends.
        await connectStream.WriteAsync(new byte[] { 0x01, 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 });

        bool isFloodCutOff = await IsFloodCutOffAsync(connectStream);

        await DriveUntilAsync(client, client, () => clientTransport.ClientSocket.State is LocalConnectionState.Disconnected, () => $"The client is still [{clientTransport.ClientSocket.State}] after the server sent [{HostileByteBudget}] bytes of headers that never ended, and the flood was cut off: [{isFloodCutOff}].");

        await clientTransport.ShutdownAsync();
    }

    /// <summary>
    /// A CONNECT that does not ask for WebTransport, naming no protocol or another one, is refused rather than taken as a session.
    /// </summary>
    /// <param name="protocol">The <c>:protocol</c> the request names, or empty to name none.</param>
    [Theory(Timeout = 60000)]
    [InlineData("")]
    [InlineData("connect-udp")]
    public async Task LiveWebTransport_AConnectNotAskingForWebTransport_IsRefused(string protocol)
    {
        ushort port = ProbeFreeUdpPort();
        (_, Quic serverTransport) = await StartServerAsync(port);

        await using QuicConnection hostileConnection = await ConnectRawClientAsync(port);
        await using QuicStream requestStream = await hostileConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        await requestStream.WriteAsync(CreateConnectRequestFrame(protocol.Length == 0 ? [] : CreatePlainProtocolFieldLine(protocol)));

        Assert.False(await IsConnectAcceptedAsync(requestStream), $"The server accepted a CONNECT naming the protocol [{protocol}] as a WebTransport session.");

        await hostileConnection.CloseAsync(NoErrorCode);
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A CONNECT naming the WebTransport protocol with its field name and value Huffman coded, as a browser's QPACK encoder writes them
    /// because that is shorter, is accepted.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AConnectWithAHuffmanCodedProtocol_IsAccepted()
    {
        ushort port = ProbeFreeUdpPort();
        (_, Quic serverTransport) = await StartServerAsync(port);

        await using QuicConnection quicConnection = await ConnectRawClientAsync(port);
        await using QuicStream requestStream = await quicConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        // A literal name with the Huffman bit, its length seven, and :protocol; then a Huffman value nine long, webtransport.
        byte[] huffmanProtocolFieldLine = [0x2F, 0x00, 0xB9, 0x5D, 0x87, 0x49, 0xC8, 0x7A, 0x3F, 0x89, 0xF0, 0x58, 0xD3, 0x60, 0xEA, 0x45, 0x67, 0xB1, 0x3F];

        await requestStream.WriteAsync(CreateConnectRequestFrame(huffmanProtocolFieldLine));

        Assert.True(await IsConnectAcceptedAsync(requestStream), "The server refused a CONNECT whose :protocol webtransport was Huffman coded.");

        await quicConnection.CloseAsync(NoErrorCode);
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A client that completes its handshake and never opens a session is closed once the connecting timeout has passed, where the server's
    /// own keep-alives would otherwise hold it open for good.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AConnectionThatNeverOpensASession_IsClosedAfterTheConnectingTimeout()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await CreateServerAsync(port);
        serverTransport.Configuration.ConnectingTimeoutSeconds = 1;

        Assert.Equal(ConnectionStateChangeResult.Success, await serverTransport.ConnectAsync(Invoker.Server));

        await using QuicConnection idleConnection = await ConnectRawClientAsync(port);
        Task idleConnectionClosedTask = WaitForConnectionCloseAsync(idleConnection);
        Stopwatch stopwatch = Stopwatch.StartNew();

        await DriveUntilAsync(server, server, () => idleConnectionClosedTask.IsCompleted, () => $"The server held a connection that never opened a session for [{stopwatch.Elapsed.TotalSeconds:0.0}] seconds, past its [1] second connecting timeout.");

        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A server capped at one client holds at most two connections, opened or not, and refuses the rest at their handshake, rather than
    /// taking every connection that asks and keeping each until it opens a session; once those close, it takes connections again.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_ConnectionsPastTwiceTheCap_AreRefusedAtTheHandshake()
    {
        ushort port = ProbeFreeUdpPort();
        (_, Quic serverTransport) = await CreateServerAsync(port);
        serverTransport.SetMaximumConnections(1);

        Assert.Equal(ConnectionStateChangeResult.Success, await serverTransport.ConnectAsync(Invoker.Server));

        List<QuicConnection> heldConnections = new();

        for (int i = 0; i < 4; i++)
        {
            try
            {
                heldConnections.Add(await ConnectRawClientAsync(port));
            }
            catch (QuicException)
            {
                // Refused at the handshake.
            }
        }

        int heldConnectionCount = heldConnections.Count;

        foreach (QuicConnection heldConnection in heldConnections)
            await heldConnection.DisposeAsync();

        // A closed connection stops counting once MsQuic releases it, which follows its close by a few round trips.
        QuicConnection? laterConnection = null;
        DateTime deadline = DateTime.UtcNow + BackgroundWaitTimeout;

        while (laterConnection is null && DateTime.UtcNow < deadline)
        {
            try
            {
                laterConnection = await ConnectRawClientAsync(port);
            }
            catch (QuicException)
            {
                await Task.Delay(20);
            }
        }

        bool isLaterConnectionTaken = laterConnection is not null;

        if (laterConnection is not null)
            await laterConnection.DisposeAsync();

        await serverTransport.ShutdownAsync();

        Assert.True(heldConnectionCount <= 2, $"A server capped at [1] client held [{heldConnectionCount}] connections that never opened a session.");
        Assert.True(isLaterConnectionTaken, $"The server still refused connections [{BackgroundWaitTimeout.TotalSeconds}] seconds after every connection it held had closed.");
    }

    /// <summary>
    /// A client that floods tiny reliable packets between two of the server's passes has exactly as many of them queued as a session may hold,
    /// and is cut off, rather than having MsQuic's threads queue every one of them for the network loop.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AFloodOfReliablePacketsBetweenTwoPasses_IsHeldToTheQueueCap()
    {
        ushort port = ProbeFreeUdpPort();
        (_, Quic serverTransport) = await StartServerAsync(port);

        await using QuicConnection hostileConnection = await ConnectRawClientAsync(port);
        await using QuicStream connectStream = await hostileConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        await connectStream.WriteAsync(CreateConnectRequestFrame(CreatePlainProtocolFieldLine("webtransport")));
        Assert.True(await IsConnectAcceptedAsync(connectStream));

        // The stream signal and session zero, the CONNECT's stream, then one-byte packets each behind a one-byte length.
        byte[] flood = new byte[3 + FloodPacketCount * 2];
        flood[0] = 0x40;
        flood[1] = 0x41;

        for (int i = 0; i < FloodPacketCount; i++)
            flood[3 + i * 2] = 0x01;

        await using QuicStream reliableStream = await hostileConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await reliableStream.WriteAsync(flood);

        int queuedPacketCount = await WaitForQueuedServerPacketsToSettleAsync(serverTransport, Channel.Reliable);

        await hostileConnection.CloseAsync(NoErrorCode);
        await serverTransport.ShutdownAsync();

        Assert.True(queuedPacketCount == MaximumQueuedReliablePacketCount, $"The server queued [{queuedPacketCount}] of the [{FloodPacketCount}] reliable packets one session sent between two passes, where a session may hold [{MaximumQueuedReliablePacketCount}].");
    }

    /// <summary>
    /// A client that floods datagrams between two of the server's passes has exactly as many of them queued as a session may hold, the rest
    /// dropped as a full socket drops them, rather than having MsQuic's threads queue every one of them for the network loop.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AFloodOfDatagramsBetweenTwoPasses_IsHeldToTheQueueCap()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);
        (CoreManager client, Quic clientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await DriveUntilAsync(server, client, () => IsClientAuthenticated(client));

        // What the client sent while authenticating is read first, so the flood counts against an empty queue; the client is not driven again.
        for (int i = 0; i < 5; i++)
        {
            await Task.Delay(20);
            DriveFullTick(server);
        }

        // The client's own session sends the datagrams directly, so the engine's batching cannot fold them together.
        object clientSession = typeof(QuicClientSocket).GetField("_webTransportSession", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(clientTransport.ClientSocket)!;
        MethodInfo trySend = clientSession.GetType().GetMethod("TrySend", BindingFlags.Instance | BindingFlags.NonPublic)!;
        object[] trySendArguments = [Channel.Unreliable, new ArraySegment<byte>([0xAA])];
        int sentDatagramCount = 0;

        for (int i = 0; i < FloodPacketCount; i++)
        {
            if ((bool)trySend.Invoke(clientSession, trySendArguments)!)
                sentDatagramCount++;
        }

        int queuedPacketCount = await WaitForQueuedServerPacketsToSettleAsync(serverTransport, Channel.Unreliable);

        // Once the network loop has taken them, which the queue's own drain stands in for, the session may queue as many again.
        object serverEvents = GetServerEvents(serverTransport);
        serverEvents.GetType().GetMethod("Clear", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(serverEvents, null);

        for (int i = 0; i < FloodPacketCount; i++)
            trySend.Invoke(clientSession, trySendArguments);

        int requeuedPacketCount = await WaitForQueuedServerPacketsToSettleAsync(serverTransport, Channel.Unreliable);

        await clientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();

        Assert.True(queuedPacketCount == MaximumQueuedDatagramCount, $"The server queued [{queuedPacketCount}] of the [{sentDatagramCount}] datagrams one session sent between two passes, where a session may hold [{MaximumQueuedDatagramCount}].");
        Assert.True(requeuedPacketCount == MaximumQueuedDatagramCount, $"Once its first [{queuedPacketCount}] datagrams were taken, the server queued [{requeuedPacketCount}] of the session's next flood, where a session may hold [{MaximumQueuedDatagramCount}].");
    }

    /// <summary>
    /// Opens a bare QUIC connection to a local server, offering HTTP/3 and doing nothing more, for a test to play a hostile client.
    /// </summary>
    /// <param name="port">The server's port.</param>
    /// <returns>The connection, its handshake complete.</returns>
    /// <remarks>
    /// A test closes it before stopping the server while it is still open: a stream left open is otherwise disposed by waiting out the idle
    /// timeout for an acknowledgment a stopped server never sends.
    /// </remarks>
    private static ValueTask<QuicConnection> ConnectRawClientAsync(ushort port) => QuicConnection.ConnectAsync(new()
    {
        RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, port),
        DefaultStreamErrorCode = RequestCancelledErrorCode,
        DefaultCloseErrorCode = NoErrorCode,
        MaxInboundUnidirectionalStreams = 8,
        ClientAuthenticationOptions = new()
        {
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            TargetHost = "localhost",
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
        },
    });

    /// <summary>
    /// Starts a bare QUIC listener on a free loopback port, offering HTTP/3 and doing nothing more, for a test to play a hostile server.
    /// </summary>
    /// <param name="certificate">The certificate it presents, which the Nucleus client pins.</param>
    /// <returns>The listener.</returns>
    private static ValueTask<QuicListener> ListenRawServerAsync(X509Certificate2 certificate) => QuicListener.ListenAsync(new()
    {
        ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
        ApplicationProtocols = [SslApplicationProtocol.Http3],
        ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
        {
            DefaultStreamErrorCode = RequestCancelledErrorCode,
            DefaultCloseErrorCode = NoErrorCode,
            MaxInboundBidirectionalStreams = 4,
            MaxInboundUnidirectionalStreams = 8,
            ServerAuthenticationOptions = new()
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ServerCertificate = certificate,
            },
        }),
    });

    /// <summary>
    /// Makes a self-signed ECDSA P-256 certificate, the kind a browser accepts by its hash, valid between two times.
    /// </summary>
    /// <param name="notBefore">When it becomes valid.</param>
    /// <param name="notAfter">When it expires.</param>
    /// <returns>The certificate, with its private key in a stored key the certificate deletes when it is disposed.</returns>
    /// <remarks>Schannel signs in another process, which cannot reach an ephemeral key, so the key is carried through PKCS #12 into a stored one.</remarks>
    private static X509Certificate2 CreateRawServerCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new("CN=localhost", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 ephemeralCertificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

        return X509CertificateLoader.LoadPkcs12(ephemeralCertificate.Export(X509ContentType.Pfx), password: null);
    }

    /// <summary>
    /// Takes the first two-way stream a peer opens, passing over the one-way streams it opens first.
    /// </summary>
    /// <param name="quicConnection">The connection.</param>
    /// <returns>The stream.</returns>
    private static async Task<QuicStream> AcceptBidirectionalStreamAsync(QuicConnection quicConnection)
    {
        while (true)
        {
            QuicStream quicStream = await quicConnection.AcceptInboundStreamAsync();

            if (quicStream.Type is QuicStreamType.Bidirectional)
                return quicStream;
        }
    }

    /// <summary>
    /// Builds a CONNECT request's HEADERS frame as a browser lays one out: <c>:method CONNECT</c> and <c>:scheme https</c> as static
    /// entries, <c>:authority</c> and <c>:path</c> as static names with plain values, then the protocol field line given.
    /// </summary>
    /// <param name="protocolFieldLine">The encoded <c>:protocol</c> field line, or empty for none.</param>
    /// <returns>The frame.</returns>
    private static byte[] CreateConnectRequestFrame(byte[] protocolFieldLine)
    {
        byte[] authority = Encoding.ASCII.GetBytes("localhost:7777");
        List<byte> fieldSection = [0x00, 0x00, 0xCF, 0xD7, 0x50, (byte)authority.Length, .. authority, 0x51, 0x01, (byte)'/', .. protocolFieldLine];

        Assert.True(fieldSection.Count < 64, "The field section must fit a one-byte length.");

        return [0x01, (byte)fieldSection.Count, .. fieldSection];
    }

    /// <summary>
    /// Encodes a <c>:protocol</c> field line with a plain literal name and value, as this transport's own client writes it.
    /// </summary>
    /// <param name="protocol">The protocol named, shorter than 127 characters.</param>
    /// <returns>The field line.</returns>
    private static byte[] CreatePlainProtocolFieldLine(string protocol) => [0x27, 0x02, .. Encoding.ASCII.GetBytes(":protocol"), (byte)protocol.Length, .. Encoding.ASCII.GetBytes(protocol)];

    /// <summary>
    /// Reads what a server answers a CONNECT with.
    /// </summary>
    /// <param name="requestStream">The stream the CONNECT was sent on.</param>
    /// <returns>True when the server answered with <c>:status 200</c>; false when it refused the request or closed the stream.</returns>
    /// <remarks>This transport's server answers with a field section whose first line is <c>:status 200</c> as a static entry, so that is all that is read.</remarks>
    private static async Task<bool> IsConnectAcceptedAsync(QuicStream requestStream)
    {
        byte[] response = new byte[64];
        int responseLength = 0;

        try
        {
            // The frame type, a one-byte length, and the field section's two prefix bytes come before the status.
            while (responseLength < 5)
            {
                int readLength = await requestStream.ReadAsync(response.AsMemory(responseLength));

                if (readLength == 0)
                    return false;

                responseLength += readLength;
            }
        }
        catch (QuicException)
        {
            return false;
        }

        return response[0] == 0x01 && response[4] == 0xD9;
    }

    /// <summary>
    /// Takes and drops every stream a peer opens until the connection closes.
    /// </summary>
    /// <param name="quicConnection">The connection.</param>
    private static async Task WaitForConnectionCloseAsync(QuicConnection quicConnection)
    {
        try
        {
            while (true)
                await (await quicConnection.AcceptInboundStreamAsync()).DisposeAsync();
        }
        catch (Exception exception) when (exception is QuicException or ObjectDisposedException)
        {
            // Closed by the peer, or disposed by the test.
        }
    }

    /// <summary>
    /// Writes filler on a stream until the peer cuts it off or the budget runs out, then writes once more after a pause, so a close already
    /// on its way is heard.
    /// </summary>
    /// <param name="stream">The stream flooded.</param>
    /// <returns>True when the peer closed the stream or the connection before the flood ended.</returns>
    private static async Task<bool> IsFloodCutOffAsync(QuicStream stream)
    {
        byte[] filler = new byte[HostileWriteSize];

        try
        {
            for (int writtenByteCount = 0; writtenByteCount < HostileByteBudget; writtenByteCount += filler.Length)
                await stream.WriteAsync(filler);

            await Task.Delay(500);
            await stream.WriteAsync(filler);
        }
        catch (QuicException)
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Waits, without driving either peer, for something MsQuic does on its own threads, or fails the test.
    /// </summary>
    /// <param name="condition">The condition awaited.</param>
    /// <param name="description">What is awaited, for the failure message.</param>
    private static async Task WaitUntilAsync(Func<bool> condition, string description)
    {
        DateTime deadline = DateTime.UtcNow + BackgroundWaitTimeout;

        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Waited [{BackgroundWaitTimeout.TotalSeconds}] seconds for {description}.");

            await Task.Delay(2);
        }
    }

    /// <summary>
    /// Waits, without driving the server, until the packets its MsQuic threads have queued on a channel stop growing.
    /// </summary>
    /// <param name="serverTransport">The server's transport.</param>
    /// <param name="channel">The channel counted.</param>
    /// <returns>How many packets were queued on the channel once the count settled.</returns>
    private static async Task<int> WaitForQueuedServerPacketsToSettleAsync(Quic serverTransport, Channel channel)
    {
        DateTime deadline = DateTime.UtcNow + BackgroundWaitTimeout;
        int queuedPacketCount = 0;

        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(250);

            int nextQueuedPacketCount = ReadQueuedServerEvents(serverTransport).FindAll(queuedEvent => queuedEvent.Type == "Received" && queuedEvent.Channel == channel).Count;

            if (nextQueuedPacketCount > 0 && nextQueuedPacketCount == queuedPacketCount)
                return queuedPacketCount;

            queuedPacketCount = nextQueuedPacketCount;
        }

        return queuedPacketCount;
    }

    /// <summary>
    /// Returns the queue a server's MsQuic threads report into.
    /// </summary>
    /// <param name="serverTransport">The server's transport.</param>
    /// <returns>The server socket's <c>WebTransportEvents</c>.</returns>
    private static object GetServerEvents(Quic serverTransport) => typeof(QuicServerSocket).GetField("_events", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(serverTransport.ServerSocket)!;

    /// <summary>
    /// Reads what a server's MsQuic threads have queued for its next receive pass, without taking any of it.
    /// </summary>
    /// <param name="serverTransport">The server's transport.</param>
    /// <returns>Each queued event's type name and channel, oldest first.</returns>
    /// <remarks>Read under the queue's own lock, so a MsQuic thread queuing at the same moment cannot tear the walk.</remarks>
    private static List<(string Type, Channel Channel)> ReadQueuedServerEvents(Quic serverTransport)
    {
        const BindingFlags InstanceFieldFlags = BindingFlags.Instance | BindingFlags.NonPublic;

        object events = GetServerEvents(serverTransport);
        object eventsLock = events.GetType().GetField("_lock", InstanceFieldFlags)!.GetValue(events)!;
        IEnumerable queuedEvents = (IEnumerable)events.GetType().GetField("_queuedEvents", InstanceFieldFlags)!.GetValue(events)!;
        List<(string Type, Channel Channel)> readEvents = new();

        lock (eventsLock)
        {
            foreach (object queuedEvent in queuedEvents)
            {
                Type queuedEventType = queuedEvent.GetType();

                readEvents.Add((queuedEventType.GetField("Type")!.GetValue(queuedEvent)!.ToString()!, (Channel)queuedEventType.GetField("Channel")!.GetValue(queuedEvent)!));
            }
        }

        return readEvents;
    }
}
