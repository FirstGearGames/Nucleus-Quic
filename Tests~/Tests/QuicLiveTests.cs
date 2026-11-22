using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using CodeBoost.Logging;
using Nucleus.Connections;
using Nucleus.Managers.Core;
using Nucleus.Managers.Messages;
using Nucleus.Managers.NetworkLoop;
using Nucleus.Serializers;
using Nucleus.Transports;
using Xunit;
using Xunit.Abstractions;

namespace Nucleus.Integrations.Unity.Transports.Tests;

/// <summary>
/// Live coverage for <see cref="Quic"/>: a server and a client, each its own CoreManager, over real QUIC on loopback,
/// driven by hand.
/// </summary>
/// <remarks>
/// Authentication alone proves little, so each case asserts what crossed the wire: a message each way on each channel, a reliable message
/// many datagrams long, the address the server recorded, and the client's link dropping when the server kicks it.
/// </remarks>
public partial class QuicLiveTests
{
    /// <summary>
    /// Attempts allowed for any one settle.
    /// </summary>
    private const int MaximumDriveAttempts = 1500;
    /// <summary>
    /// The size of the reliable message each side sends, many times one datagram, so the stream framing has to reassemble it.
    /// </summary>
    private const int LargePayloadSize = 20_000;
    /// <summary>
    /// The size of the unreliable message each side sends, several datagrams long, so the engine has to split it into pieces.
    /// </summary>
    private const int UnreliablePayloadSize = 4_000;

    /// <summary>
    /// Routes the engine's log lines to the test output.
    /// </summary>
    /// <param name="testOutputHelper">The per-test output sink.</param>
    public QuicLiveTests(ITestOutputHelper testOutputHelper) => LoggingService.UseLogger(new TestOutputLogger(testOutputHelper));

    /// <summary>
    /// A client pinning the hash of the certificate the server made for itself connects, authenticates, and exchanges a message each way
    /// on each channel, the reliable one far larger than a datagram; the server records the client's loopback address.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AClientPinningTheServersCertificate_ExchangesMessagesOnBothChannels()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);

        Assert.Equal(64, serverTransport.ServerCertificateHash.Length);

        (CoreManager client, Quic clientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await DriveUntilAsync(server, client, () => IsClientAuthenticated(client));

        Connection remoteClient = Assert.Single(server.TransportManager.ActiveConnections);
        Assert.Equal("127.0.0.1", remoteClient.RemoteAddress);

        List<(Channel Channel, ProbeMessage Message, byte[] Payload)> serverReceived = new();
        List<(Channel Channel, ProbeMessage Message, byte[] Payload)> clientReceived = new();

        server.MessageManager.RegisterMessageHandler((in MessageContext messageContext, ProbeMessage probeMessage) => serverReceived.Add((messageContext.Channel, probeMessage, probeMessage.Payload.ToArray())));
        client.MessageManager.RegisterMessageHandler((in MessageContext messageContext, ProbeMessage probeMessage) => clientReceived.Add((messageContext.Channel, probeMessage, probeMessage.Payload.ToArray())));

        byte[] largePayload = CreatePayload(LargePayloadSize);
        Assert.True(client.TransportManager.TryGetServerConnection(out Connection serverConnection));

        serverConnection.SendMessage(Channel.Reliable, new ProbeMessage(12, largePayload));
        remoteClient.SendMessage(Channel.Reliable, new ProbeMessage(22, largePayload));

        // A datagram can be dropped even on loopback, so the unreliable probes are sent every pass until one lands.
        await DriveUntilAsync(server, client, () =>
        {
            if (!serverReceived.Exists(received => received.Channel is Channel.Unreliable))
                serverConnection.SendMessage(Channel.Unreliable, new ProbeMessage(11, new byte[] { 1, 2, 3 }));

            if (!clientReceived.Exists(received => received.Channel is Channel.Unreliable))
                remoteClient.SendMessage(Channel.Unreliable, new ProbeMessage(21, new byte[] { 4, 5, 6 }));

            return serverReceived.Count >= 2 && clientReceived.Count >= 2 && serverReceived.Exists(received => received.Channel is Channel.Unreliable) && clientReceived.Exists(received => received.Channel is Channel.Unreliable);
        }, () => $"The server received [{string.Join(", ", serverReceived.ConvertAll(received => $"{received.Message.Value} on {received.Channel}"))}] and the client received [{string.Join(", ", clientReceived.ConvertAll(received => $"{received.Message.Value} on {received.Channel}"))}].");

        (Channel Channel, ProbeMessage Message, byte[] Payload) serverReliable = serverReceived.Find(received => received.Channel is Channel.Reliable);
        (Channel Channel, ProbeMessage Message, byte[] Payload) clientReliable = clientReceived.Find(received => received.Channel is Channel.Reliable);
        (Channel Channel, ProbeMessage Message, byte[] Payload) serverUnreliable = serverReceived.Find(received => received.Channel is Channel.Unreliable);
        (Channel Channel, ProbeMessage Message, byte[] Payload) clientUnreliable = clientReceived.Find(received => received.Channel is Channel.Unreliable);

        Assert.Equal(12, serverReliable.Message.Value);
        Assert.Equal(largePayload, serverReliable.Payload);
        Assert.Equal(22, clientReliable.Message.Value);
        Assert.Equal(largePayload, clientReliable.Payload);
        Assert.Equal(11, serverUnreliable.Message.Value);
        Assert.Equal(new byte[] { 1, 2, 3 }, serverUnreliable.Payload);
        Assert.Equal(21, clientUnreliable.Message.Value);
        Assert.Equal(new byte[] { 4, 5, 6 }, clientUnreliable.Payload);

        await clientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// An unreliable message several datagrams long, which the engine splits into pieces, arrives whole each way: every piece crosses as a
    /// full-size datagram and the pieces are put back together, where the small probes only ever fill a few bytes of one.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AnUnreliableMessageLargerThanADatagram_ArrivesWholeEachWay()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);
        (CoreManager client, Quic clientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await DriveUntilAsync(server, client, () => IsClientAuthenticated(client));

        Connection remoteClient = Assert.Single(server.TransportManager.ActiveConnections);
        Assert.True(client.TransportManager.TryGetServerConnection(out Connection serverConnection));

        byte[] payload = CreatePayload(UnreliablePayloadSize);
        byte[]? serverReceived = null;
        byte[]? clientReceived = null;

        server.MessageManager.RegisterMessageHandler((in MessageContext messageContext, ProbeMessage probeMessage) => serverReceived = messageContext.Channel is Channel.Unreliable ? probeMessage.Payload.ToArray() : null);
        client.MessageManager.RegisterMessageHandler((in MessageContext messageContext, ProbeMessage probeMessage) => clientReceived = messageContext.Channel is Channel.Unreliable ? probeMessage.Payload.ToArray() : null);

        // Losing any one piece loses the message, so each side sends again every pass until one lands.
        await DriveUntilAsync(server, client, () =>
        {
            if (serverReceived is null)
                serverConnection.SendMessage(Channel.Unreliable, new ProbeMessage(31, payload));

            if (clientReceived is null)
                remoteClient.SendMessage(Channel.Unreliable, new ProbeMessage(41, payload));

            return serverReceived is not null && clientReceived is not null;
        }, () => $"The server received [{serverReceived?.Length}] bytes and the client received [{clientReceived?.Length}] bytes.");

        Assert.Equal(payload, serverReceived);
        Assert.Equal(payload, clientReceived);

        await clientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A client pinning a hash the server's certificate does not have is refused during the handshake and falls back to Disconnected.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AClientPinningAnotherHash_IsRefused()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);
        string wrongHash = new('0', 64);

        (CoreManager client, Quic clientTransport) = await ConnectClientAsync(port, wrongHash);

        await DriveUntilAsync(server, client, () => clientTransport.ClientSocket.State is LocalConnectionState.Disconnected);

        Assert.False(IsClientAuthenticated(client));
        Assert.Empty(server.TransportManager.ActiveConnections);

        await clientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A client the server kicks has its link dropped, and the server's roster empties.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AKickedClient_IsDisconnected()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager server, Quic serverTransport) = await StartServerAsync(port);
        (CoreManager client, Quic clientTransport) = await ConnectClientAsync(port, serverTransport.ServerCertificateHash);

        await DriveUntilAsync(server, client, () => IsClientAuthenticated(client));

        Assert.Single(server.TransportManager.ActiveConnections).Kick();

        await DriveUntilAsync(server, client, () => clientTransport.ClientSocket.State is LocalConnectionState.Disconnected && server.TransportManager.ActiveConnections.Count == 0);

        await clientTransport.ShutdownAsync();
        await serverTransport.ShutdownAsync();
    }

    /// <summary>
    /// A host's own client, pointed at its own server on loopback, is paired inside the process and authenticates without a session.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task LiveWebTransport_AHostsOwnClient_IsPairedInProcess()
    {
        ushort port = ProbeFreeUdpPort();
        (CoreManager host, Quic hostTransport) = await StartServerAsync(port);

        hostTransport.RemoteHost = "127.0.0.1";
        Assert.Equal(ConnectionStateChangeResult.Success, await hostTransport.ConnectAsync(Invoker.Client));

        await DriveUntilAsync(host, host, () => IsClientAuthenticated(host));

        Connection ownClient = Assert.Single(host.TransportManager.ActiveConnections);
        Assert.True(hostTransport.IsOwnClientConnection(ownClient));

        await hostTransport.ShutdownAsync();
    }

    /// <summary>
    /// Starts a server on a port, with the certificate it makes for itself.
    /// </summary>
    /// <param name="port">The UDP port.</param>
    /// <returns>The server and its transport.</returns>
    private static async Task<(CoreManager, Quic)> StartServerAsync(ushort port)
    {
        (CoreManager server, Quic serverTransport) = await CreateServerAsync(port);

        Assert.Equal(ConnectionStateChangeResult.Success, await serverTransport.ConnectAsync(Invoker.Server));

        return (server, serverTransport);
    }

    /// <summary>
    /// Creates a server on a port without starting it, so a test can configure it first.
    /// </summary>
    /// <param name="port">The UDP port.</param>
    /// <returns>The server and its transport.</returns>
    private static async Task<(CoreManager, Quic)> CreateServerAsync(ushort port)
    {
        CoreManager server = CreateManager();
        Quic serverTransport = (Quic)await server.TransportManager.AddTransportAsync<Quic>();
        serverTransport.SetPort(port);

        return (server, serverTransport);
    }

    /// <summary>
    /// Starts a client connecting to a local server.
    /// </summary>
    /// <param name="port">The server's port.</param>
    /// <param name="certificateHash">The hash the client pins.</param>
    /// <param name="isPinnedCertificateValidityLimitEnabled">Whether the client refuses a pinned certificate valid for more than 14 days.</param>
    /// <returns>The client and its transport.</returns>
    private static async Task<(CoreManager, Quic)> ConnectClientAsync(ushort port, string certificateHash, bool isPinnedCertificateValidityLimitEnabled = false)
    {
        CoreManager client = CreateManager();
        Quic clientTransport = (Quic)await client.TransportManager.AddTransportAsync<Quic>();
        clientTransport.SetPort(port);
        clientTransport.RemoteHost = "127.0.0.1";
        clientTransport.CertificateHash = certificateHash;
        clientTransport.PinnedCertificateValidityLimitEnabled = isPinnedCertificateValidityLimitEnabled;

        Assert.Equal(ConnectionStateChangeResult.Success, await clientTransport.ConnectAsync(Invoker.Client));

        return (client, clientTransport);
    }

    /// <summary>
    /// Creates a CoreManager whose loop is driven by hand.
    /// </summary>
    /// <returns>The CoreManager.</returns>
    private static CoreManager CreateManager() => new(tickRate: 60, new ManualStepProvider());

    /// <summary>
    /// Drives both peers until a condition holds, or fails the test.
    /// </summary>
    /// <param name="server">The server CoreManager.</param>
    /// <param name="client">The client CoreManager, which may be the server's own for a host.</param>
    /// <param name="condition">The condition awaited, checked before every pass.</param>
    /// <param name="describeFailure">Describes what was reached instead, for the failure message, or <see langword="null"/> for none.</param>
    private static async Task DriveUntilAsync(CoreManager server, CoreManager client, Func<bool> condition, Func<string>? describeFailure = null)
    {
        for (int attempt = 0; attempt < MaximumDriveAttempts; attempt++)
        {
            if (condition())
                return;

            DriveFullTick(server);

            if (!ReferenceEquals(client, server))
                DriveFullTick(client);

            await Task.Delay(2);
        }

        Assert.True(condition(), $"The condition was not met within [{MaximumDriveAttempts}] passes. {describeFailure?.Invoke()}");
    }

    /// <summary>
    /// Drives one full tick, in the order the real loop runs its steps.
    /// </summary>
    /// <param name="coreManager">The CoreManager to drive.</param>
    private static void DriveFullTick(CoreManager coreManager)
    {
        NetworkLoopManager networkLoopManager = coreManager.NetworkLoopManager;
        StepDelta stepDelta = new(0, 0, 0);

        Assert.True(networkLoopManager.TryGetFirstNetworkLoopStepCallback(ManualStepProvider.LocatorStep, out ManualStepProvider manualStepProvider));
        manualStepProvider.IsTickFrame = true;

        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.EarlyVariableUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.EarlyStateUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.LateStateUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.Reconcile, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.EarlyFixedUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.LateFixedUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.VariableUpdate, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.EarlySerialize, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.LateSerialize, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.TickAdvance, stepDelta);
        networkLoopManager.InvokeNetworkLoopStep(NetworkLoopSteps.LateVariableUpdate, stepDelta);
    }

    /// <summary>
    /// Reads whether a client has authenticated and adopted the identifier its server assigned it.
    /// </summary>
    /// <param name="client">The client CoreManager.</param>
    /// <returns>True once the client holds an authenticated local Connection with an identifier.</returns>
    private static bool IsClientAuthenticated(CoreManager client) => client.TransportManager.TryGetLocalClientConnection(out Connection localClientConnection) && localClientConnection is { IsAuthenticated: true, IsIdUnset: false };

    /// <summary>
    /// Fills a payload with bytes that differ from one position to the next, so a misplaced byte shows.
    /// </summary>
    /// <param name="size">The payload size.</param>
    /// <returns>The payload.</returns>
    private static byte[] CreatePayload(int size)
    {
        byte[] payload = new byte[size];

        for (int i = 0; i < size; i++)
            payload[i] = (byte)(i * 31 + 7);

        return payload;
    }

    /// <summary>
    /// Asks the operating system for a free UDP port by binding one and reading back what it chose.
    /// </summary>
    /// <returns>A port that was free when it was probed.</returns>
    private static ushort ProbeFreeUdpPort()
    {
        using UdpClient probe = new(new IPEndPoint(IPAddress.Loopback, 0));

        return (ushort)((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }

    /// <summary>
    /// A loop step provider that runs nothing on its own, so the test drives every step.
    /// </summary>
    private sealed class ManualStepProvider : INetworkLoopStepProvider, INetworkLoopStepCallback
    {
        /// <inheritdoc/>
        public bool IsStarted { get; private set; }
        /// <inheritdoc/>
        public bool IsTickFrame { get; set; }
        /// <summary>
        /// The step this provider registers on so the test can find it through the loop.
        /// </summary>
        public const NetworkLoopSteps LocatorStep = NetworkLoopSteps.TickAdvance;
        /// <summary>
        /// The loop this provider was installed on.
        /// </summary>
        private NetworkLoopManager? _networkLoopManager;

        /// <inheritdoc/>
        public void Initialize(NetworkLoopManager networkLoopManager)
        {
            _networkLoopManager = networkLoopManager;
            networkLoopManager.RegisterNetworkLoopStepCallbacks(this);
        }

        /// <inheritdoc/>
        public void Start() => IsStarted = true;

        /// <inheritdoc/>
        public void Stop() => IsStarted = false;

        /// <inheritdoc/>
        public void Return()
        {
            _networkLoopManager?.UnregisterNetworkLoopStepCallbacks(this);
            _networkLoopManager = null;
        }

        /// <inheritdoc/>
        NetworkLoopSteps INetworkLoopStepCallback.GetNetworkLoopSteps() => LocatorStep;

        /// <inheritdoc/>
        void INetworkLoopStepCallback.OnNetworkLoopStep(NetworkLoopSteps networkLoopStep, StepDelta stepDelta) { }
    }

    /// <summary>
    /// Writes the engine's log lines to the test output.
    /// </summary>
    private sealed class TestOutputLogger : ILogger
    {
        /// <summary>
        /// The per-test output sink.
        /// </summary>
        private readonly ITestOutputHelper _testOutputHelper;

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="testOutputHelper">The per-test output sink.</param>
        public TestOutputLogger(ITestOutputHelper testOutputHelper) => _testOutputHelper = testOutputHelper;

        /// <inheritdoc/>
        public LoggerSetting GetLoggerSetting() => LoggerSetting.LoggerServiceSetting;

        /// <inheritdoc/>
        public bool DisableUnconditionalDevelopmentStacktrace() => true;

        /// <inheritdoc/>
        public void LogInformation(string message) => Write($"Information :: {message}");

        /// <inheritdoc/>
        public void LogWarning(string message) => Write($"Warning :: {message}");

        /// <inheritdoc/>
        public void LogError(string message) => Write($"Error :: {message}");

        /// <summary>
        /// Writes a line, which MsQuic's threads may also do after the test has finished.
        /// </summary>
        /// <param name="line">The line.</param>
        private void Write(string line)
        {
            try
            {
                _testOutputHelper.WriteLine(line);
            }
            catch (InvalidOperationException)
            {
                // The test this logger belonged to has ended.
            }
        }
    }
}

/// <summary>
/// A message the live tests send each way: a value, and a payload sized to fit a datagram or to span many.
/// </summary>
[NetworkType]
public struct ProbeMessage : IMessage
{
    /// <inheritdoc/>
    public bool IsAuthenticationRequired => true;

    /// <summary>
    /// The value sent, checked on arrival.
    /// </summary>
    public int Value;

    /// <summary>
    /// The payload sent, checked byte for byte on arrival.
    /// </summary>
    public ArraySegment<byte> Payload;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <param name="payload">The payload.</param>
    public ProbeMessage(int value, byte[] payload)
    {
        Value = value;
        Payload = payload;
    }
}
