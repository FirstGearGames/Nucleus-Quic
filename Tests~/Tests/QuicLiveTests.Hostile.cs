using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Reflection;
using System.Runtime.Versioning;
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
    /// Opens a bare QUIC connection to a local server, offering HTTP/3 and doing nothing more, for a test to play a hostile client.
    /// </summary>
    /// <param name="port">The server's port.</param>
    /// <returns>The connection, its handshake complete.</returns>
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
    /// Reads what a server's MsQuic threads have queued for its next receive pass, without taking any of it.
    /// </summary>
    /// <param name="serverTransport">The server's transport.</param>
    /// <returns>Each queued event's type name and channel, oldest first.</returns>
    /// <remarks>Read under the queue's own lock, so a MsQuic thread queuing at the same moment cannot tear the walk.</remarks>
    private static List<(string Type, Channel Channel)> ReadQueuedServerEvents(Quic serverTransport)
    {
        const BindingFlags InstanceFieldFlags = BindingFlags.Instance | BindingFlags.NonPublic;

        object events = typeof(QuicServerSocket).GetField("_events", InstanceFieldFlags)!.GetValue(serverTransport.ServerSocket)!;
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
