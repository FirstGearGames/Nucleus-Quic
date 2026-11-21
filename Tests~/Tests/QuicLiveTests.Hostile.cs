using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Nucleus.Connections;
using Nucleus.Managers.Core;
using Nucleus.Managers.Messages;
using Nucleus.Transports;
using Xunit;

namespace Nucleus.Integrations.Unity.Transports.Tests;

public partial class QuicLiveTests
{
    /// <summary>
    /// How long a test waits on something MsQuic does on its own threads before it fails.
    /// </summary>
    private static readonly TimeSpan BackgroundWaitTimeout = TimeSpan.FromSeconds(10);

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
