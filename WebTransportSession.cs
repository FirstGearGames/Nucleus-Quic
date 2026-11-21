using System;
using Nucleus.Connections;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// One WebTransport session: a server's link to one client, or a client's link to its server.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unreliable packets travel as WebTransport datagrams. Reliable packets travel on one two-way WebTransport stream that the client
    /// opens, each prefixed with its length, so they arrive whole and in order whatever their size.
    /// </para>
    /// <para>
    /// A session reports what happens to it through the <see cref="WebTransportEvents"/> its socket drains, from whichever thread learns
    /// of it, so the socket applies every change on the network loop thread.
    /// </para>
    /// </remarks>
    internal abstract class WebTransportSession
    {
        /// <summary>
        /// The Connection a server registered this session's client as, or <see langword="null"/> before it was admitted and after it
        /// left.
        /// </summary>
        /// <remarks>Read and written on the network loop thread only.</remarks>
        internal Connection NucleusConnection;
        /// <summary>
        /// The address the peer connected from, as this side observed it, or <see langword="null"/> when there is none to observe.
        /// </summary>
        internal string RemoteAddress;
        /// <summary>
        /// Why the session closed, as the underlying library reported it, for the log line a failed connect writes.
        /// </summary>
        /// <remarks>Written before the close is queued and read after it is drained, so the queue orders the two.</remarks>
        internal string CloseReason = string.Empty;
        /// <summary>
        /// How many of this session's packets the <see cref="WebTransportEvents"/> hold that the network loop has not yet taken.
        /// </summary>
        /// <remarks>Changed only under the lock of the events that hold them.</remarks>
        internal int QueuedPacketCount;

        /// <summary>
        /// Sends a packet.
        /// </summary>
        /// <param name="channel">The channel the engine chose: a datagram when unreliable, the reliable stream otherwise.</param>
        /// <param name="payload">The packet, copied before this returns.</param>
        /// <returns>True when the packet was handed on; false when the session is not open or the packet cannot be sent.</returns>
        internal abstract bool TrySend(Channel channel, ArraySegment<byte> payload);

        /// <summary>
        /// Brings in whatever the session has received since the last pass, for a session nothing reports from on its own.
        /// </summary>
        /// <remarks>Called on the network loop thread before the events are drained. MsQuic reports from its own threads, so the base does nothing; the browser is asked here.</remarks>
        internal virtual void Poll() { }

        /// <summary>
        /// Closes the session, telling the peer.
        /// </summary>
        /// <param name="isAfterDelivery">True to deliver the reliable data already sent before the session closes.</param>
        /// <remarks>Idempotent. The close is reported through the events once it has happened.</remarks>
        internal abstract void Close(bool isAfterDelivery);
    }
}
