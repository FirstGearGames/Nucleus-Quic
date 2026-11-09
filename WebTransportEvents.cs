using System;
using System.Collections.Generic;
using CodeBoost.Performance;
using Nucleus.Transports;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// The sessions opening, the packets arriving and the sessions closing for one socket, queued from whichever thread learned of them and
    /// drained on the network loop thread.
    /// </summary>
    /// <remarks>
    /// MsQuic reports everything on its own worker threads, so the queue is locked. It is a plain Queue behind a lock rather than a
    /// ConcurrentQueue, which allocates a new segment every few dozen enqueues.
    /// </remarks>
    internal sealed class WebTransportEvents
    {
        /// <summary>
        /// Guards <see cref="_queuedEvents"/>.
        /// </summary>
        private readonly object _lock = new();
        /// <summary>
        /// The events not yet drained, oldest first.
        /// </summary>
        private readonly Queue<WebTransportEvent> _queuedEvents = new();

        /// <summary>
        /// Queues a session having opened.
        /// </summary>
        /// <param name="session">The session.</param>
        internal void EnqueueOpened(WebTransportSession session) => Enqueue(new(WebTransportEventType.Opened, session, default, Channel.Unreliable));

        /// <summary>
        /// Queues a packet having arrived.
        /// </summary>
        /// <param name="session">The session it arrived on.</param>
        /// <param name="payload">The packet, over an array rented from <see cref="TrackedArrayPool{T0}"/> which the queue now owns.</param>
        /// <param name="channel">The channel it arrived on.</param>
        internal void EnqueueReceived(WebTransportSession session, ArraySegment<byte> payload, Channel channel) => Enqueue(new(WebTransportEventType.Received, session, payload, channel));

        /// <summary>
        /// Queues a session having closed.
        /// </summary>
        /// <param name="session">The session.</param>
        internal void EnqueueClosed(WebTransportSession session) => Enqueue(new(WebTransportEventType.Closed, session, default, Channel.Unreliable));

        /// <summary>
        /// Takes the oldest event.
        /// </summary>
        /// <param name="webTransportEvent">The event taken.</param>
        /// <returns>True when there was one.</returns>
        internal bool TryDequeue(out WebTransportEvent webTransportEvent)
        {
            lock (_lock)
                return _queuedEvents.TryDequeue(out webTransportEvent);
        }

        /// <summary>
        /// Drops every queued event, handing each packet's array back.
        /// </summary>
        internal void Clear()
        {
            while (TryDequeue(out WebTransportEvent webTransportEvent))
            {
                if (webTransportEvent.Payload.Array is not null)
                    TrackedArrayPool<byte>.Return(webTransportEvent.Payload.Array);
            }
        }

        /// <summary>
        /// Queues an event.
        /// </summary>
        /// <param name="webTransportEvent">The event.</param>
        private void Enqueue(in WebTransportEvent webTransportEvent)
        {
            lock (_lock)
                _queuedEvents.Enqueue(webTransportEvent);
        }
    }

    /// <summary>
    /// What happened to a session.
    /// </summary>
    internal enum WebTransportEventType : byte
    {
        /// <summary>
        /// The session has opened and can carry packets both ways.
        /// </summary>
        Opened = 0,
        /// <summary>
        /// A packet has arrived.
        /// </summary>
        Received = 1,
        /// <summary>
        /// The session has closed, by either side or by a timeout.
        /// </summary>
        Closed = 2,
    }

    /// <summary>
    /// One queued event.
    /// </summary>
    internal readonly struct WebTransportEvent
    {
        /// <summary>
        /// What happened.
        /// </summary>
        public readonly WebTransportEventType Type;
        /// <summary>
        /// The session it happened to.
        /// </summary>
        public readonly WebTransportSession Session;
        /// <summary>
        /// The packet that arrived, over an array rented from <see cref="TrackedArrayPool{T0}"/>, for <see cref="WebTransportEventType.Received"/>.
        /// </summary>
        public readonly ArraySegment<byte> Payload;
        /// <summary>
        /// The channel the packet arrived on, for <see cref="WebTransportEventType.Received"/>.
        /// </summary>
        public readonly Channel Channel;

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="type">What happened.</param>
        /// <param name="session">The session it happened to.</param>
        /// <param name="payload">The packet that arrived, or default.</param>
        /// <param name="channel">The channel the packet arrived on.</param>
        public WebTransportEvent(WebTransportEventType type, WebTransportSession session, ArraySegment<byte> payload, Channel channel)
        {
            Type = type;
            Session = session;
            Payload = payload;
            Channel = channel;
        }
    }
}
