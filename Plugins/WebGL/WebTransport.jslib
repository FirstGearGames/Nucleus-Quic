// The browser half of the Nucleus WebTransport client. BrowserSession.cs calls these; everything the browser receives is queued here and
// taken on the engine's receive pass, because the browser cannot call into C# cheaply.
//
// Unreliable packets are WebTransport datagrams. Reliable packets travel on one two-way stream this side opens, each prefixed with its
// length as a QUIC variable-length integer, and the stream opens with an empty frame so the server hears of it at once.
var WebTransportLibrary = {
    $WebTransportSessions: { nextId: 1, byId: {} },

    WebTransportConnect: function (urlPointer, certificateHashPointer) {
        var url = UTF8ToString(urlPointer);
        var certificateHash = UTF8ToString(certificateHashPointer);
        var sessionId = WebTransportSessions.nextId++;
        // State is 0 while connecting, 1 once open and 2 once closed.
        var session = { state: 0, packets: [], transport: null, datagramWriter: null, streamWriter: null };
        var options = {};

        WebTransportSessions.byId[sessionId] = session;

        if (certificateHash.length === 64) {
            var hash = new Uint8Array(32);

            for (var i = 0; i < 32; i++)
                hash[i] = parseInt(certificateHash.substr(i * 2, 2), 16);

            options.serverCertificateHashes = [{ algorithm: 'sha-256', value: hash }];
        }

        function close(reason) {
            if (session.state !== 2 && reason)
                console.warn('[Nucleus WebTransport] The session to ' + url + ' closed: ' + reason);

            session.state = 2;
        }

        function readDatagrams(reader) {
            reader.read().then(function (result) {
                if (result.done)
                    return;

                session.packets.push({ isReliable: false, bytes: result.value });
                readDatagrams(reader);
            }, function () { });
        }

        function readStream(reader, unread) {
            reader.read().then(function (result) {
                if (result.done) {
                    close('the server ended the reliable stream');

                    return;
                }

                var joined = new Uint8Array(unread.length + result.value.length);

                joined.set(unread, 0);
                joined.set(result.value, unread.length);

                var offset = 0;

                while (offset < joined.length) {
                    var size = 1 << (joined[offset] >> 6);

                    if (joined.length - offset < size)
                        break;

                    var length = joined[offset] & 0x3f;

                    for (var i = 1; i < size; i++)
                        length = length * 256 + joined[offset + i];

                    if (joined.length - offset - size < length)
                        break;

                    if (length > 0)
                        session.packets.push({ isReliable: true, bytes: joined.slice(offset + size, offset + size + length) });

                    offset += size + length;
                }

                readStream(reader, joined.subarray(offset));
            }, function (error) { close(String(error)); });
        }

        try {
            session.transport = new WebTransport(url, options);
        } catch (error) {
            close(String(error));

            return sessionId;
        }

        var transport = session.transport;

        transport.closed.then(function () { close('the session was closed'); }, function (error) { close(String(error)); });
        transport.ready.then(function () {
            session.datagramWriter = transport.datagrams.writable.getWriter();
            readDatagrams(transport.datagrams.readable.getReader());

            return transport.createBidirectionalStream();
        }).then(function (stream) {
            session.streamWriter = stream.writable.getWriter();
            session.streamWriter.write(new Uint8Array([0]));
            readStream(stream.readable.getReader(), new Uint8Array(0));

            if (session.state === 0)
                session.state = 1;
        }).catch(function (error) { close(String(error)); });

        return sessionId;
    },

    WebTransportGetState: function (sessionId) {
        var session = WebTransportSessions.byId[sessionId];

        return session ? session.state : 2;
    },

    WebTransportPeekSize: function (sessionId) {
        var session = WebTransportSessions.byId[sessionId];

        return session && session.packets.length > 0 ? session.packets[0].bytes.length : -1;
    },

    WebTransportReceive: function (sessionId, bufferPointer, capacity) {
        var session = WebTransportSessions.byId[sessionId];
        var packet = session.packets.shift();

        HEAPU8.set(packet.bytes.subarray(0, capacity), bufferPointer);

        return packet.isReliable ? 1 : 0;
    },

    WebTransportSend: function (sessionId, bufferPointer, offset, length, isReliable) {
        var session = WebTransportSessions.byId[sessionId];

        if (!session || session.state !== 1)
            return 0;

        var start = bufferPointer + offset;

        if (!isReliable) {
            session.datagramWriter.write(HEAPU8.slice(start, start + length)).catch(function () { });

            return 1;
        }

        var size = length < 64 ? 1 : length < 16384 ? 2 : length < 1073741824 ? 4 : 8;
        var frame = new Uint8Array(size + length);
        var remaining = length;

        for (var i = size - 1; i >= 0; i--) {
            frame[i] = remaining % 256;
            remaining = Math.floor(remaining / 256);
        }

        frame[0] |= (size === 1 ? 0 : size === 2 ? 1 : size === 4 ? 2 : 3) << 6;
        frame.set(HEAPU8.subarray(start, start + length), size);
        session.streamWriter.write(frame).catch(function () { });

        return 1;
    },

    WebTransportClose: function (sessionId) {
        var session = WebTransportSessions.byId[sessionId];

        if (!session)
            return;

        delete WebTransportSessions.byId[sessionId];
        session.state = 2;

        try {
            if (session.transport)
                session.transport.close();
        } catch (error) { }
    }
};

autoAddDeps(WebTransportLibrary, '$WebTransportSessions');
mergeInto(LibraryManager.library, WebTransportLibrary);
