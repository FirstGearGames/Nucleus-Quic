using System;
using System.Text;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// The HTTP/3 and WebTransport framing this transport speaks: QUIC variable-length integers, the SETTINGS a WebTransport endpoint
    /// announces, the extended CONNECT that opens a session and the response that accepts it, and the header that names a WebTransport
    /// stream.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only what one session per connection needs is spoken. Header blocks are QPACK with the static table alone, which the SETTINGS
    /// advertise by leaving the dynamic table at its default size of zero, so a peer may only refer to static entries or send literals.
    /// Literals this side writes are never Huffman coded, and literals a peer writes are skipped rather than decoded: the only facts read
    /// from a header block are the method of a request and the status of a response, which every browser sends as static entries.
    /// </para>
    /// <para>
    /// Draft 02 of WebTransport over HTTP/3, which Chrome and Firefox speak, and drafts 07 onwards, which Safari speaks, are both offered.
    /// Their datagrams and stream headers are identical, and a session this transport serves never pools, so nothing more differs.
    /// </para>
    /// </remarks>
    internal static class Http3
    {
        /// <summary>
        /// The ALPN token every HTTP/3 connection negotiates.
        /// </summary>
        internal const string ApplicationProtocol = "h3";
        /// <summary>
        /// The signal that opens a two-way WebTransport stream, followed by the session it belongs to.
        /// </summary>
        internal const ulong BidirectionalStreamSignal = 0x41;
        /// <summary>
        /// The largest value a variable-length integer can carry.
        /// </summary>
        internal const ulong MaximumVariableLengthInteger = (1UL << 62) - 1;
        /// <summary>
        /// The most bytes a variable-length integer takes.
        /// </summary>
        internal const int MaximumVariableLengthIntegerSize = 8;
        /// <summary>
        /// The HEADERS frame type.
        /// </summary>
        private const ulong HeadersFrameType = 0x01;
        /// <summary>
        /// The SETTINGS frame type.
        /// </summary>
        private const ulong SettingsFrameType = 0x04;
        /// <summary>
        /// The control stream type.
        /// </summary>
        private const ulong ControlStreamType = 0x00;
        /// <summary>
        /// Allows the extended CONNECT a WebTransport session is opened with.
        /// </summary>
        private const ulong EnableConnectProtocolSetting = 0x08;
        /// <summary>
        /// Allows HTTP datagrams.
        /// </summary>
        private const ulong H3DatagramSetting = 0x33;
        /// <summary>
        /// Allows HTTP datagrams under the identifier the drafts used before it was assigned.
        /// </summary>
        private const ulong DraftH3DatagramSetting = 0xffd277;
        /// <summary>
        /// Offers WebTransport draft 02.
        /// </summary>
        private const ulong EnableWebTransportDraft02Setting = 0x2b603742;
        /// <summary>
        /// Offers WebTransport drafts 07 onwards, by the most sessions one connection may carry.
        /// </summary>
        private const ulong WebTransportMaximumSessionsSetting = 0xc671706a;
        /// <summary>
        /// The QPACK static table entry for <c>:method CONNECT</c>.
        /// </summary>
        private const int MethodConnectStaticIndex = 15;
        /// <summary>
        /// The first QPACK static table entry named <c>:method</c>.
        /// </summary>
        private const int FirstMethodStaticIndex = 15;
        /// <summary>
        /// The last QPACK static table entry named <c>:method</c>.
        /// </summary>
        private const int LastMethodStaticIndex = 21;
        /// <summary>
        /// The QPACK static table entry for <c>:scheme https</c>.
        /// </summary>
        private const int SchemeHttpsStaticIndex = 23;
        /// <summary>
        /// The QPACK static table entry for <c>:status 200</c>.
        /// </summary>
        private const int StatusOkStaticIndex = 25;
        /// <summary>
        /// The first QPACK static table entry named <c>:status</c>.
        /// </summary>
        private const int FirstStatusStaticIndex = 24;
        /// <summary>
        /// The last QPACK static table entry named <c>:status</c> in the block that starts at <see cref="FirstStatusStaticIndex"/>.
        /// </summary>
        private const int LastStatusStaticIndex = 28;
        /// <summary>
        /// The QPACK static table entry named <c>:authority</c>.
        /// </summary>
        private const int AuthorityStaticIndex = 0;
        /// <summary>
        /// The QPACK static table entry named <c>:path</c>.
        /// </summary>
        private const int PathStaticIndex = 1;

        /// <summary>
        /// Returns how many bytes a value takes as a variable-length integer.
        /// </summary>
        /// <param name="value">The value, no larger than <see cref="MaximumVariableLengthInteger"/>.</param>
        /// <returns>One, two, four or eight.</returns>
        internal static int GetVariableLengthIntegerSize(ulong value) => value < 1UL << 6 ? 1 : value < 1UL << 14 ? 2 : value < 1UL << 30 ? 4 : 8;

        /// <summary>
        /// Writes a variable-length integer.
        /// </summary>
        /// <param name="destination">The buffer written to, with room for <see cref="GetVariableLengthIntegerSize"/> bytes.</param>
        /// <param name="value">The value, no larger than <see cref="MaximumVariableLengthInteger"/>.</param>
        /// <returns>How many bytes were written.</returns>
        internal static unsafe int WriteVariableLengthInteger(byte* destination, ulong value)
        {
            int size = GetVariableLengthIntegerSize(value);
            ulong lengthBits = size switch { 1 => 0UL, 2 => 1UL, 4 => 2UL, _ => 3UL };
            ulong encoded = value | lengthBits << (size * 8 - 2);

            for (int i = 0; i < size; i++)
                destination[i] = (byte)(encoded >> ((size - 1 - i) * 8));

            return size;
        }

        /// <summary>
        /// Writes a variable-length integer into an array.
        /// </summary>
        /// <param name="destination">The array written to.</param>
        /// <param name="offset">Where the integer starts, moved past it.</param>
        /// <param name="value">The value, no larger than <see cref="MaximumVariableLengthInteger"/>.</param>
        internal static unsafe void WriteVariableLengthInteger(byte[] destination, ref int offset, ulong value)
        {
            fixed (byte* destinationPointer = &destination[offset])
                offset += WriteVariableLengthInteger(destinationPointer, value);
        }

        /// <summary>
        /// Reads a variable-length integer.
        /// </summary>
        /// <param name="source">The bytes read from.</param>
        /// <param name="offset">Where the integer starts, moved past it when it is read.</param>
        /// <param name="end">Where the readable bytes end.</param>
        /// <param name="value">The value read.</param>
        /// <returns>True when the whole integer was there to read.</returns>
        internal static bool TryReadVariableLengthInteger(byte[] source, ref int offset, int end, out ulong value)
        {
            value = 0;

            if (offset >= end)
                return false;

            int size = 1 << (source[offset] >> 6);

            if (end - offset < size)
                return false;

            value = source[offset] & 0x3FUL;

            for (int i = 1; i < size; i++)
                value = value << 8 | source[offset + i];

            offset += size;

            return true;
        }

        /// <summary>
        /// Reads a variable-length integer from native memory.
        /// </summary>
        /// <param name="source">The bytes read from.</param>
        /// <param name="length">How many bytes may be read.</param>
        /// <param name="value">The value read.</param>
        /// <returns>How many bytes the integer took, or zero when it was cut short.</returns>
        internal static unsafe int ReadVariableLengthInteger(byte* source, int length, out ulong value)
        {
            value = 0;

            if (length < 1)
                return 0;

            int size = 1 << (source[0] >> 6);

            if (length < size)
                return 0;

            value = source[0] & 0x3FUL;

            for (int i = 1; i < size; i++)
                value = value << 8 | source[i];

            return size;
        }

        /// <summary>
        /// Creates what opens this endpoint's control stream: the stream type and the SETTINGS that announce WebTransport.
        /// </summary>
        /// <returns>The bytes to send as the stream's first and only write.</returns>
        internal static byte[] CreateControlStream()
        {
            byte[] settings = new byte[64];
            int settingsLength = 0;

            WriteSetting(settings, ref settingsLength, EnableConnectProtocolSetting);
            WriteSetting(settings, ref settingsLength, H3DatagramSetting);
            WriteSetting(settings, ref settingsLength, DraftH3DatagramSetting);
            WriteSetting(settings, ref settingsLength, EnableWebTransportDraft02Setting);
            WriteSetting(settings, ref settingsLength, WebTransportMaximumSessionsSetting);

            byte[] controlStream = new byte[1 + 1 + MaximumVariableLengthIntegerSize + settingsLength];
            int offset = 0;

            WriteVariableLengthInteger(controlStream, ref offset, ControlStreamType);
            WriteVariableLengthInteger(controlStream, ref offset, SettingsFrameType);
            WriteVariableLengthInteger(controlStream, ref offset, (ulong)settingsLength);
            Buffer.BlockCopy(settings, 0, controlStream, offset, settingsLength);

            return Trim(controlStream, offset + settingsLength);
        }

        /// <summary>
        /// Creates the extended CONNECT request that opens a WebTransport session.
        /// </summary>
        /// <param name="authority">The host and port being connected to, such as <c>play.example.com:7777</c>.</param>
        /// <returns>The HEADERS frame.</returns>
        internal static byte[] CreateConnectRequest(string authority)
        {
            byte[] authorityBytes = Encoding.ASCII.GetBytes(authority);
            byte[] fieldSection = new byte[128 + authorityBytes.Length];
            int length = 0;

            // The required insert count and the delta base, both zero because nothing refers to the dynamic table.
            fieldSection[length++] = 0x00;
            fieldSection[length++] = 0x00;
            fieldSection[length++] = (byte)(0xC0 | MethodConnectStaticIndex);
            fieldSection[length++] = (byte)(0xC0 | SchemeHttpsStaticIndex);
            WriteLiteralWithStaticName(fieldSection, ref length, AuthorityStaticIndex, authorityBytes);
            WriteLiteralWithStaticName(fieldSection, ref length, PathStaticIndex, Encoding.ASCII.GetBytes("/"));
            WriteLiteral(fieldSection, ref length, ":protocol", "webtransport");
            WriteLiteral(fieldSection, ref length, "sec-webtransport-http3-draft02", "1");

            return CreateHeadersFrame(fieldSection, length);
        }

        /// <summary>
        /// Creates the response that accepts a WebTransport session.
        /// </summary>
        /// <returns>The HEADERS frame.</returns>
        /// <remarks>The draft header is what a draft 02 client waits for; a later draft ignores it.</remarks>
        internal static byte[] CreateConnectResponse()
        {
            byte[] fieldSection = new byte[64];
            int length = 0;

            fieldSection[length++] = 0x00;
            fieldSection[length++] = 0x00;
            fieldSection[length++] = (byte)(0xC0 | StatusOkStaticIndex);
            WriteLiteral(fieldSection, ref length, "sec-webtransport-http3-draft", "draft02");

            return CreateHeadersFrame(fieldSection, length);
        }

        /// <summary>
        /// Creates what opens a two-way WebTransport stream: the signal, the session, and one empty frame so the peer hears of the stream
        /// before anything else is sent on it.
        /// </summary>
        /// <param name="sessionId">The session, which is the identifier of the stream its CONNECT was sent on.</param>
        /// <returns>The bytes to start the stream with.</returns>
        internal static byte[] CreateBidirectionalStreamHeader(long sessionId)
        {
            byte[] header = new byte[MaximumVariableLengthIntegerSize * 2 + 1];
            int offset = 0;

            WriteVariableLengthInteger(header, ref offset, BidirectionalStreamSignal);
            WriteVariableLengthInteger(header, ref offset, (ulong)sessionId);
            header[offset++] = 0x00;

            return Trim(header, offset);
        }

        /// <summary>
        /// Reads the HEADERS frame a request or response stream opens with, skipping any other frame in front of it.
        /// </summary>
        /// <param name="source">The bytes received on the stream.</param>
        /// <param name="offset">Where reading starts, moved past every frame read.</param>
        /// <param name="end">Where the received bytes end.</param>
        /// <param name="fieldSectionOffset">Where the frame's field section starts.</param>
        /// <param name="fieldSectionEnd">Where the frame's field section ends.</param>
        /// <returns>True when a whole HEADERS frame was read; false when more bytes are needed.</returns>
        internal static bool TryReadHeadersFrame(byte[] source, ref int offset, int end, out int fieldSectionOffset, out int fieldSectionEnd)
        {
            fieldSectionOffset = 0;
            fieldSectionEnd = 0;

            while (true)
            {
                int frameOffset = offset;

                if (!TryReadVariableLengthInteger(source, ref frameOffset, end, out ulong frameType) || !TryReadVariableLengthInteger(source, ref frameOffset, end, out ulong frameLength))
                    return false;

                if ((ulong)(end - frameOffset) < frameLength)
                    return false;

                offset = frameOffset + (int)frameLength;

                if (frameType != HeadersFrameType)
                    continue;

                fieldSectionOffset = frameOffset;
                fieldSectionEnd = offset;

                return true;
            }
        }

        /// <summary>
        /// Returns whether a request's field section asks for <c>:method CONNECT</c>.
        /// </summary>
        /// <param name="source">The bytes holding the field section.</param>
        /// <param name="offset">Where the field section starts.</param>
        /// <param name="end">Where it ends.</param>
        /// <returns>True for a CONNECT request.</returns>
        internal static bool IsConnectRequest(byte[] source, int offset, int end) => HasField(source, offset, end, MethodConnectStaticIndex, FirstMethodStaticIndex, LastMethodStaticIndex, "CONNECT");

        /// <summary>
        /// Returns whether a response's field section carries <c>:status 200</c>.
        /// </summary>
        /// <param name="source">The bytes holding the field section.</param>
        /// <param name="offset">Where the field section starts.</param>
        /// <param name="end">Where it ends.</param>
        /// <returns>True for a response accepting the session.</returns>
        internal static bool IsOkResponse(byte[] source, int offset, int end) => HasField(source, offset, end, StatusOkStaticIndex, FirstStatusStaticIndex, LastStatusStaticIndex, "200");

        /// <summary>
        /// Writes one setting with the value one.
        /// </summary>
        /// <param name="destination">The SETTINGS payload being built.</param>
        /// <param name="offset">Where the setting starts, moved past it.</param>
        /// <param name="settingId">The setting.</param>
        private static void WriteSetting(byte[] destination, ref int offset, ulong settingId)
        {
            WriteVariableLengthInteger(destination, ref offset, settingId);
            WriteVariableLengthInteger(destination, ref offset, 1);
        }

        /// <summary>
        /// Wraps a field section in a HEADERS frame.
        /// </summary>
        /// <param name="fieldSection">The field section.</param>
        /// <param name="length">How many bytes of it are used.</param>
        /// <returns>The frame.</returns>
        private static byte[] CreateHeadersFrame(byte[] fieldSection, int length)
        {
            byte[] frame = new byte[1 + MaximumVariableLengthIntegerSize + length];
            int offset = 0;

            WriteVariableLengthInteger(frame, ref offset, HeadersFrameType);
            WriteVariableLengthInteger(frame, ref offset, (ulong)length);
            Buffer.BlockCopy(fieldSection, 0, frame, offset, length);

            return Trim(frame, offset + length);
        }

        /// <summary>
        /// Writes a field line whose name is a static table entry and whose value is a plain literal.
        /// </summary>
        /// <param name="destination">The field section being built.</param>
        /// <param name="offset">Where the line starts, moved past it.</param>
        /// <param name="nameIndex">The static table entry the name is taken from.</param>
        /// <param name="value">The value.</param>
        private static void WriteLiteralWithStaticName(byte[] destination, ref int offset, int nameIndex, byte[] value)
        {
            WritePrefixedInteger(destination, ref offset, 0x50, prefixBits: 4, (ulong)nameIndex);
            WritePrefixedInteger(destination, ref offset, 0x00, prefixBits: 7, (ulong)value.Length);
            Buffer.BlockCopy(value, 0, destination, offset, value.Length);
            offset += value.Length;
        }

        /// <summary>
        /// Writes a field line whose name and value are both plain literals.
        /// </summary>
        /// <param name="destination">The field section being built.</param>
        /// <param name="offset">Where the line starts, moved past it.</param>
        /// <param name="name">The name, in lower case.</param>
        /// <param name="value">The value.</param>
        private static void WriteLiteral(byte[] destination, ref int offset, string name, string value)
        {
            WritePrefixedInteger(destination, ref offset, 0x20, prefixBits: 3, (ulong)name.Length);
            offset += Encoding.ASCII.GetBytes(name, 0, name.Length, destination, offset);
            WritePrefixedInteger(destination, ref offset, 0x00, prefixBits: 7, (ulong)value.Length);
            offset += Encoding.ASCII.GetBytes(value, 0, value.Length, destination, offset);
        }

        /// <summary>
        /// Writes an HPACK-style integer with an N-bit prefix.
        /// </summary>
        /// <param name="destination">The buffer written to.</param>
        /// <param name="offset">Where the integer starts, moved past it.</param>
        /// <param name="firstByteFlags">The bits above the prefix in the first byte.</param>
        /// <param name="prefixBits">How many low bits of the first byte the integer starts in.</param>
        /// <param name="value">The value.</param>
        private static void WritePrefixedInteger(byte[] destination, ref int offset, byte firstByteFlags, int prefixBits, ulong value)
        {
            ulong prefixMaximum = (1UL << prefixBits) - 1;

            if (value < prefixMaximum)
            {
                destination[offset++] = (byte)(firstByteFlags | (byte)value);

                return;
            }

            destination[offset++] = (byte)(firstByteFlags | (byte)prefixMaximum);
            value -= prefixMaximum;

            while (value >= 0x80)
            {
                destination[offset++] = (byte)(value & 0x7F | 0x80);
                value >>= 7;
            }

            destination[offset++] = (byte)value;
        }

        /// <summary>
        /// Reads an HPACK-style integer with an N-bit prefix.
        /// </summary>
        /// <param name="source">The bytes read from.</param>
        /// <param name="offset">Where the integer starts, moved past it.</param>
        /// <param name="end">Where the readable bytes end.</param>
        /// <param name="prefixBits">How many low bits of the first byte the integer starts in.</param>
        /// <param name="value">The value read.</param>
        /// <returns>True when the whole integer was there to read.</returns>
        private static bool TryReadPrefixedInteger(byte[] source, ref int offset, int end, int prefixBits, out ulong value)
        {
            value = 0;

            if (offset >= end)
                return false;

            ulong prefixMaximum = (1UL << prefixBits) - 1;
            value = source[offset++] & prefixMaximum;

            if (value < prefixMaximum)
                return true;

            for (int shift = 0; offset < end && shift <= 56; shift += 7)
            {
                byte next = source[offset++];
                value += (ulong)(next & 0x7F) << shift;

                if ((next & 0x80) == 0)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Skips a string literal whose length has a 7-bit prefix, reporting where its bytes are and whether they are Huffman coded.
        /// </summary>
        /// <param name="source">The bytes read from.</param>
        /// <param name="offset">Where the literal starts, moved past it.</param>
        /// <param name="end">Where the readable bytes end.</param>
        /// <param name="valueOffset">Where the literal's bytes start.</param>
        /// <param name="valueLength">How many bytes the literal holds.</param>
        /// <param name="isHuffmanCoded">Whether the bytes are Huffman coded.</param>
        /// <returns>True when the whole literal was there.</returns>
        private static bool TrySkipStringLiteral(byte[] source, ref int offset, int end, out int valueOffset, out int valueLength, out bool isHuffmanCoded)
        {
            valueOffset = 0;
            valueLength = 0;
            isHuffmanCoded = offset < end && (source[offset] & 0x80) != 0;

            if (!TryReadPrefixedInteger(source, ref offset, end, prefixBits: 7, out ulong length) || (ulong)(end - offset) < length)
                return false;

            valueOffset = offset;
            valueLength = (int)length;
            offset += valueLength;

            return true;
        }

        /// <summary>
        /// Returns whether a field section holds a field, either as a whole static entry or as a static name with a plain literal value.
        /// </summary>
        /// <param name="source">The bytes holding the field section.</param>
        /// <param name="offset">Where the field section starts.</param>
        /// <param name="end">Where it ends.</param>
        /// <param name="staticIndex">The static entry that is the whole field.</param>
        /// <param name="firstNameIndex">The first static entry with the field's name.</param>
        /// <param name="lastNameIndex">The last static entry with the field's name.</param>
        /// <param name="value">The field's value.</param>
        /// <returns>True when the field is there.</returns>
        /// <remarks>A field section that refers to the dynamic table is refused, because this endpoint advertised none.</remarks>
        private static bool HasField(byte[] source, int offset, int end, int staticIndex, int firstNameIndex, int lastNameIndex, string value)
        {
            if (!TryReadPrefixedInteger(source, ref offset, end, prefixBits: 8, out ulong requiredInsertCount) || requiredInsertCount != 0 || !TryReadPrefixedInteger(source, ref offset, end, prefixBits: 7, out _))
                return false;

            while (offset < end)
            {
                byte first = source[offset];

                // An indexed field line: 1, static, then a 6-bit index.
                if ((first & 0x80) != 0)
                {
                    bool isStatic = (first & 0x40) != 0;

                    if (!TryReadPrefixedInteger(source, ref offset, end, prefixBits: 6, out ulong index))
                        return false;

                    if (isStatic && index == (ulong)staticIndex)
                        return true;

                    continue;
                }

                // A literal field line with a name reference: 01, never-indexed, static, then a 4-bit index.
                if ((first & 0x40) != 0)
                {
                    bool isStatic = (first & 0x10) != 0;

                    if (!TryReadPrefixedInteger(source, ref offset, end, prefixBits: 4, out ulong nameIndex) || !TrySkipStringLiteral(source, ref offset, end, out int valueOffset, out int valueLength, out bool isHuffmanCoded))
                        return false;

                    if (isStatic && nameIndex >= (ulong)firstNameIndex && nameIndex <= (ulong)lastNameIndex && !isHuffmanCoded && IsAscii(source, valueOffset, valueLength, value))
                        return true;

                    continue;
                }

                // A literal field line with a literal name: 001, never-indexed, Huffman, then a 3-bit name length.
                if ((first & 0x20) != 0)
                {
                    if (!TryReadPrefixedInteger(source, ref offset, end, prefixBits: 3, out ulong nameLength) || (ulong)(end - offset) < nameLength)
                        return false;

                    offset += (int)nameLength;

                    if (!TrySkipStringLiteral(source, ref offset, end, out _, out _, out _))
                        return false;

                    continue;
                }

                // Both remaining forms refer to the dynamic table, which this endpoint advertised none of.
                return false;
            }

            return false;
        }

        /// <summary>
        /// Returns whether a run of bytes spells an ASCII string exactly.
        /// </summary>
        /// <param name="source">The bytes.</param>
        /// <param name="offset">Where the run starts.</param>
        /// <param name="length">How long the run is.</param>
        /// <param name="value">The string.</param>
        /// <returns>True when they match.</returns>
        private static bool IsAscii(byte[] source, int offset, int length, string value)
        {
            if (length != value.Length)
                return false;

            for (int i = 0; i < length; i++)
            {
                if (source[offset + i] != value[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Copies the used part of a buffer into an array of exactly that length.
        /// </summary>
        /// <param name="source">The buffer.</param>
        /// <param name="length">How many bytes of it are used.</param>
        /// <returns>The trimmed copy.</returns>
        private static byte[] Trim(byte[] source, int length)
        {
            byte[] trimmed = new byte[length];
            Buffer.BlockCopy(source, 0, trimmed, 0, length);

            return trimmed;
        }
    }
}
