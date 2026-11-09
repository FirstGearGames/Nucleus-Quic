using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// Makes the short-lived self-signed certificate a browser accepts by its hash: ECDSA on P-256, valid for less than two weeks, packed
    /// with its private key as PKCS #12 for MsQuic to load.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A browser only accepts a certificate no authority signed when the page names its SHA-256 in <c>serverCertificateHashes</c>, and
    /// only when it is ECDSA on P-256 and valid for two weeks at most. Unity's Mono has no ECDSA, so the curve arithmetic, the signature,
    /// the X.509 encoding and the PKCS #12 packing are all done here with nothing but <see cref="BigInteger"/> and SHA-256.
    /// </para>
    /// <para>
    /// The private key never leaves the process: it is packed unencrypted into the PKCS #12 bytes handed straight to MsQuic. The package
    /// carries an HMAC-SHA256 under an empty password, which both Windows and OpenSSL require to read it.
    /// </para>
    /// </remarks>
    internal static class SelfSignedCertificate
    {
        /// <summary>
        /// How long a made certificate is valid, inside the two weeks a browser allows.
        /// </summary>
        internal static readonly TimeSpan ValidityPeriod = TimeSpan.FromDays(13);
        /// <summary>
        /// The P-256 field prime.
        /// </summary>
        private static readonly BigInteger FieldPrime = ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        /// <summary>
        /// The P-256 group order.
        /// </summary>
        private static readonly BigInteger GroupOrder = ParseHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        /// <summary>
        /// The x coordinate of the P-256 base point.
        /// </summary>
        private static readonly BigInteger BasePointX = ParseHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        /// <summary>
        /// The y coordinate of the P-256 base point.
        /// </summary>
        private static readonly BigInteger BasePointY = ParseHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        /// <summary>
        /// The DER of <c>ecdsa-with-SHA256</c>.
        /// </summary>
        private const string EcdsaWithSha256Oid = "06082A8648CE3D040302";
        /// <summary>
        /// The DER of <c>id-ecPublicKey</c>.
        /// </summary>
        private const string EcPublicKeyOid = "06072A8648CE3D0201";
        /// <summary>
        /// The DER of <c>prime256v1</c>.
        /// </summary>
        private const string Prime256V1Oid = "06082A8648CE3D030107";
        /// <summary>
        /// The DER of <c>commonName</c>.
        /// </summary>
        private const string CommonNameOid = "0603550403";
        /// <summary>
        /// The DER of <c>subjectAltName</c>, which Chrome needs present before it reads a certificate it was given the hash of.
        /// </summary>
        private const string SubjectAltNameOid = "0603551D11";
        /// <summary>
        /// The DER of PKCS #7 <c>data</c>.
        /// </summary>
        private const string DataOid = "06092A864886F70D010701";
        /// <summary>
        /// The DER of the PKCS #12 <c>keyBag</c>.
        /// </summary>
        private const string KeyBagOid = "060B2A864886F70D010C0A0101";
        /// <summary>
        /// The DER of the PKCS #12 <c>certBag</c>.
        /// </summary>
        private const string CertificateBagOid = "060B2A864886F70D010C0A0103";
        /// <summary>
        /// The DER of PKCS #9 <c>x509Certificate</c>.
        /// </summary>
        private const string X509CertificateOid = "060A2A864886F70D01091601";
        /// <summary>
        /// The DER of PKCS #9 <c>localKeyId</c>, which ties the certificate to its key inside the package.
        /// </summary>
        private const string LocalKeyIdOid = "06092A864886F70D010915";
        /// <summary>
        /// The DER of <c>sha256</c>.
        /// </summary>
        private const string Sha256Oid = "0609608648016503040201";
        /// <summary>
        /// How many times the PKCS #12 MAC key derivation hashes.
        /// </summary>
        private const int MacIterationCount = 2048;

        /// <summary>
        /// Makes a certificate valid from a little before now for <see cref="ValidityPeriod"/>.
        /// </summary>
        /// <param name="commonName">The subject's common name.</param>
        /// <param name="certificateHash">The SHA-256 of the certificate, which a browser is given in <c>serverCertificateHashes</c>.</param>
        /// <returns>The certificate and its private key as PKCS #12 bytes with no password.</returns>
        /// <remarks>The start is an hour back, so a client whose clock runs a little behind still finds it valid.</remarks>
        internal static byte[] CreatePkcs12(string commonName, out byte[] certificateHash)
        {
            using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
            using SHA256 sha256 = SHA256.Create();

            BigInteger privateKey = CreateScalar(randomNumberGenerator);
            MultiplyBasePoint(privateKey, out BigInteger publicKeyX, out BigInteger publicKeyY);

            byte[] publicKey = Concatenate(new byte[] { 0x04 }, ToFixedBytes(publicKeyX), ToFixedBytes(publicKeyY));
            byte[] signatureAlgorithm = Sequence(Hex(EcdsaWithSha256Oid));
            byte[] name = Sequence(Set(Sequence(Hex(CommonNameOid), Element(0x0C, Encoding.UTF8.GetBytes(commonName)))));
            DateTime notBefore = DateTime.UtcNow.AddHours(-1);

            byte[] serialNumber = new byte[16];
            randomNumberGenerator.GetBytes(serialNumber);
            serialNumber[0] = (byte)(serialNumber[0] & 0x7F | 0x01);

            byte[] toBeSigned = Sequence(
                Element(0xA0, Element(0x02, new byte[] { 0x02 })),
                Element(0x02, serialNumber),
                signatureAlgorithm,
                name,
                Sequence(UtcTime(notBefore), UtcTime(notBefore + ValidityPeriod)),
                name,
                Sequence(Sequence(Hex(EcPublicKeyOid), Hex(Prime256V1Oid)), BitString(publicKey)),
                Element(0xA3, Sequence(Sequence(Hex(SubjectAltNameOid), Element(0x04, Sequence(Element(0x82, Encoding.ASCII.GetBytes(commonName))))))));

            Sign(sha256.ComputeHash(toBeSigned), privateKey, randomNumberGenerator, out BigInteger signatureR, out BigInteger signatureS);

            byte[] certificate = Sequence(toBeSigned, signatureAlgorithm, BitString(Sequence(Integer(signatureR), Integer(signatureS))));
            certificateHash = sha256.ComputeHash(certificate);

            byte[] ecPrivateKey = Sequence(Element(0x02, new byte[] { 0x01 }), Element(0x04, ToFixedBytes(privateKey)), Element(0xA1, BitString(publicKey)));
            byte[] privateKeyInfo = Sequence(Element(0x02, new byte[] { 0x00 }), Sequence(Hex(EcPublicKeyOid), Hex(Prime256V1Oid)), Element(0x04, ecPrivateKey));
            byte[] bagAttributes = Set(Sequence(Hex(LocalKeyIdOid), Set(Element(0x04, new byte[] { 0x01 }))));

            byte[] safeContents = Sequence(
                Sequence(Hex(CertificateBagOid), Element(0xA0, Sequence(Hex(X509CertificateOid), Element(0xA0, Element(0x04, certificate)))), bagAttributes),
                Sequence(Hex(KeyBagOid), Element(0xA0, privateKeyInfo), bagAttributes));

            byte[] authenticatedSafe = Sequence(Sequence(Hex(DataOid), Element(0xA0, Element(0x04, safeContents))));

            byte[] macSalt = new byte[8];
            randomNumberGenerator.GetBytes(macSalt);

            byte[] mac;

            using (HMACSHA256 hmacSha256 = new(DeriveMacKey(sha256, macSalt)))
                mac = hmacSha256.ComputeHash(authenticatedSafe);

            byte[] macData = Sequence(Sequence(Sequence(Hex(Sha256Oid), new byte[] { 0x05, 0x00 }), Element(0x04, mac)), Element(0x04, macSalt), Integer(MacIterationCount));

            return Sequence(Element(0x02, new byte[] { 0x03 }), Sequence(Hex(DataOid), Element(0xA0, Element(0x04, authenticatedSafe))), macData);
        }

        /// <summary>
        /// Formats a certificate hash the way a page or an inspector writes it: lowercase hex, two characters a byte.
        /// </summary>
        /// <param name="certificateHash">The hash.</param>
        /// <returns>The hex.</returns>
        internal static string ToHex(byte[] certificateHash)
        {
            StringBuilder hex = new(certificateHash.Length * 2);

            foreach (byte hashByte in certificateHash)
                hex.Append(hashByte.ToString("x2", CultureInfo.InvariantCulture));

            return hex.ToString();
        }

        /// <summary>
        /// Reads a certificate hash written as hex, with or without colons or spaces between the bytes.
        /// </summary>
        /// <param name="hex">The hex.</param>
        /// <param name="certificateHash">The hash read.</param>
        /// <returns>True when it was 32 bytes of hex.</returns>
        internal static bool TryParseHex(string hex, out byte[] certificateHash)
        {
            certificateHash = null;

            List<byte> hashBytes = new(32);
            int highNibble = -1;

            foreach (char character in hex)
            {
                if (character is ':' or ' ' or '-')
                    continue;

                int nibble = character >= '0' && character <= '9' ? character - '0' : character >= 'a' && character <= 'f' ? character - 'a' + 10 : character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1;

                if (nibble < 0)
                    return false;

                if (highNibble < 0)
                {
                    highNibble = nibble;

                    continue;
                }

                hashBytes.Add((byte)(highNibble << 4 | nibble));
                highNibble = -1;
            }

            if (highNibble >= 0 || hashBytes.Count != 32)
                return false;

            certificateHash = hashBytes.ToArray();

            return true;
        }

        /// <summary>
        /// Derives the PKCS #12 MAC key for an empty password, as RFC 7292 appendix B.2 sets out for SHA-256.
        /// </summary>
        /// <param name="sha256">The hash to derive with.</param>
        /// <param name="salt">The MAC salt.</param>
        /// <returns>The 32-byte HMAC key.</returns>
        /// <remarks>One hash block is the whole key, so only the first output block is computed. The empty password is the two-byte BMP terminator alone, repeated to the block size.</remarks>
        private static byte[] DeriveMacKey(SHA256 sha256, byte[] salt)
        {
            const int BlockSize = 64;
            const byte MacKeyId = 3;

            byte[] input = new byte[BlockSize * 3];

            for (int i = 0; i < BlockSize; i++)
            {
                input[i] = MacKeyId;
                input[BlockSize + i] = salt[i % salt.Length];
            }

            byte[] key = sha256.ComputeHash(input);

            for (int iteration = 1; iteration < MacIterationCount; iteration++)
                key = sha256.ComputeHash(key);

            return key;
        }

        /// <summary>
        /// Signs a digest with ECDSA.
        /// </summary>
        /// <param name="digest">The SHA-256 digest.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="randomNumberGenerator">The source of the per-signature secret.</param>
        /// <param name="signatureR">The first half of the signature.</param>
        /// <param name="signatureS">The second half of the signature.</param>
        private static void Sign(byte[] digest, BigInteger privateKey, RandomNumberGenerator randomNumberGenerator, out BigInteger signatureR, out BigInteger signatureS)
        {
            BigInteger digestValue = FromUnsignedBytes(digest);

            do
            {
                BigInteger nonce = CreateScalar(randomNumberGenerator);
                MultiplyBasePoint(nonce, out BigInteger pointX, out _);
                signatureR = pointX % GroupOrder;
                signatureS = BigInteger.ModPow(nonce, GroupOrder - 2, GroupOrder) * (digestValue + signatureR * privateKey) % GroupOrder;
            } while (signatureR.IsZero || signatureS.IsZero);
        }

        /// <summary>
        /// Draws a scalar uniformly from one to one less than the group order.
        /// </summary>
        /// <param name="randomNumberGenerator">The source of randomness.</param>
        /// <returns>The scalar.</returns>
        private static BigInteger CreateScalar(RandomNumberGenerator randomNumberGenerator)
        {
            byte[] scalarBytes = new byte[32];
            BigInteger scalar;

            do
            {
                randomNumberGenerator.GetBytes(scalarBytes);
                scalar = FromUnsignedBytes(scalarBytes);
            } while (scalar.IsZero || scalar >= GroupOrder);

            return scalar;
        }

        /// <summary>
        /// Multiplies the base point by a scalar, in Jacobian coordinates so only the final conversion inverts.
        /// </summary>
        /// <param name="scalar">The scalar.</param>
        /// <param name="x">The product's x coordinate.</param>
        /// <param name="y">The product's y coordinate.</param>
        private static void MultiplyBasePoint(BigInteger scalar, out BigInteger x, out BigInteger y)
        {
            BigInteger jacobianX = BigInteger.Zero;
            BigInteger jacobianY = BigInteger.One;
            BigInteger jacobianZ = BigInteger.Zero;

            for (int bit = 255; bit >= 0; bit--)
            {
                Double(ref jacobianX, ref jacobianY, ref jacobianZ);

                if (!(scalar >> bit).IsEven)
                    AddBasePoint(ref jacobianX, ref jacobianY, ref jacobianZ);
            }

            BigInteger inverseZ = BigInteger.ModPow(jacobianZ, FieldPrime - 2, FieldPrime);
            BigInteger inverseZSquared = inverseZ * inverseZ % FieldPrime;

            x = jacobianX * inverseZSquared % FieldPrime;
            y = jacobianY * inverseZSquared % FieldPrime * inverseZ % FieldPrime;
        }

        /// <summary>
        /// Doubles a point in Jacobian coordinates, using the curve's a of minus three.
        /// </summary>
        /// <param name="x">The x coordinate, replaced.</param>
        /// <param name="y">The y coordinate, replaced.</param>
        /// <param name="z">The z coordinate, replaced; zero is the point at infinity.</param>
        private static void Double(ref BigInteger x, ref BigInteger y, ref BigInteger z)
        {
            if (z.IsZero || y.IsZero)
            {
                z = BigInteger.Zero;

                return;
            }

            BigInteger delta = z * z % FieldPrime;
            BigInteger gamma = y * y % FieldPrime;
            BigInteger beta = x * gamma % FieldPrime;
            BigInteger alpha = 3 * Modulo(x - delta) * (x + delta) % FieldPrime;
            BigInteger doubledX = Modulo(alpha * alpha - 8 * beta);

            z = Modulo((y + z) * (y + z) - gamma - delta);
            y = Modulo(alpha * (4 * beta - doubledX) - 8 * gamma * gamma);
            x = doubledX;
        }

        /// <summary>
        /// Adds the base point to a point in Jacobian coordinates.
        /// </summary>
        /// <param name="x">The x coordinate, replaced.</param>
        /// <param name="y">The y coordinate, replaced.</param>
        /// <param name="z">The z coordinate, replaced; zero is the point at infinity.</param>
        private static void AddBasePoint(ref BigInteger x, ref BigInteger y, ref BigInteger z)
        {
            if (z.IsZero)
            {
                x = BasePointX;
                y = BasePointY;
                z = BigInteger.One;

                return;
            }

            BigInteger zSquared = z * z % FieldPrime;
            BigInteger scaledBaseX = BasePointX * zSquared % FieldPrime;
            BigInteger scaledBaseY = BasePointY * z % FieldPrime * zSquared % FieldPrime;
            BigInteger xDifference = Modulo(scaledBaseX - x);
            BigInteger yDifference = Modulo(scaledBaseY - y);

            if (xDifference.IsZero)
            {
                if (yDifference.IsZero)
                    Double(ref x, ref y, ref z);
                else
                    z = BigInteger.Zero;

                return;
            }

            BigInteger xDifferenceSquared = xDifference * xDifference % FieldPrime;
            BigInteger xDifferenceCubed = xDifference * xDifferenceSquared % FieldPrime;
            BigInteger scaledX = x * xDifferenceSquared % FieldPrime;
            BigInteger sumX = Modulo(yDifference * yDifference - xDifferenceCubed - 2 * scaledX);

            y = Modulo(yDifference * (scaledX - sumX) - y * xDifferenceCubed);
            z = z * xDifference % FieldPrime;
            x = sumX;
        }

        /// <summary>
        /// Reduces a value into the field, never negative.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>The value modulo the field prime.</returns>
        private static BigInteger Modulo(BigInteger value)
        {
            BigInteger remainder = value % FieldPrime;

            return remainder.Sign < 0 ? remainder + FieldPrime : remainder;
        }

        /// <summary>
        /// Reads a big-endian unsigned number.
        /// </summary>
        /// <param name="bigEndianBytes">The bytes.</param>
        /// <returns>The number.</returns>
        private static BigInteger FromUnsignedBytes(byte[] bigEndianBytes)
        {
            byte[] littleEndianBytes = new byte[bigEndianBytes.Length + 1];

            for (int i = 0; i < bigEndianBytes.Length; i++)
                littleEndianBytes[i] = bigEndianBytes[bigEndianBytes.Length - 1 - i];

            return new(littleEndianBytes);
        }

        /// <summary>
        /// Writes a field element or scalar as exactly 32 big-endian bytes.
        /// </summary>
        /// <param name="value">The value, below two to the 256.</param>
        /// <returns>The bytes.</returns>
        private static byte[] ToFixedBytes(BigInteger value)
        {
            byte[] littleEndianBytes = value.ToByteArray();
            byte[] bigEndianBytes = new byte[32];

            for (int i = 0; i < 32 && i < littleEndianBytes.Length; i++)
                bigEndianBytes[31 - i] = littleEndianBytes[i];

            return bigEndianBytes;
        }

        /// <summary>
        /// Parses a positive number written in hex.
        /// </summary>
        /// <param name="hex">The hex.</param>
        /// <returns>The number.</returns>
        private static BigInteger ParseHex(string hex) => BigInteger.Parse($"0{hex}", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

        /// <summary>
        /// Encodes a DER INTEGER from a non-negative number.
        /// </summary>
        /// <param name="value">The number.</param>
        /// <returns>The element.</returns>
        private static byte[] Integer(BigInteger value)
        {
            byte[] littleEndianBytes = value.ToByteArray();
            byte[] bigEndianBytes = new byte[littleEndianBytes.Length];

            for (int i = 0; i < littleEndianBytes.Length; i++)
                bigEndianBytes[i] = littleEndianBytes[littleEndianBytes.Length - 1 - i];

            return Element(0x02, bigEndianBytes);
        }

        /// <summary>
        /// Encodes a DER BIT STRING with no unused bits.
        /// </summary>
        /// <param name="content">The bits.</param>
        /// <returns>The element.</returns>
        private static byte[] BitString(byte[] content) => Element(0x03, Concatenate(new byte[] { 0x00 }, content));

        /// <summary>
        /// Encodes a DER UTCTime.
        /// </summary>
        /// <param name="time">The time, in UTC.</param>
        /// <returns>The element.</returns>
        private static byte[] UtcTime(DateTime time) => Element(0x17, Encoding.ASCII.GetBytes(time.ToString("yyMMddHHmmss'Z'", CultureInfo.InvariantCulture)));

        /// <summary>
        /// Encodes a DER SEQUENCE.
        /// </summary>
        /// <param name="elements">The encoded elements it holds.</param>
        /// <returns>The element.</returns>
        private static byte[] Sequence(params byte[][] elements) => Element(0x30, Concatenate(elements));

        /// <summary>
        /// Encodes a DER SET.
        /// </summary>
        /// <param name="elements">The encoded elements it holds, already in order.</param>
        /// <returns>The element.</returns>
        private static byte[] Set(params byte[][] elements) => Element(0x31, Concatenate(elements));

        /// <summary>
        /// Encodes one DER element.
        /// </summary>
        /// <param name="tag">The tag byte.</param>
        /// <param name="content">The content.</param>
        /// <returns>The tag, the length and the content.</returns>
        private static byte[] Element(byte tag, byte[] content)
        {
            byte[] length = content.Length < 0x80 ? new[] { (byte)content.Length } : content.Length <= 0xFF ? new byte[] { 0x81, (byte)content.Length } : new byte[] { 0x82, (byte)(content.Length >> 8), (byte)content.Length };

            return Concatenate(new[] { tag }, length, content);
        }

        /// <summary>
        /// Reads encoded bytes written in hex.
        /// </summary>
        /// <param name="hex">The hex, two characters a byte.</param>
        /// <returns>The bytes.</returns>
        private static byte[] Hex(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);

            return bytes;
        }

        /// <summary>
        /// Joins byte arrays end to end.
        /// </summary>
        /// <param name="parts">The arrays.</param>
        /// <returns>The joined bytes.</returns>
        private static byte[] Concatenate(params byte[][] parts)
        {
            int length = 0;

            foreach (byte[] part in parts)
                length += part.Length;

            byte[] joined = new byte[length];
            int offset = 0;

            foreach (byte[] part in parts)
            {
                Buffer.BlockCopy(part, 0, joined, offset, part.Length);
                offset += part.Length;
            }

            return joined;
        }
    }
}
