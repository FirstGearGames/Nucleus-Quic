#if !UNITY_WEBGL || UNITY_EDITOR
using System;
using System.Runtime.InteropServices;
using CodeBoost.Logging;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// A certificate and its private key imported from PKCS #12 bytes into a Windows certificate context, which is the form the Schannel
    /// build of MsQuic takes a server certificate in.
    /// </summary>
    /// <remarks>
    /// The Schannel build cannot read PKCS #12 itself, unlike the OpenSSL build every other platform uses. Schannel signs in the system's
    /// security process, which cannot reach a key held only in this one, so the key is written to the user's key store under a fresh name
    /// and deleted again when the listener stops, as .NET does for a certificate it imports. A process killed before then leaves that one
    /// key file behind.
    /// </remarks>
    internal sealed class WindowsCertificate
    {
        /// <summary>
        /// The certificate context MsQuic is handed.
        /// </summary>
        internal IntPtr CertificateContext { get; private set; }
        /// <summary>
        /// The in-memory store the import created, which owns the key the context refers to.
        /// </summary>
        private IntPtr _certificateStore;
        /// <summary>
        /// Imports the key through CNG, which ECDSA keys need.
        /// </summary>
        private const uint AlwaysCngKspFlag = 0x200;
        /// <summary>
        /// Asks for the certificate's key as a CNG handle only.
        /// </summary>
        private const uint AcquireOnlyNCryptKeyFlag = 0x40000;
        /// <summary>
        /// Asks for the certificate's key without any prompt.
        /// </summary>
        private const uint AcquireSilentFlag = 0x40;
        /// <summary>
        /// The library the certificate calls live in.
        /// </summary>
        private const string Crypt32 = "crypt32.dll";
        /// <summary>
        /// The library the CNG key calls live in.
        /// </summary>
        private const string NCrypt = "ncrypt.dll";

        /// <summary>
        /// Creates an instance over an imported store and the certificate taken from it.
        /// </summary>
        /// <param name="certificateStore">The store.</param>
        /// <param name="certificateContext">The certificate.</param>
        private WindowsCertificate(IntPtr certificateStore, IntPtr certificateContext)
        {
            _certificateStore = certificateStore;
            CertificateContext = certificateContext;
        }

        /// <summary>
        /// Deletes the key from the user's key store and releases the certificate and its store.
        /// </summary>
        internal void Release()
        {
            if (CertificateContext != IntPtr.Zero)
            {
                // Deleting the key also frees its handle; a handle the context only lends is left alone.
                if (CryptAcquireCertificatePrivateKey(CertificateContext, AcquireOnlyNCryptKeyFlag | AcquireSilentFlag, IntPtr.Zero, out IntPtr keyHandle, out _, out bool isKeyHandleOwned) && isKeyHandleOwned)
                    NCryptDeleteKey(keyHandle, 0);

                CertFreeCertificateContext(CertificateContext);
            }

            if (_certificateStore != IntPtr.Zero)
                CertCloseStore(_certificateStore, 0);

            CertificateContext = IntPtr.Zero;
            _certificateStore = IntPtr.Zero;
        }

        /// <summary>
        /// Imports PKCS #12 bytes and takes the first certificate with its key.
        /// </summary>
        /// <param name="pkcs12">The PKCS #12 bytes.</param>
        /// <param name="password">The password protecting them, or empty for none.</param>
        /// <param name="windowsCertificate">The imported certificate, or <see langword="null"/> when the import failed.</param>
        /// <returns>True when the import succeeded.</returns>
        internal static unsafe bool TryImport(byte[] pkcs12, string password, out WindowsCertificate windowsCertificate)
        {
            windowsCertificate = null;

            IntPtr certificateStore;

            fixed (byte* pkcs12Pointer = pkcs12)
            {
                CryptDataBlob cryptDataBlob = new() { Length = (uint)pkcs12.Length, Data = pkcs12Pointer };

                certificateStore = PFXImportCertStore(ref cryptDataBlob, password ?? string.Empty, AlwaysCngKspFlag);
            }

            if (certificateStore == IntPtr.Zero)
            {
                Logger<WindowsCertificate>.LogError($"Windows could not import the server certificate: error [{Marshal.GetLastWin32Error()}]. The password may be wrong.");

                return false;
            }

            IntPtr enumeratedCertificateContext = CertEnumCertificatesInStore(certificateStore, IntPtr.Zero);

            if (enumeratedCertificateContext == IntPtr.Zero)
            {
                Logger<WindowsCertificate>.LogError("The server certificate file holds no certificate.");
                CertCloseStore(certificateStore, 0);

                return false;
            }

            // Duplicated so the context outlives the enumeration it came from; the enumeration's own reference is let go of with it.
            IntPtr certificateContext = CertDuplicateCertificateContext(enumeratedCertificateContext);
            CertFreeCertificateContext(enumeratedCertificateContext);

            windowsCertificate = new(certificateStore, certificateContext);

            return true;
        }

        /// <summary>
        /// Imports PKCS #12 bytes into an in-memory store.
        /// </summary>
        [DllImport(Crypt32, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr PFXImportCertStore(ref CryptDataBlob pfx, string password, uint flags);

        /// <summary>
        /// Takes the next certificate from a store.
        /// </summary>
        [DllImport(Crypt32)]
        private static extern IntPtr CertEnumCertificatesInStore(IntPtr certificateStore, IntPtr previousCertificateContext);

        /// <summary>
        /// Adds a reference to a certificate context.
        /// </summary>
        [DllImport(Crypt32)]
        private static extern IntPtr CertDuplicateCertificateContext(IntPtr certificateContext);

        /// <summary>
        /// Releases a reference to a certificate context.
        /// </summary>
        [DllImport(Crypt32)]
        private static extern bool CertFreeCertificateContext(IntPtr certificateContext);

        /// <summary>
        /// Closes a store.
        /// </summary>
        [DllImport(Crypt32)]
        private static extern bool CertCloseStore(IntPtr certificateStore, uint flags);

        /// <summary>
        /// Opens the key a certificate context refers to.
        /// </summary>
        [DllImport(Crypt32)]
        private static extern bool CryptAcquireCertificatePrivateKey(IntPtr certificateContext, uint flags, IntPtr parameters, out IntPtr keyHandle, out uint keySpec, out bool isKeyHandleOwned);

        /// <summary>
        /// Deletes a CNG key from its store and frees its handle.
        /// </summary>
        [DllImport(NCrypt)]
        private static extern int NCryptDeleteKey(IntPtr keyHandle, uint flags);

        /// <summary>
        /// <c>CRYPT_DATA_BLOB</c>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct CryptDataBlob
        {
            /// <summary>
            /// The number of bytes.
            /// </summary>
            public uint Length;
            /// <summary>
            /// The bytes.
            /// </summary>
            public byte* Data;
        }
    }
}
#endif
