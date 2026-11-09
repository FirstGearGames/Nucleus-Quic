# Nucleus Quic

**A WebTransport transport for Nucleus, so a WebGL build can join the same server as every desktop build.** WebTransport runs over QUIC, which is UDP, and it is the only UDP connection a web browser can open. Unreliable packets stay unreliable, and reliable packets arrive whole and in order whatever their size.

## Requirements

- Unity 6.5 or newer, with Nucleus already in the project. This assembly references `Nucleus.dll` and `CodeBoost.dll`, which Nucleus installs in `Assets/Nucleus`, and the `Nucleus.Integrations.Unity` assembly.
- A server that is not a browser. A browser cannot accept connections, so a WebGL build is always a client and never hosts, including through host migration. Run the server as a dedicated server or from a desktop build.

Where each build gets its QUIC library:

| Platform | QUIC library |
|---|---|
| Windows, Editor and builds | `Plugins/Windows/x86_64/msquic.dll`, which ships in this package. |
| WebGL | The browser's own WebTransport, through `Plugins/WebGL/WebTransport.jslib`. Chrome, Edge and Firefox support it. |
| Linux | Install MsQuic from packages.microsoft.com (`sudo apt install libmsquic`). If only `libmsquic.so.2` is installed, add a `libmsquic.so` link beside it. Not yet tested. |
| macOS | None. MsQuic has no supported macOS build, so a Mac player can only connect from a browser. |

## Install

This folder is a Unity package (`com.firstgeargames.nucleus.quic`). Either:

- In the Package Manager, choose **Install package from disk** and pick this folder's `package.json`, or add `"com.firstgeargames.nucleus.quic": "file:<path to this folder>"` to `Packages/manifest.json`.
- Or copy the folder into your project's `Packages` or `Assets` folder.

## Quick start

1. Add a **Quic Transport** component to the GameObject holding your `UnityCoreManager`. Make it the only `NetworkTransport` there and on its children.
2. Start the server. It makes its own certificate and logs the hash clients need:
   ```
   The WebTransport server made its own certificate, valid for 13 days. Clients connect with certificate hash [98aa83df...].
   ```
3. On each client, set **Remote Host** to the server's address and **Certificate Hash** to the logged hash, then start the client.

A host's own client, pointed at this machine on the server's port, joins its server inside the process and never touches the network.

## Settings

| Setting | Default | What it does |
|---|---|---|
| Port | 7777 | The UDP port the server listens on and clients connect to. |
| Remote Host | 127.0.0.1 | The host name or IP address a client connects to, without a port. |
| Bind Address | empty | The local address the server listens on. Empty listens on every interface. |
| Certificate Path | empty | Server only. A PKCS #12 (`.pfx`) file holding the certificate and its private key. Empty makes a new certificate on every start. |
| Certificate Password | empty | Server only. The password protecting the certificate file. |
| Certificate Hash | empty | Client only. The SHA-256 of the server's certificate as 64 hex characters. Empty trusts only certificates the system or browser already trusts. |
| Maximum Connections | 0 | Server only. The most clients the server accepts at once. 0 accepts any number. |
| Maximum Transmission Unit | 1200 | The largest packet built before it is split. Keep it at 1200 unless every network path is known to carry more. |
| Maximum Reliable Packet Size | 1048576 | Server only. The largest reliable packet, in bytes, a client may send. A client that sends a larger one is disconnected. |
| Connecting Timeout Seconds | 10 | How long a client waits for the server to answer. 0 uses the idle timeout. |
| Idle Timeout Seconds | 15 | How long either side waits without hearing from the other before dropping the link. |

`QuicTransport.RemoteHost`, `Port` and `CertificateHash` can be set from code before the client starts. On the server, `QuicTransport.ServerCertificateHash` holds the hash of the certificate it is using.

## Certificates

A browser only connects to a server whose certificate it trusts. There are two ways to give it one.

**A certificate the server makes itself.** Leave **Certificate Path** empty. The server makes a new certificate every time it starts and logs its hash. Give that hash to every client as **Certificate Hash**, through whatever your game uses to find servers. A browser accepts a certificate like this for 14 days at most, so the server makes it valid for 13. A server that runs longer must be restarted or given a real certificate. This is how to develop locally, because no authority signs a certificate for `127.0.0.1`.

**A certificate from a public authority.** Put the certificate and its private key in a `.pfx` file, set **Certificate Path** and **Certificate Password** on the server, and point clients at the domain the certificate names. Clients leave **Certificate Hash** empty.

## Things that look like bugs but are not

- **The server's certificate hash changes every restart.** A certificate the server makes itself is new each time. Use a certificate file when clients need a hash that stays the same.
- **On Windows, a key appears in the user's key store while the server runs.** Windows' TLS runs in a system process that can only use a stored key. The server deletes it when it stops.
- **A browser client drops at once when its tab closes.** A browser cannot wait for its last packets to be acknowledged. A server kick does wait, so the kick reason arrives.

## Tests

`Tests~` is ignored by Unity. It holds a .NET build of this folder, compiled the way Unity compiles it, and live tests that connect real Nucleus servers and clients over QUIC on loopback. They run on Windows. Run them in Release, pointing at the folder holding the `Nucleus.dll` your Unity project uses:

```bash
dotnet test "Tests~/Tests" -c Release -p:NucleusAssembliesDirectory="<your project>/Assets/Nucleus"
```

## License

MIT. See [LICENSE](LICENSE). `msquic.dll` is Microsoft's MsQuic 2.4.8, also under the MIT license; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
