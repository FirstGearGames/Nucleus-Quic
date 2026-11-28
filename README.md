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
| Linux | Install MsQuic 2.5.13 or newer from packages.microsoft.com (`sudo apt install libmsquic`); older builds lack security fixes. If only `libmsquic.so.2` is installed, add a `libmsquic.so` link beside it. Not yet tested. |
| macOS | None. MsQuic has no supported macOS build, so a Mac player can only connect from a browser. |

## Install

This folder is a Unity package (`com.firstgeargames.nucleus.quic`). Either:

- In the Package Manager, choose **Install package from git URL** and enter `https://github.com/FirstGearGames/Nucleus-Quic.git`. Add `#v1.0.0` to the end to pin a release.
- Or, in the Package Manager, choose **Install package from disk** and pick this folder's `package.json`, or add `"com.firstgeargames.nucleus.quic": "file:<path to this folder>"` to `Packages/manifest.json`.
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
| Pinned Certificate Validity Limit Enabled | off | Client only. Refuses a pinned certificate that is valid for more than 14 days in total, as a browser does. See [Certificates](#certificates). |
| Maximum Connections | 0 | Server only. The most clients the server accepts at once. 0 accepts any number. Connections past twice this, counting those still opening, are refused at their handshake. |
| Maximum Transmission Unit | 1000 | The largest packet built before it is split. Firefox silently drops a datagram larger than 1024 bytes, so raise it only when no player connects from Firefox. |
| Maximum Reliable Packet Size | 1048576 | Server only. The largest reliable packet, in bytes, a client may send. A client that sends a larger one is disconnected. |
| Allowed Origins | empty | Server only. The web pages a browser may connect from, such as `https://game.example.com`. Empty accepts every page. Native clients are always accepted. See [Allowed origins](#allowed-origins). |
| Connecting Timeout Seconds | 10 | How long a client waits for the server to answer, and how long the server gives a new connection to open its session before closing it. 0 uses the idle timeout. |
| Idle Timeout Seconds | 15 | How long either side waits without hearing from the other before dropping the link. |

`QuicTransport.RemoteHost`, `Port` and `CertificateHash` can be set from code before the client starts. On the server, `QuicTransport.ServerCertificateHash` holds the hash of the certificate it is using.

## Certificates

A browser only connects to a server whose certificate it trusts. There are two ways to give it one.

**A certificate the server makes itself.** Leave **Certificate Path** empty. The server makes a new certificate every time it starts and logs its hash. Give that hash to every client as **Certificate Hash**, through whatever your game uses to find servers. A browser accepts a certificate like this for 14 days at most, so the server makes it valid for 13. A server that runs longer must be restarted or given a real certificate. This is how to develop locally, because no authority signs a certificate for `127.0.0.1`.

**A certificate from a public authority.** Put the certificate and its private key in a `.pfx` file, set **Certificate Path** and **Certificate Password** on the server, and point clients at the domain the certificate names. Clients leave **Certificate Hash** empty.

**Holding native clients to the browser's limit.** A browser refuses a pinned certificate that is valid for more than 14 days in total. Native clients accept a longer one by default, so a game that only ships native builds can pin a long-lived certificate file and keep the same hash. Turn on **Pinned Certificate Validity Limit Enabled** on clients when the game also ships a WebGL build, so a certificate a browser would refuse is refused on every platform. A certificate the server makes itself is valid for 13 days, so it passes either way.

## Allowed origins

A browser tells the server which web page opened each connection, and the page cannot change what the browser says. Without a list, any website's page can connect to your server through the browsers of the people visiting it.

To accept only your own pages, add each one to **Allowed Origins** on the server, written the way a browser names a page: the scheme, the host, and the port when it is not the scheme's default. For example, `https://game.example.com`, or `http://localhost:8080` for a build you test locally. Letter case does not matter. Leave out any path, such as `/play`. A browser on any other page sees its connection fail. Leave the list empty to accept every page, which is the default.

Native clients do not name a page, so they connect whatever the list holds. The list stops other websites, not other programs, which can claim to be any page they like, so it does not replace authentication.

## Things that look like bugs but are not

- **The server's certificate hash changes every restart.** A certificate the server makes itself is new each time. Use a certificate file when clients need a hash that stays the same.
- **On Windows, a key is written to the user's key store as the server starts.** Windows' TLS runs in a system process that can only load a stored key. The server deletes it again as soon as that process has loaded it.
- **A browser client drops at once when its tab closes.** A browser cannot wait for its last packets to be acknowledged. A server kick does wait, so the kick reason arrives.
- **Browsers cannot connect while desktop clients can.** When the server lists **Allowed Origins**, the page must be listed exactly as the browser names it, with its port when that is not the default. The server does not log these refusals, so a page that keeps trying cannot fill the log.

## Tests

`Tests~` is ignored by Unity. It holds a .NET build of this folder, compiled the way Unity compiles it, and live tests that connect real Nucleus servers and clients over QUIC on loopback. They run on Windows. Run them in Release, pointing at the folder holding the `Nucleus.dll` your Unity project uses:

```bash
dotnet test "Tests~/Tests" -c Release -p:NucleusAssembliesDirectory="<your project>/Assets/Nucleus"
```

## License

MIT. See [LICENSE](LICENSE). `msquic.dll` is Microsoft's MsQuic 2.5.13, also under the MIT license; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
