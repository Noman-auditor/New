# Native components (not bundled)

The app compiles without these, but **Connect will fail with a clear error until both are added.**

## 1. Xray core (AAR)
Put a gomobile build of Xray (e.g. the AndroidLibXrayLite project's `libv2ray.aar`) into `app/libs/`.
`core/XrayEngine.kt` calls it by reflection and expects `libv2ray.Libv2ray.newCoreController(handler)`
and `CoreController.startLoop(config, fd)` / `stopLoop()`. If your AAR exposes a different API,
adjust only `XrayEngine.kt`. Xray-core is MPL-2.0.

## 2. hev-socks5-tunnel (.so)
Build `libhev-socks5-tunnel.so` from the heiher/hev-socks5-tunnel project with the Android NDK and
place each ABI under `app/src/main/jniLibs/<abi>/` (arm64-v8a, armeabi-v7a, x86_64, x86).
The Kotlin binding is `hev/htproxy/TProxyService.kt`; its package and class name must not change.
hev-socks5-tunnel is MIT licensed.

## Not implemented
WireGuard profiles (the parser accepts none yet and XrayConfig rejects the protocol), per-app routing,
split-tunnel and custom rules (only Default and Bypass LAN are applied).

## SSH / DNSTT / OpenVPN (added later)

- **SSH** (direct, TLS/SNI, HTTP payload, front proxy): pure Kotlin via JSch (`com.github.mwiede:jsch`). No native files.
- **DNSTT**: needs `libdnstt.so` per ABI in `app/src/main/jniLibs/<abi>/` (static Go build of dnstt-client).
  The GitHub Actions workflow builds it. Use IP addresses for DoH/DoT resolvers.
- **OpenVPN**: imported `.ovpn` files are handed to the "OpenVPN for Android" app (de.blinkt.openvpn).
- Link formats: see `LinkParser.kt` (`ssh://`, `socks://`, `http-proxy://`).
