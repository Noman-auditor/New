package com.nora.tunnel.core

import android.content.Context
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Runs the dnstt-client binary (packaged as lib/<abi>/libdnstt.so, built by CI) which listens on
 * 127.0.0.1:[SshEngine.DNSTT_PORT] and tunnels TCP through DNS to the dnstt server. The SSH
 * session then connects to that local port.
 *
 * extra keys: ns (tunnel domain, e.g. t.example.com), pubkey (hex), rmode (udp|doh|dot, default udp),
 *             resolver (udp/dot: host:port ; doh: https URL). Default: udp to the profile's address:port.
 * Use IP addresses for resolvers: the binary has no DNS of its own on Android.
 */
object DnsttRunner {
    private var proc: Process? = null

    fun start(ctx: Context, p: Profile, x: JSONObject) {
        stop()
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libdnstt.so")
        if (!bin.exists()) throw IllegalStateException("libdnstt.so not found (see NATIVE.md)")
        val ns = x.optString("ns")
        val key = x.optString("pubkey")
        if (ns.isBlank() || key.isBlank()) throw IllegalStateException("DNSTT needs ns= and pubkey=")
        val rmode = x.optString("rmode", "udp")
        val resolver = x.optString("resolver").ifBlank { "${p.address}:${p.port}" }
        val flag = when (rmode) { "doh" -> "-doh"; "dot" -> "-dot"; else -> "-udp" }

        val pb = ProcessBuilder(
            bin.absolutePath, flag, resolver, "-pubkey", key, ns, "127.0.0.1:${SshEngine.DNSTT_PORT}",
        ).redirectErrorStream(true)
        pb.environment()["SSL_CERT_DIR"] = "/system/etc/security/cacerts"   // Go has no CA store on Android
        val pr = pb.start()
        proc = pr
        Thread {
            try { pr.inputStream.bufferedReader().forEachLine { AppLog.add("INFO", "dnstt: $it") } } catch (_: Exception) {}
        }.start()

        repeat(40) {                       // wait up to ~4 s for the local listener
            if (!pr.isAlive) throw IllegalStateException("dnstt-client exited (code ${pr.exitValue()})")
            try { Socket().use { it.connect(InetSocketAddress("127.0.0.1", SshEngine.DNSTT_PORT), 200) }; return }
            catch (_: Exception) { Thread.sleep(100) }
        }
        throw IllegalStateException("dnstt-client did not start listening")
    }

    fun stop() {
        try { proc?.destroy() } catch (_: Exception) {}
        proc = null
    }
}
