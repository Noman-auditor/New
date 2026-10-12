package com.nora.tunnel.core

import android.content.Context
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Proxy as JschProxy
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * SSH tunnel engine. Opens an SSH session (direct, TLS-wrapped, or after an HTTP "payload"),
 * then exposes a local SOCKS5 server on 127.0.0.1:[XrayConfig.SOCKS_PORT] that forwards every
 * CONNECT through SSH "direct-tcpip" channels. hev-socks5-tunnel feeds the TUN into that SOCKS.
 * UDP: only DNS (port 53) is supported, relayed as DNS-over-TCP through the SSH session.
 *
 * Profile: protocol "ssh", secret "user:password", address/port = SSH server.
 * extra: mode (direct|dnstt), tls (1/0), sni, allowInsecure, payload, proxy (host:port of an
 *        HTTP proxy / front to dial instead of the server), plus dnstt keys (see DnsttRunner).
 */
object SshEngine {
    const val DNSTT_PORT = 10809

    private var session: Session? = null
    private var server: ServerSocket? = null
    @Volatile private var running = false
    private var pool = Executors.newCachedThreadPool()
    private val timer: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()

    fun isAlive(): Boolean = running && session?.isConnected == true

    fun start(ctx: Context, p: Profile, serverIp: String) {
        stop()
        pool = Executors.newCachedThreadPool()
        val x = JSONObject(p.extra.ifBlank { "{}" })
        val user = p.secret.substringBefore(":")
        val pass = p.secret.substringAfter(":", "")
        if (user.isBlank()) throw IllegalStateException("SSH username is missing")

        var host = serverIp
        var port = p.port
        var hop: Pair<String, Int>? = null
        if (x.optString("mode") == "dnstt") {
            DnsttRunner.start(ctx, p, x)
            host = "127.0.0.1"; port = DNSTT_PORT
        } else if (x.optString("proxy").contains(":")) {
            hop = x.getString("proxy").substringBeforeLast(":") to x.getString("proxy").substringAfterLast(":").toInt()
        }

        val jsch = JSch()
        val s = jsch.getSession(user, host, port)
        s.setPassword(pass)
        s.setConfig("StrictHostKeyChecking", "no")
        s.setConfig("PreferredAuthentications", "password,keyboard-interactive")
        s.setServerAliveInterval(20_000)
        s.setServerAliveCountMax(3)
        val tls = x.optString("tls") in setOf("1", "true")
        val payload = x.optString("payload")
        if (tls || payload.isNotBlank() || hop != null) {
            s.setProxy(HopProxy(hop, tls, x.optString("sni").ifBlank { p.address },
                x.optString("allowInsecure") in setOf("1", "true"), payload, p.address, p.port))
        }
        s.connect(20_000)
        session = s

        val ss = ServerSocket(XrayConfig.SOCKS_PORT, 128, InetAddress.getByName("127.0.0.1"))
        server = ss
        running = true
        pool.execute {
            while (running) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                pool.execute { try { handle(c) } catch (_: Exception) { try { c.close() } catch (_: Exception) {} } }
            }
        }
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) {}
        server = null
        try { session?.disconnect() } catch (_: Exception) {}
        session = null
        try { pool.shutdownNow() } catch (_: Exception) {}
        DnsttRunner.stop()
    }

    // ---------------- transport (direct / TLS / payload / front proxy) ----------------

    private class HopProxy(
        val hop: Pair<String, Int>?, val tls: Boolean, val sni: String, val insecure: Boolean,
        val payload: String, val realHost: String, val realPort: Int,
    ) : JschProxy {
        private var sock: Socket? = null
        private var ins: InputStream? = null
        private var outs: OutputStream? = null

        override fun connect(sf: SocketFactory?, host: String, port: Int, timeout: Int) {
            val (h, p) = hop ?: (host to port)
            var s = Socket()
            s.connect(InetSocketAddress(h, p), timeout)
            s.tcpNoDelay = true
            if (tls) {
                val f: SSLSocketFactory = if (insecure) trustAll().socketFactory else SSLSocketFactory.getDefault() as SSLSocketFactory
                val ssl = f.createSocket(s, sni, p, true) as SSLSocket
                ssl.startHandshake()
                s = ssl
            }
            val i = s.getInputStream()
            val o = s.getOutputStream()
            if (payload.isNotBlank()) {
                o.write(expand(payload).toByteArray(Charsets.ISO_8859_1)); o.flush()
                s.soTimeout = timeout
                readHttpHeader(i)       // swallow the "HTTP/1.1 101/200 ..." answer; then the stream is raw SSH
                s.soTimeout = 0
            }
            sock = s; ins = i; outs = o
        }

        private fun expand(t: String) = t
            .replace("[crlf]", "\r\n").replace("[cr]", "\r").replace("[lf]", "\n")
            .replace("[host_port]", "$realHost:$realPort").replace("[host]", realHost)
            .replace("[port]", realPort.toString()).replace("[split]", "")
            .replace("\\r", "\r").replace("\\n", "\n")

        private fun readHttpHeader(i: InputStream) {
            val sb = StringBuilder()
            while (!sb.endsWith("\r\n\r\n") && !sb.endsWith("\n\n")) {
                val b = i.read()
                if (b < 0) throw IllegalStateException("Connection closed during payload handshake")
                sb.append(b.toChar())
                if (sb.length > 16_384) throw IllegalStateException("Payload response too large")
            }
            val code = sb.lineSequence().firstOrNull().orEmpty().split(" ").getOrNull(1)?.toIntOrNull()
            if (code != null && code !in 100..299) throw IllegalStateException("Payload rejected: ${sb.lineSequence().first()}")
        }

        override fun getInputStream() = ins
        override fun getOutputStream() = outs
        override fun getSocket() = sock
        override fun close() { try { sock?.close() } catch (_: Exception) {} }

        private fun trustAll(): SSLContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }), SecureRandom())
        }
    }

    // ---------------- local SOCKS5 server ----------------

    private fun handle(c: Socket) {
        c.tcpNoDelay = true
        val i = DataInputStream(c.getInputStream())
        val o = c.getOutputStream()
        if (i.readUnsignedByte() != 5) { c.close(); return }
        i.readFully(ByteArray(i.readUnsignedByte()))
        o.write(byteArrayOf(5, 0)); o.flush()
        i.readUnsignedByte()                       // VER
        val cmd = i.readUnsignedByte()
        i.readUnsignedByte()                       // RSV
        val host = when (i.readUnsignedByte()) {
            1 -> ByteArray(4).also { i.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress!! }
            4 -> ByteArray(16).also { i.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress!! }
            3 -> ByteArray(i.readUnsignedByte()).also { i.readFully(it) }.toString(Charsets.UTF_8)
            else -> { reply(o, 8); c.close(); return }
        }
        val port = i.readUnsignedShort()
        when (cmd) {
            1 -> connect(c, i, o, host, port)
            3 -> udpAssociate(c, i, o)
            else -> { reply(o, 7); c.close() }
        }
    }

    private fun reply(o: OutputStream, code: Int, port: Int = 0) {
        o.write(byteArrayOf(5, code.toByte(), 0, 1, 127, 0, 0, 1, (port shr 8).toByte(), port.toByte())); o.flush()
    }

    private fun openChannel(host: String, port: Int): Triple<ChannelDirectTCPIP, InputStream, OutputStream> {
        val s = session ?: throw IllegalStateException("SSH session closed")
        val ch = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
        ch.setHost(host); ch.setPort(port)
        val cin = ch.inputStream
        val cout = ch.outputStream
        ch.connect(10_000)
        return Triple(ch, cin, cout)
    }

    private fun connect(c: Socket, ci: InputStream, co: OutputStream, host: String, port: Int) {
        val (ch, rin, rout) = try { openChannel(host, port) } catch (_: Exception) { reply(co, 5); c.close(); return }
        reply(co, 0)
        val up = pool.submit { copy(ci, rout); try { ch.disconnect() } catch (_: Exception) {} }
        copy(rin, co)
        try { c.close() } catch (_: Exception) {}
        try { ch.disconnect() } catch (_: Exception) {}
        up.cancel(true)
    }

    private fun copy(a: InputStream, b: OutputStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = a.read(buf)
                if (n < 0) break
                b.write(buf, 0, n); b.flush()
            }
        } catch (_: Exception) {}
    }

    /** UDP ASSOCIATE: only DNS (port 53) is forwarded, as DNS-over-TCP through SSH. */
    private fun udpAssociate(c: Socket, ci: DataInputStream, co: OutputStream) {
        val u = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        reply(co, 0, u.localPort)
        pool.execute {
            val buf = ByteArray(4096)
            while (!u.isClosed) {
                val pk = DatagramPacket(buf, buf.size)
                try { u.receive(pk) } catch (_: Exception) { break }
                val d = pk.data.copyOfRange(pk.offset, pk.offset + pk.length)
                val client = InetSocketAddress(pk.address, pk.port)
                pool.execute { try { relayDns(u, client, d) } catch (_: Exception) {} }
            }
        }
        try { while (ci.read() >= 0) { /* wait for control connection to close */ } } catch (_: Exception) {}
        u.close(); c.close()
    }

    private fun relayDns(u: DatagramSocket, client: InetSocketAddress, d: ByteArray) {
        if (d.size < 10 || d[2].toInt() != 0) return            // FRAG must be 0 (RSV(2) FRAG(1) ATYP(1) ...)
        val hdr = when (d[3].toInt() and 0xFF) {
            1 -> 4 + 4 + 2; 4 -> 4 + 16 + 2; else -> return
        }
        val addr = if (d[3].toInt() == 1) d.copyOfRange(4, 8) else d.copyOfRange(4, 20)
        val port = ((d[hdr - 2].toInt() and 0xFF) shl 8) or (d[hdr - 1].toInt() and 0xFF)
        if (port != 53) return
        val q = d.copyOfRange(hdr, d.size)
        val (ch, rin, rout) = openChannel(InetAddress.getByAddress(addr).hostAddress!!, 53)
        val guard = timer.schedule({ try { ch.disconnect() } catch (_: Exception) {} }, 8, TimeUnit.SECONDS)
        try {
            rout.write(byteArrayOf((q.size shr 8).toByte(), q.size.toByte()) + q); rout.flush()
            val di = DataInputStream(rin)
            val len = di.readUnsignedShort()
            val ans = ByteArray(len); di.readFully(ans)
            val out = d.copyOfRange(0, hdr) + ans
            u.send(DatagramPacket(out, out.size, client))
        } finally { guard.cancel(false); try { ch.disconnect() } catch (_: Exception) {} }
    }
}
