package com.nora.tunnel.core

import android.net.Uri
import android.util.Base64
import com.nora.tunnel.data.Profile
import org.json.JSONObject

object LinkParser {

    fun parse(link: String): Profile? = try {
        val l = link.trim()
        when {
            l.startsWith("vless://") -> parseUriStyle(l, "vless")
            l.startsWith("trojan://") -> parseUriStyle(l, "trojan")
            l.startsWith("vmess://") -> parseVmess(l)
            l.startsWith("ss://") -> parseSs(l)
            l.startsWith("ssh://") -> parseSsh(l)
            l.startsWith("socks://") || l.startsWith("socks5://") -> parseProxy(l, "socks", 1080)
            l.startsWith("http-proxy://") -> parseProxy(l, "http", 8080)
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    /** Parses plain text or base64 subscription content into profiles. */
    fun parseSubscription(body: String): List<Profile> {
        parseOvpn(body)?.let { return listOf(it) }
        val text = if (body.contains("://")) body else decodeB64(body.trim())
        return text.lines().mapNotNull { parse(it) }
    }

    private fun parseUriStyle(link: String, proto: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else 443
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "flow", "pbk", "sid", "fp", "alpn", "serviceName", "headerType", "method", "allowInsecure")) {
            u.getQueryParameter(k)?.let { extra.put(k, it) }
        }
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = proto, address = host, port = port,
            secret = u.userInfo ?: "",
            transport = u.getQueryParameter("type") ?: "tcp",
            security = u.getQueryParameter("security") ?: if (proto == "trojan") "tls" else "none",
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    /**
     * ssh://user:pass@host:port?tls=1&sni=..&payload=..&proxy=host:port&allowInsecure=1#name
     * ssh://user:pass@RESOLVER_IP:53?mode=dnstt&ns=t.example.com&pubkey=HEX[&rmode=udp|doh|dot&resolver=..]#name
     * payload placeholders: [crlf] [cr] [lf] [host] [port] [host_port]   (URL-encode the whole value)
     */
    private fun parseSsh(link: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val mode = u.getQueryParameter("mode") ?: "direct"
        val port = if (u.port > 0) u.port else if (mode == "dnstt") 53 else 22
        val extra = JSONObject()
        for (k in listOf("mode", "tls", "sni", "allowInsecure", "payload", "proxy", "ns", "pubkey", "rmode", "resolver")) {
            u.getQueryParameter(k)?.let { extra.put(k, it) }
        }
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = "ssh", address = host, port = port, secret = u.userInfo ?: "",
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    /** A pasted/imported .ovpn file becomes one profile that is handed to "OpenVPN for Android". */
    private fun parseOvpn(body: String): Profile? {
        if (body.contains("://")) return null
        val remote = Regex("(?m)^\\s*remote\\s+(\\S+)(?:\\s+(\\d+))?").find(body) ?: return null
        if (!Regex("(?m)^\\s*(client|dev\\s+tun|dev\\s+tap)").containsMatchIn(body)) return null
        val host = remote.groupValues[1]
        val port = remote.groupValues[2].toIntOrNull() ?: 1194
        return Profile(
            name = "OpenVPN $host", protocol = "ovpn", address = host, port = port, secret = "",
            extra = JSONObject().put("config", body).toString(), country = CountryUtil.fromName(host),
        )
    }

    /** socks://user:pass@host:port#name , http-proxy://user:pass@host:port?security=tls#name */
    private fun parseProxy(link: String, proto: String, defPort: Int): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else defPort
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = proto, address = host, port = port,
            secret = u.userInfo ?: "", security = u.getQueryParameter("security") ?: "none",
            extra = JSONObject().apply {
                u.getQueryParameter("sni")?.let { put("sni", it) }
            }.toString(),
            country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseVmess(link: String): Profile? {
        val j = JSONObject(decodeB64(link.removePrefix("vmess://")))
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "alpn", "fp", "type")) {
            j.optString(k).takeIf { it.isNotBlank() }?.let { extra.put(k, it) }
        }
        val name = j.optString("ps").ifBlank { j.optString("add") }
        return Profile(
            name = name, protocol = "vmess", address = j.getString("add"),
            port = j.get("port").toString().toInt(), secret = j.getString("id"),
            transport = j.optString("net", "tcp"),
            security = j.optString("tls").ifBlank { "none" },
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseSs(link: String): Profile? {
        val body = link.removePrefix("ss://")
        val name = body.substringAfter('#', "").let { Uri.decode(it) }
        val main = body.substringBefore('#').substringBefore('?')
        val (userInfo, hostPort) = if (main.contains('@')) {
            val ui = main.substringBeforeLast('@')
            val decoded = if (ui.contains(':')) ui else decodeB64(ui)
            decoded to main.substringAfterLast('@')
        } else {
            val d = decodeB64(main)
            d.substringBeforeLast('@') to d.substringAfterLast('@')
        }
        val method = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':')
        val host = hostPort.substringBeforeLast(':')
        val port = hostPort.substringAfterLast(':').toInt()
        val extra = JSONObject().put("method", method.ifBlank { "aes-256-gcm" })
        val n = name.ifBlank { "$host:$port" }
        return Profile(
            name = n, protocol = "ss", address = host, port = port, secret = password,
            extra = extra.toString(), country = CountryUtil.fromName(n), rawLink = link,
        )
    }

    private fun decodeB64(s: String): String {
        var t = s.replace('-', '+').replace('_', '/').trim()
        while (t.length % 4 != 0) t += "="
        return String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8)
    }
}

object CountryUtil {
    private val codes = mapOf(
        "united states" to "US", "usa" to "US", "germany" to "DE", "singapore" to "SG",
        "japan" to "JP", "united kingdom" to "GB", "uk" to "GB", "canada" to "CA",
        "france" to "FR", "netherlands" to "NL", "india" to "IN", "bangladesh" to "BD",
    )

    /** Returns ISO country code guessed from a server name, or "". */
    fun fromName(name: String): String {
        val n = name.lowercase()
        codes.forEach { (k, v) -> if (n.contains(k)) return v }
        Regex("\\b([A-Z]{2})\\b").find(name)?.value?.let { return it }
        // Flag emoji: two regional indicator symbols
        val cps = name.codePoints().toArray()
        for (i in 0 until cps.size - 1) {
            if (cps[i] in 0x1F1E6..0x1F1FF && cps[i + 1] in 0x1F1E6..0x1F1FF) {
                return "" + ('A' + (cps[i] - 0x1F1E6)) + ('A' + (cps[i + 1] - 0x1F1E6))
            }
        }
        return ""
    }

    fun flag(code: String): String {
        if (code.length != 2) return "\uD83C\uDF10"
        return code.uppercase().map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
    }
}
