package com.nora.tunnel.core

import com.nora.tunnel.data.Profile
import org.json.JSONArray
import org.json.JSONObject

object XrayConfig {
    const val SOCKS_PORT = 10808

    private val lanCidrs = listOf(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "fc00::/7", "fe80::/10",
    )

    /** [serverIp] is the already-resolved address, so no DNS is needed before the tunnel is up. */
    fun build(p: Profile, serverIp: String, dns: String, routingMode: String): String {
        val extra = JSONObject(p.extra.ifBlank { "{}" })
        val rules = JSONArray()
        if (routingMode == "bypass_lan") {
            rules.put(JSONObject().put("type", "field").put("ip", JSONArray(lanCidrs)).put("outboundTag", "direct"))
        }
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(
                JSONObject().put("tag", "socks").put("listen", "127.0.0.1").put("port", SOCKS_PORT)
                    .put("protocol", "socks")
                    .put("settings", JSONObject().put("udp", true).put("auth", "noauth"))
                    .put("sniffing", JSONObject().put("enabled", true)
                        .put("destOverride", JSONArray().put("http").put("tls")))
            ))
            .put("outbounds", JSONArray()
                .put(outbound(p, serverIp, extra))
                .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
                .put(JSONObject().put("tag", "block").put("protocol", "blackhole")))
            .put("dns", JSONObject().put("servers", JSONArray().put(dns)))
            .put("routing", JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules))
            .toString()
    }

    private fun outbound(p: Profile, ip: String, x: JSONObject): JSONObject {
        val o = JSONObject().put("tag", "proxy").put("protocol", if (p.protocol == "ss") "shadowsocks" else p.protocol)
        val settings = when (p.protocol) {
            "vless" -> JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", ip).put("port", p.port).put("users", JSONArray().put(
                    JSONObject().put("id", p.secret).put("encryption", "none")
                        .apply { x.optString("flow").takeIf { it.isNotBlank() }?.let { put("flow", it) } }
                ))))
            "vmess" -> JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", ip).put("port", p.port).put("users", JSONArray().put(
                    JSONObject().put("id", p.secret).put("alterId", 0).put("security", "auto")
                ))))
            "trojan" -> JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", ip).put("port", p.port).put("password", p.secret)))
            "ss" -> JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", ip).put("port", p.port).put("password", p.secret)
                    .put("method", x.optString("method", "aes-256-gcm"))))
            "http", "socks" -> JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", ip).put("port", p.port).apply {
                    if (p.secret.contains(":")) put("users", JSONArray().put(
                        JSONObject().put("user", p.secret.substringBefore(":")).put("pass", p.secret.substringAfter(":"))
                    ))
                }))
            else -> throw IllegalArgumentException("Protocol '${p.protocol}' is not supported by the Xray engine")
        }
        o.put("settings", settings)
        if (p.protocol in setOf("vless", "vmess", "trojan") ||
            (p.protocol in setOf("http", "socks") && p.security == "tls")) o.put("streamSettings", stream(p, x))
        return o
    }

    private fun stream(p: Profile, x: JSONObject): JSONObject {
        val net = p.transport.ifBlank { "tcp" }
        val s = JSONObject().put("network", net).put("security", p.security.ifBlank { "none" })
        val host = x.optString("host")
        val path = x.optString("path", "/")
        val sni = x.optString("sni").ifBlank { host.ifBlank { p.address } }
        when (p.security) {
            "tls" -> s.put("tlsSettings", JSONObject().put("serverName", sni).put("allowInsecure", x.optString("allowInsecure") in setOf("1", "true"))
                .apply {
                    x.optString("fp").takeIf { it.isNotBlank() }?.let { put("fingerprint", it) }
                    x.optString("alpn").takeIf { it.isNotBlank() }?.let { put("alpn", JSONArray(it.split(","))) }
                })
            "reality" -> s.put("realitySettings", JSONObject().put("serverName", sni)
                .put("fingerprint", x.optString("fp").ifBlank { "chrome" })
                .put("publicKey", x.optString("pbk")).put("shortId", x.optString("sid")).put("spiderX", ""))
        }
        when (net) {
            "tcp" -> if (x.optString("headerType") == "http") s.put("tcpSettings", JSONObject().put("header",
                JSONObject().put("type", "http").put("request", JSONObject()
                    .put("version", "1.1").put("method", x.optString("method", "GET"))
                    .put("path", JSONArray().put(path))
                    .put("headers", JSONObject()
                        .put("Host", JSONArray().put(host.ifBlank { p.address }))
                        .put("User-Agent", JSONArray().put("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36"))
                        .put("Connection", JSONArray().put("keep-alive"))))))
            "ws" -> s.put("wsSettings", JSONObject().put("path", path)
                .apply { if (host.isNotBlank()) put("headers", JSONObject().put("Host", host)) })
            "grpc" -> s.put("grpcSettings", JSONObject().put("serviceName", x.optString("serviceName")))
            "httpupgrade" -> s.put("httpupgradeSettings", JSONObject().put("path", path).put("host", host))
            "xhttp" -> s.put("xhttpSettings", JSONObject().put("path", path).put("host", host))
            "h2" -> s.put("httpSettings", JSONObject().put("path", path)
                .apply { if (host.isNotBlank()) put("host", JSONArray().put(host)) })
        }
        return s
    }
}
