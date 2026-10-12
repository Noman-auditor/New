package com.nora.tunnel.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.nora.tunnel.MainActivity
import com.nora.tunnel.NoraApp
import com.nora.tunnel.R
import com.nora.tunnel.data.Profile
import com.nora.tunnel.data.ProfileDao
import com.nora.tunnel.data.SettingsStore
import hev.htproxy.TProxyService
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.io.File
import java.net.InetAddress

class NoraVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "com.nora.tunnel.CONNECT"
        const val ACTION_DISCONNECT = "com.nora.tunnel.DISCONNECT"
        private const val CHANNEL = "nora_vpn"
        private const val NOTIF_ID = 1
        private const val TUN_ADDR = "26.26.26.1"
    }

    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e ->
            AppLog.add("ERROR", "Service error: ${e.javaClass.simpleName}: ${e.message}")
        },
    )
    private var tun: ParcelFileDescriptor? = null
    private var connectJob: Job? = null
    private var monitorJob: Job? = null
    private var netCb: ConnectivityManager.NetworkCallback? = null
    private var killSwitch = false
    private var hevRunning = false
    private var persistedRx = 0L
    private var persistedTx = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> scope.launch { shutdown() }
            ACTION_CONNECT -> {
                startFg("Connecting…")
                if (connectJob?.isActive != true) connectJob = scope.launch { connectWithRetry() }
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        scope.launch { shutdown() }
        super.onRevoke()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    // ---- connection flow ----

    private suspend fun connectWithRetry() {
        VpnController.setConnecting()
        NoraWidget.refresh(this)
        var last: Exception? = null
        for (attempt in 1..3) {
            try { doConnect(); return }
            catch (e: CancellationException) { throw e }
            catch (e: NoRetryException) { last = e; break }
            catch (e: Throwable) {
                // Throwable (not Exception): native/JNI problems surface as Errors such as
                // UnsatisfiedLinkError, and must not kill the whole app.
                last = if (e is Exception) e else RuntimeException("${e.javaClass.simpleName}: ${e.message}", e)
                AppLog.add("ERROR", "Attempt $attempt failed: ${e.message}")
                stopEngines()
                if (attempt < 3) delay(2000L * attempt)
            }
        }
        fail(last?.message ?: "Connection failed")
    }

    private suspend fun doConnect() {
        val app = application as NoraApp
        val s = app.settings
        val dns = s.dnsServer.first().ifBlank { "1.1.1.1" }
        val blockV6 = s.blockIpv6On.first()
        val mode = s.routingMode.first()
        killSwitch = s.killSwitchOn.first()

        val profile = pickProfile(app.db.profiles(), s)
        // OpenVPN profiles are handed to the official "OpenVPN for Android" app (it owns its own TUN).
        if (profile.protocol == "ovpn") throw NoRetryException(OvpnHandoff.offer(this, profile))
        val isSsh = profile.protocol == "ssh"
        if (!TProxyService.loaded) throw IllegalStateException("libhev-socks5-tunnel.so not found (see NATIVE.md)")
        if (!isSsh && !XrayEngine.isAvailable()) throw IllegalStateException("Xray library not found (see NATIVE.md)")

        // Resolve the server before the tunnel exists, so DNS never needs the tunnel.
        val ip = withContext(Dispatchers.IO) { InetAddress.getByName(profile.address).hostAddress!! }
        val config = if (isSsh) "" else XrayConfig.build(profile, ip, dns, mode)

        if (tun == null) tun = buildTun(dns, blockV6) ?: throw IllegalStateException("VPN permission was revoked")

        if (isSsh) withContext(Dispatchers.IO) { SshEngine.start(this@NoraVpnService, profile, ip) }
        else XrayEngine.start(this, config)
        val yaml = File(filesDir, "hev.yaml")
        yaml.writeText(
            """
            tunnel:
              mtu: 1500
              ipv4: $TUN_ADDR
            socks5:
              port: ${XrayConfig.SOCKS_PORT}
              address: 127.0.0.1
              udp: 'udp'
            """.trimIndent() + "\n"
        )
        TProxyService.TProxyStartService(yaml.absolutePath, tun!!.fd)
        hevRunning = true

        VpnController.setConnected(profile.name)
        AppLog.add("CONNECT", "Connected to ${profile.name} (${profile.protocol})")
        notifyText("Connected: ${profile.name}")
        registerNetworkCallback()
        startMonitors(ip, profile.port, s)
        NoraWidget.refresh(this)
    }

    private suspend fun pickProfile(dao: ProfileDao, s: SettingsStore): Profile {
        val id = s.selectedProfileId.first()
        if (id != -1L) dao.get(id)?.let { return it }
        val all = dao.observeAll().first()
        if (all.isEmpty()) throw IllegalStateException("No profiles. Import one first.")
        // Auto Select: lowest TCP latency wins.
        val timed = coroutineScope { all.map { p -> async { p to Net.tcpPing(p.address, p.port) } }.awaitAll() }
        return timed.filter { it.second != null }.minByOrNull { it.second!! }?.first
            ?: throw IllegalStateException("No reachable server")
    }

    private fun buildTun(dns: String, blockV6: Boolean): ParcelFileDescriptor? {
        val b = Builder().setSession("Nora Tunnel").setMtu(1500)
            .addAddress(TUN_ADDR, 30).addRoute("0.0.0.0", 0).addDnsServer(dns)
        // Our own sockets (Xray -> server) must not loop back into the tunnel.
        try { b.addDisallowedApplication(packageName) } catch (_: Exception) {}
        // IPv6 routed into a tunnel that only carries IPv4 = IPv6 is dropped, not leaked.
        if (blockV6) b.addAddress("fc00::1", 128).addRoute("::", 0)
        return b.establish()
    }

    private fun startMonitors(ip: String, port: Int, s: SettingsStore) {
        persistedRx = 0; persistedTx = 0
        monitorJob = scope.launch {
            var lastRx = 0L; var lastTx = 0L; var tick = 0
            val profileIsSsh = SshEngine.isAlive()
            while (isActive) {
                delay(1000); tick++
                if (profileIsSsh && !SshEngine.isAlive()) { fail("SSH session lost"); return@launch }
                val st = TProxyService.TProxyGetStats()
                if (st != null && st.size >= 4) {
                    val tx = st[1]; val rx = st[3]
                    VpnController.updateStats(rx, tx, maxOf(0, rx - lastRx), maxOf(0, tx - lastTx))
                    lastRx = rx; lastTx = tx
                }
                if (tick % 15 == 0) persistTraffic(s)
                if (tick % 20 == 1) launch { VpnController.updatePing(Net.tcpPing(ip, port)) }
                if (tick % 5 == 0) NoraWidget.refresh(this@NoraVpnService)
            }
        }
    }

    private suspend fun persistTraffic(s: SettingsStore) {
        val l = VpnController.live.value
        val dRx = l.rx - persistedRx; val dTx = l.tx - persistedTx
        if (dRx > 0 || dTx > 0) { s.addTraffic(dRx, dTx); persistedRx = l.rx; persistedTx = l.tx }
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                setUnderlyingNetworks(arrayOf(network)); AppLog.add("INFO", "Network available")
            }
            override fun onLost(network: Network) {
                setUnderlyingNetworks(null); AppLog.add("INFO", "Network lost")
            }
        }
        netCb = cb
        try { cm.registerDefaultNetworkCallback(cb) } catch (_: Exception) {}
    }

    // ---- teardown ----

    private fun stopEngines() {
        if (hevRunning) { try { TProxyService.TProxyStopService() } catch (_: Throwable) {}; hevRunning = false }
        SshEngine.stop()
        XrayEngine.stop()
    }

    /** Final failure. With the kill switch on, the TUN stays up with no engine, so traffic is blackholed. */
    private fun fail(msg: String) {
        monitorJob?.cancel()
        stopEngines()
        AppLog.add("ERROR", msg)
        if (killSwitch && tun != null) {
            VpnController.setError("$msg. Kill switch is blocking traffic.")
            notifyText("Kill switch active: traffic blocked")
        } else {
            closeTun()
            VpnController.setError(msg)
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        NoraWidget.refresh(this)
    }

    private suspend fun shutdown() {
        connectJob?.cancel()
        monitorJob?.cancel()
        withContext(NonCancellable) { persistTraffic((application as NoraApp).settings) }
        netCb?.let { try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } catch (_: Exception) {} }
        netCb = null
        stopEngines()
        closeTun()
        val wasUp = VpnController.state.value != VpnState.DISCONNECTED
        VpnController.setDisconnected()
        if (wasUp) AppLog.add("DISCONNECT", "Disconnected")
        NoraWidget.refresh(this)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeTun() { try { tun?.close() } catch (_: Exception) {}; tun = null }

    // ---- notification ----

    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, NoraVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_tile).setContentTitle("Nora Tunnel").setContentText(text)
            .setOngoing(true).setContentIntent(open)
            .addAction(0, "Disconnect", stop).build()
    }

    private fun startFg(text: String) {
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0
        ServiceCompat.startForeground(this, NOTIF_ID, notification(text), type)
    }

    private fun notifyText(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
    }
}

/** Failure that must not be retried (the message is shown to the user as is). */
class NoRetryException(msg: String) : Exception(msg)
