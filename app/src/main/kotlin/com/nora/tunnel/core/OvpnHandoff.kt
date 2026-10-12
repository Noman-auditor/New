package com.nora.tunnel.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import com.nora.tunnel.R
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.File

/**
 * OpenVPN needs its own TUN + native openvpn/openssl stack, so Nora hands the profile to the
 * open-source "OpenVPN for Android" app (de.blinkt.openvpn). A notification (tap = import) is used
 * because Android blocks activities started from a background service.
 */
object OvpnHandoff {
    private const val PKG = "de.blinkt.openvpn"
    private const val CH = "nora_ovpn"

    /** Returns the message to show to the user. Throws if OpenVPN for Android is not installed. */
    fun offer(ctx: Context, p: Profile): String {
        try { ctx.packageManager.getPackageInfo(PKG, 0) }
        catch (_: PackageManager.NameNotFoundException) {
            throw NoRetryException("Install \\"OpenVPN for Android\\" (de.blinkt.openvpn) to use OpenVPN profiles")
        }
        val dir = File(ctx.cacheDir, "ovpn").apply { mkdirs() }
        val f = File(dir, "nora-${p.id}.ovpn")
        f.writeText(JSONObject(p.extra).optString("config"))
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", f)

        val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/x-openvpn-profile")
            .setPackage(PKG).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(ctx, 7, view, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

        val nm = ctx.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CH, "OpenVPN hand-off", NotificationManager.IMPORTANCE_HIGH))
        }
        nm.notify(2, NotificationCompat.Builder(ctx, CH).setSmallIcon(R.drawable.ic_tile)
            .setContentTitle("OpenVPN profile ready").setContentText("Tap to open in OpenVPN for Android, then connect there")
            .setAutoCancel(true).setContentIntent(pi).build())
        return "OpenVPN profile ready: tap the notification to open it in OpenVPN for Android"
    }
}
