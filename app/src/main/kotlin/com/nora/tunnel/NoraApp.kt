package com.nora.tunnel

import android.app.Application
import com.nora.tunnel.core.AppLog
import com.nora.tunnel.data.AppDb
import com.nora.tunnel.data.SettingsStore
import java.io.File

class NoraApp : Application() {
    val db by lazy { AppDb.get(this) }
    val settings by lazy { SettingsStore(this) }

    override fun onCreate() {
        super.onCreate()
        val crashFile = File(filesDir, "last_crash.txt")

        // Show the previous crash (if any) in the Logs screen, then clear it.
        try {
            if (crashFile.exists()) {
                AppLog.add("ERROR", "App crashed last time:\n" + crashFile.readText().take(2500))
                crashFile.delete()
            }
        } catch (_: Throwable) {}

        // Save the stack trace of any uncaught crash so it survives the process dying.
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try { crashFile.writeText("Thread: ${t.name}\n" + e.stackTraceToString()) } catch (_: Throwable) {}
            previous?.uncaughtException(t, e)
        }
    }
}
