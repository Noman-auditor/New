package com.nora.tunnel.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nora.tunnel.data.Profile
import com.nora.tunnel.ui.theme.NoraColors

fun protoLabel(p: Profile): String {
    val name = when (p.protocol) {
        "ss" -> "Shadowsocks"
        "vless" -> "VLESS"
        "vmess" -> "VMess"
        "trojan" -> "Trojan"
        "wireguard" -> "WireGuard"
        "ssh" -> if (p.extra.contains("dnstt")) "DNSTT + SSH" else "SSH"
        "http" -> "HTTP Proxy"
        "socks" -> "SOCKS5"
        "ovpn" -> "OpenVPN"
        else -> p.protocol
    }
    return "$name • ${p.transport.uppercase()}"
}

@Composable
fun Badge(text: String, color: Color = NoraColors.Mint) {
    Text(
        text, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(color.copy(alpha = 0.15f))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

@Composable
fun ScreenHeader(title: String, onBack: (() -> Unit)? = null, trailing: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        if (onBack != null) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Color.White,
                modifier = Modifier.clickable { onBack() }.padding(end = 12.dp),
            )
        }
        Text(title, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
        trailing()
    }
}

fun Modifier.clickableNoRipple(onClick: () -> Unit): Modifier = this.clickable(onClick = onClick)

fun formatBytes(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / 1048576.0)
    else -> "%.2f GB".format(b / 1073741824.0)
}

@Composable
fun ToggleRow(title: String, sub: String? = null, checked: Boolean, onChange: (Boolean) -> Unit) {
    NoraCard(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, color = Color.White, fontWeight = FontWeight.SemiBold)
                if (sub != null) Text(sub, color = NoraColors.TextDim, fontSize = 12.sp)
            }
            androidx.compose.material3.Switch(
                checked = checked, onCheckedChange = onChange,
                colors = androidx.compose.material3.SwitchDefaults.colors(
                    checkedTrackColor = NoraColors.Mint, checkedThumbColor = NoraColors.OnMint,
                ),
            )
        }
    }
}

@Composable
fun InfoRow(title: String, value: String, onClick: (() -> Unit)? = null) {
    NoraCard(Modifier.fillMaxWidth(), onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, color = Color.White, modifier = Modifier.weight(1f))
            Text(value, color = NoraColors.TextDim, fontSize = 13.sp)
        }
    }
}
