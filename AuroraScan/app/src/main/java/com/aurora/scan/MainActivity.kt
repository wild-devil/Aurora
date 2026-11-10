package com.aurora.scan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

val NeonCyan = Color(0xFF00F5FF)
val NeonPurple = Color(0xFFB026FF)
val NeonPink = Color(0xFFFF2E9A)
val BgTop = Color(0xFF05060F)
val BgMid = Color(0xFF0D0B22)
val BgBottom = Color(0xFF130A1F)
val GlassSurface = Color(0x33101830)
val MutedText = Color(0xFF8C93B8)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AuroraApp() }
    }
}

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun AuroraApp() {
    MaterialTheme(colorScheme = darkColorScheme(background = BgTop, surface = GlassSurface, primary = NeonCyan)) {
        val scope = rememberCoroutineScope()
        val engine = remember { ScanEngine() }

        var provider by remember { mutableStateOf("cloudflare") }
        var customText by remember { mutableStateOf("") }
        var maxIps by remember { mutableStateOf("300") }
        var port by remember { mutableStateOf("443") }
        var sni by remember { mutableStateOf("speed.cloudflare.com") }
        var scanning by remember { mutableStateOf(false) }
        var checked by remember { mutableStateOf(0) }
        var total by remember { mutableStateOf(0) }
        var results by remember { mutableStateOf(listOf<ScanResult>()) }
        val clipboard = LocalClipboardManager.current

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(BgTop, BgMid, BgBottom)))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                Text(
                    "AURORA SCAN",
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold,
                    style = TextStyle(brush = Brush.horizontalGradient(listOf(NeonCyan, NeonPurple, NeonPink)))
                )
                Text("CDN IP Scanner", color = MutedText, fontSize = 13.sp)
                Spacer(Modifier.height(16.dp))

                GlassCard {
                    Column(Modifier.padding(16.dp)) {
                        Text("Provider", color = Color.White, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(8.dp))
                        androidx.compose.foundation.layout.FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            listOf(
                                "cloudflare" to "Cloudflare",
                                "fastly" to "Fastly",
                                "akamai" to "Akamai",
                                "custom" to "Custom"
                            ).forEach { (key, label) ->
                                FilterChip(
                                    selected = provider == key,
                                    onClick = { provider = key },
                                    label = { Text(label) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = NeonPurple.copy(alpha = 0.35f),
                                        selectedLabelColor = Color.White,
                                        labelColor = MutedText
                                    )
                                )
                            }
                        }
                        if (provider == "custom") {
                            Spacer(Modifier.height(10.dp))
                            OutlinedTextField(
                                value = customText,
                                onValueChange = { customText = it },
                                label = { Text("IPs / CIDR, one per line") },
                                modifier = Modifier.fillMaxWidth(),
                                maxLines = 4
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedTextField(
                                value = maxIps,
                                onValueChange = { maxIps = it.filter(Char::isDigit) },
                                label = { Text("Max IPs") },
                                modifier = Modifier.weight(1f),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                            )
                            OutlinedTextField(
                                value = port,
                                onValueChange = { port = it.filter(Char::isDigit) },
                                label = { Text("Port") },
                                modifier = Modifier.weight(1f),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        OutlinedTextField(
                            value = sni,
                            onValueChange = { sni = it },
                            label = { Text("SNI / Host") },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                Spacer(Modifier.height(16.dp))

                Button(
                    onClick = {
                        if (scanning) {
                            engine.stopped = true
                            scanning = false
                        } else {
                            results = emptyList(); checked = 0
                            val ranges = when (provider) {
                                "cloudflare" -> Providers.cloudflare
                                "fastly" -> Providers.fastly
                                "akamai" -> Providers.akamai
                                else -> null
                            }
                            val limit = maxIps.toIntOrNull() ?: 300
                            val ipList = if (ranges != null)
                                randomIpsFromRanges(ranges, limit)
                            else
                                parseCustomInput(customText).take(limit)
                            if (ipList.isEmpty()) return@Button
                            total = ipList.size
                            engine.reset()
                            scanning = true
                            scope.launch(Dispatchers.Default) {
                                val res = engine.scan(
                                    ips = ipList,
                                    port = port.toIntOrNull() ?: 443,
                                    sni = sni,
                                    host = sni,
                                    path = "/cdn-cgi/trace",
                                    timeoutMs = 3000,
                                    threads = 60,
                                    tries = 1
                                ) { c, t, _ -> checked = c; total = t }
                                results = res
                                scanning = false
                            }
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                    contentPadding = PaddingValues()
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.horizontalGradient(
                                    if (scanning) listOf(Color(0xFFFF2E6A), NeonPurple) else listOf(NeonCyan, NeonPurple)
                                ),
                                RoundedCornerShape(16.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            if (scanning) "STOP SCAN" else "START SCAN",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                    }
                }

                if (scanning || total > 0) {
                    Spacer(Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = if (total > 0) checked.toFloat() / total else 0f,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp)),
                        color = NeonCyan,
                        trackColor = Color(0xFF1A2040)
                    )
                    Spacer(Modifier.height(4.dp))
                    Text("$checked / $total checked  •  ${results.size} found", color = MutedText, fontSize = 12.sp)
                }

                Spacer(Modifier.height(14.dp))
                Text("Results", color = Color.White, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(8.dp))

                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(results) { r ->
                        GlassCard {
                            Row(
                                Modifier
                                    .padding(12.dp)
                                    .fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column {
                                    Text(r.ip, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                                    Text(
                                        "${r.provider} • ${r.colo.ifEmpty { "-" }} • HTTP ${r.status}",
                                        color = MutedText,
                                        fontSize = 11.sp
                                    )
                                }
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        "${r.totalMs}ms",
                                        color = when {
                                            r.totalMs < 150 -> Color(0xFF3CFFB0)
                                            r.totalMs < 400 -> Color(0xFFFFD23C)
                                            else -> Color(0xFFFF5C7A)
                                        },
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    IconButton(
                                        onClick = { clipboard.setText(AnnotatedString(r.ip)) },
                                        modifier = Modifier.size(28.dp)
                                    ) {
                                        Icon(
                                            Icons.Filled.ContentCopy,
                                            contentDescription = "Copy",
                                            tint = NeonCyan,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun GlassCard(content: @Composable () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(GlassSurface)
            .border(
                1.dp,
                Brush.horizontalGradient(listOf(NeonCyan.copy(alpha = 0.4f), NeonPurple.copy(alpha = 0.4f))),
                RoundedCornerShape(18.dp)
            )
    ) {
        content()
    }
}
