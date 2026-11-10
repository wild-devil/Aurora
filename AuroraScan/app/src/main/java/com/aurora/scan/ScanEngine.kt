package com.aurora.scan

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

data class ScanResult(
    val ip: String,
    val port: Int,
    val tcpMs: Long,
    val tlsMs: Long,
    val ttfbMs: Long,
    val totalMs: Long,
    val status: Int,
    val provider: String,
    val colo: String,
    val server: String,
    val score: Long
)

class ScanEngine {
    @Volatile var stopped = false
    fun reset() { stopped = false }

    suspend fun scan(
        ips: List<String>,
        port: Int,
        sni: String,
        host: String,
        path: String,
        timeoutMs: Int,
        threads: Int,
        tries: Int,
        onProgress: (checked: Int, total: Int, result: ScanResult?) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(threads.coerceIn(1, 200))
        val results = java.util.Collections.synchronizedList(mutableListOf<ScanResult>())
        var checked = 0
        val lock = Any()

        val jobs = ips.map { ip ->
            async(Dispatchers.IO) {
                if (stopped) return@async
                semaphore.withPermit {
                    if (stopped) return@withPermit
                    val r = probe(ip, port, sni, host, path, timeoutMs, tries)
                    synchronized(lock) {
                        checked++
                        if (r != null) results.add(r)
                        onProgress(checked, ips.size, r)
                    }
                }
            }
        }
        jobs.awaitAll()
        results.sortedBy { it.score }
    }

    private fun probe(ip: String, port: Int, sni: String, host: String, path: String, timeoutMs: Int, tries: Int): ScanResult? {
        var best: ScanResult? = null
        var bestTotal = Long.MAX_VALUE
        var ok = 0
        repeat(tries) {
            if (stopped) return@repeat
            try {
                val t0 = System.nanoTime()
                val raw = Socket()
                raw.connect(InetSocketAddress(ip, port), timeoutMs)
                val tcpMs = (System.nanoTime() - t0) / 1_000_000

                val t1 = System.nanoTime()
                val ctx = SSLContext.getInstance("TLS")
                ctx.init(null, null, null)
                val ssl = ctx.socketFactory.createSocket(raw, sni, port, true) as SSLSocket
                ssl.soTimeout = timeoutMs
                ssl.startHandshake()
                val tlsMs = (System.nanoTime() - t1) / 1_000_000

                val t2 = System.nanoTime()
                ssl.outputStream.apply {
                    write(
                        "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                            .toByteArray()
                    )
                    flush()
                }
                val reader = BufferedReader(InputStreamReader(ssl.inputStream))
                val statusLine = reader.readLine() ?: ""
                val ttfbMs = (System.nanoTime() - t2) / 1_000_000
                val status = Regex("HTTP/\\d\\.\\d (\\d{3})").find(statusLine)?.groupValues?.get(1)?.toIntOrNull() ?: 0

                val headers = mutableMapOf<String, String>()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    val idx = line.indexOf(':')
                    if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
                }
                try { ssl.close() } catch (_: Exception) {}

                val total = tcpMs + tlsMs + ttfbMs
                ok++
                val provider = detectProvider(headers)
                val colo = detectColo(headers)
                val score = total + (if (status in 200..399) 0L else 5000L)
                val r = ScanResult(ip, port, tcpMs, tlsMs, ttfbMs, total, status, provider, colo, headers["server"] ?: "", score)
                if (total < bestTotal) { bestTotal = total; best = r }
            } catch (e: Exception) {
                // this attempt failed; loop continues to next try
            }
        }
        return if (ok > 0) best else null
    }

    private fun detectProvider(h: Map<String, String>): String = when {
        h.containsKey("cf-ray") || h["server"]?.equals("cloudflare", true) == true -> "cloudflare"
        h.containsKey("x-fastly-request-id") || h["via"]?.contains("fastly", true) == true -> "fastly"
        h["server"]?.contains("akamai", true) == true || h.keys.any { it.startsWith("x-akamai") } -> "akamai"
        else -> h["server"]?.take(20)?.ifBlank { "unknown" } ?: "unknown"
    }

    private fun detectColo(h: Map<String, String>): String {
        h["cf-ray"]?.let { if (it.contains("-")) return it.substringAfterLast("-") }
        h["x-served-by"]?.let { return it.split(",").last().trim().substringAfterLast("-") }
        return ""
    }
}
