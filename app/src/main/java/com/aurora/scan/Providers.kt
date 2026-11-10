package com.aurora.scan

import kotlin.random.Random

object Providers {
    val cloudflare = listOf(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    )
    val fastly = listOf(
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "104.156.80.0/20",
        "140.248.64.0/18", "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"
    )
    val akamai = listOf(
        "2.16.0.0/13", "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "23.192.0.0/11"
    )
}

fun ipToLong(ip: String): Long {
    val p = ip.trim().split(".").map { it.toLong() }
    return (p[0] shl 24) + (p[1] shl 16) + (p[2] shl 8) + p[3]
}

fun longToIp(v: Long): String =
    "${(v shr 24) and 0xFF}.${(v shr 16) and 0xFF}.${(v shr 8) and 0xFF}.${v and 0xFF}"

/** Returns (networkStart, networkEnd) as unsigned 32-bit longs, or null if invalid. */
fun parseCidr(cidr: String): Pair<Long, Long>? = try {
    val (base, maskStr) = cidr.trim().split("/")
    val mask = maskStr.toInt().coerceIn(0, 32)
    val baseLong = ipToLong(base)
    val size = if (mask == 0) 0x100000000L else 1L shl (32 - mask)
    val network = baseLong and (0xFFFFFFFFL shl (32 - mask))
    Pair(network, network + size - 1)
} catch (e: Exception) {
    null
}

fun randomIpsFromRanges(ranges: List<String>, count: Int): List<String> {
    val parsed = ranges.mapNotNull { parseCidr(it) }
    if (parsed.isEmpty()) return emptyList()
    val result = linkedSetOf<String>()
    var attempts = 0
    val maxAttempts = (count * 25).coerceAtLeast(200)
    while (result.size < count && attempts < maxAttempts) {
        attempts++
        val (lo, hi) = parsed[Random.nextInt(parsed.size)]
        val span = hi - lo + 1
        val v = lo + (Random.nextLong(0, if (span <= 0) 1L else span))
        result.add(longToIp(v))
    }
    return result.toList()
}

/** Parses free-form user text: plain IPs, or CIDR blocks (small ones expanded fully, large ones sampled). */
fun parseCustomInput(text: String): List<String> {
    val out = mutableListOf<String>()
    text.split(Regex("[\\s,;]+")).filter { it.isNotBlank() }.forEach { tok ->
        if (tok.contains("/")) {
            parseCidr(tok)?.let { (lo, hi) ->
                val size = hi - lo + 1
                if (size in 1..256) {
                    var v = lo
                    while (v <= hi) { out.add(longToIp(v)); v++ }
                } else {
                    out.addAll(randomIpsFromRanges(listOf(tok), size.coerceAtMost(500).toInt()))
                }
            }
        } else if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(tok)) {
            out.add(tok)
        }
    }
    return out
}
