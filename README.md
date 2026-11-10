# Aurora Scan

A native Android CDN IP scanner (Kotlin + Jetpack Compose, no Python). Scans Cloudflare / Fastly
IP ranges (or a custom list/CIDR you paste in) over real TCP + TLS (with SNI) + HTTP, and ranks
results by latency so you can pick the fastest reachable IP for a CDN-fronted connection.

## Build it from GitHub (no local setup)

1. Create a new GitHub repo and push this whole folder to it (branch `main`).
2. Go to the repo's **Actions** tab — a workflow run starts automatically on push.
3. When it finishes, open the run and download the **aurora-scan-debug-apk** artifact — that's
   your installable APK (zipped; unzip to get the `.apk`).
4. Enable "install unknown apps" for your browser/file manager on the phone, then install it.

You can also re-trigger a build any time from Actions → "Build APK" → "Run workflow".

## Build it locally instead

Open the folder in Android Studio (Giraffe or newer) → let it sync Gradle → Run, or
`Build > Build Bundle(s) / APK(s) > Build APK(s)`.

## What it does

- Pulls known Cloudflare / Fastly ranges, or your own pasted IPs/CIDRs.
- Opens a real TCP connection to each IP, does a TLS handshake with your chosen SNI, sends an
  HTTP request, and times TCP / TLS / TTFB separately.
- Detects which CDN actually answered (via response headers) and the edge PoP (colo) when present.
- Shows live progress and a ranked, color-coded result list; tap the copy icon to grab an IP.

## Notes

- This is a network diagnostic tool only — it doesn't decompile, patch, or bundle any other
  app's code or credentials.
- First Gradle sync (local or in Actions) downloads dependencies, so it needs an internet
  connection once.
