#!/usr/bin/env bash
#
# recon.sh — VAPT recon orchestrator for Kali Linux
#
# Runs standard, industry-recognized scanners (Nmap, Nikto, WhatWeb, subfinder,
# optionally sqlmap) against a single authorized target and drops raw output
# into a run folder for report_generator.py to consume.
#
# USAGE:
#   ./recon.sh -t example.com -a
#
#   -t <target>   Domain or IP to test (required)
#   -a            Confirms you have written authorization to test this target (required)
#   -u <url>      Specific URL with a parameter to test with sqlmap, e.g.
#                 "https://example.com/page.php?id=5" (optional, sqlmap is opt-in)
#   -o <dir>      Output directory (default: ./results/<target>_<timestamp>)
#
# REQUIRES (install via apt on Kali if missing):
#   nmap nikto whatweb subfinder sqlmap
#
set -euo pipefail

TARGET=""
AUTHORIZED=0
SQLI_URL=""
OUTDIR=""

usage() {
    grep '^#' "$0" | sed -e 's/^#//' -e '1,2d'
    exit 1
}

while getopts "t:au:o:h" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        a) AUTHORIZED=1 ;;
        u) SQLI_URL="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "[!] -t <target> is required."
    usage
fi

# ---- Authorization gate --------------------------------------------------
if [[ "$AUTHORIZED" -ne 1 ]]; then
    cat <<'EOF'

[!] STOP: Authorization flag not set.

    This script performs active security scanning, including brute-force-style
    SQL injection probing via sqlmap if you supply -u. Running this against
    any system you do not own or do not have EXPLICIT WRITTEN PERMISSION to
    test is illegal in most jurisdictions (in India: IT Act 2000, Sections
    43 & 66).

    If you have written authorization (a signed scope/rules-of-engagement
    document, or it's your own lab/CTF box), re-run with -a to confirm.

EOF
    exit 1
fi

echo "You are confirming you have written authorization to test: $TARGET"
read -r -p "Type the target domain again to confirm and proceed: " CONFIRM
if [[ "$CONFIRM" != "$TARGET" ]]; then
    echo "[!] Confirmation did not match target. Aborting."
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="${OUTDIR:-./results/${TARGET}_${TIMESTAMP}}"
mkdir -p "$OUTDIR"
echo "[*] Output directory: $OUTDIR"

log() { echo "[*] $(date +%H:%M:%S) - $1"; }

# ---- Phase 1: Subdomain enumeration --------------------------------------
if command -v subfinder &>/dev/null; then
    log "Running subfinder..."
    subfinder -d "$TARGET" -silent -o "$OUTDIR/subdomains.txt" || true
else
    log "subfinder not found, skipping (apt install subfinder)"
    touch "$OUTDIR/subdomains.txt"
fi

# ---- Phase 2: Port / service scan (Nmap) ---------------------------------
log "Running nmap -A (this can take a few minutes)..."
nmap -A -oA "$OUTDIR/nmap_scan" "$TARGET" > "$OUTDIR/nmap_raw.txt" 2>&1 || true

# ---- Phase 3: Web server / misconfig scan (Nikto) ------------------------
if command -v nikto &>/dev/null; then
    log "Running nikto..."
    nikto -h "https://$TARGET" -output "$OUTDIR/nikto_output.txt" -Format txt || true
else
    log "nikto not found, skipping (apt install nikto)"
fi

# ---- Phase 4: Technology fingerprinting (WhatWeb) ------------------------
if command -v whatweb &>/dev/null; then
    log "Running whatweb..."
    whatweb -a 3 "https://$TARGET" --log-json="$OUTDIR/whatweb.json" > "$OUTDIR/whatweb_raw.txt" 2>&1 || true
else
    log "whatweb not found, skipping (apt install whatweb)"
fi

# ---- Phase 5 (opt-in): SQL injection probe (sqlmap) ----------------------
if [[ -n "$SQLI_URL" ]]; then
    if command -v sqlmap &>/dev/null; then
        log "Running sqlmap against: $SQLI_URL"
        log "This is an ACTIVE injection test. Only proceeding because -u was explicitly supplied."
        sqlmap -u "$SQLI_URL" --batch --level=2 --risk=1 \
            --output-dir="$OUTDIR/sqlmap" > "$OUTDIR/sqlmap_raw.txt" 2>&1 || true
    else
        log "sqlmap not found, skipping (apt install sqlmap)"
    fi
else
    log "No -u supplied, skipping sqlmap (SQLi testing is opt-in — see README)"
fi

log "Recon complete. Raw output saved to: $OUTDIR"
log "Next: python3 scripts/report_generator.py --input $OUTDIR --target $TARGET"
