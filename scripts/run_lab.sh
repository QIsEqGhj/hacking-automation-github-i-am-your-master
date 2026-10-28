#!/usr/bin/env bash
set -Eeuo pipefail

TOOL="${TOOL:-nmap}"
PROFILE="${PROFILE:-quick}"
LAB_TARGET="${LAB_TARGET:-miniapp}"
DOMAIN="${DOMAIN:-}"
ALLOWED_DOMAIN="${LAB_ALLOWED_DOMAIN:-}"
OUT="${RESULT_DIR:-$(pwd)/results}"
mkdir -p "$OUT"

# Shared public targets are NOT on the active testing allowlist.
# Active requests are restricted to applications started within this runner.
case "$TOOL" in
  nmap|subfinder|httpx|nuclei) ;;
  *) echo "Invalid tool: $TOOL" >&2; exit 2 ;;
esac
case "$PROFILE" in
  quick|detailed) ;;
  *) echo "Invalid scan profile: $PROFILE" >&2; exit 2 ;;
esac
case "$LAB_TARGET" in
  miniapp|juice-shop) ;;
  *) echo "Lab target not allowed: $LAB_TARGET" >&2; exit 2 ;;
esac

if [[ "$TOOL" == "subfinder" ]]; then
  if [[ -z "$ALLOWED_DOMAIN" || -z "$DOMAIN" ]]; then
    echo "Subfinder requires LAB_ALLOWED_DOMAIN (repository Settings / Variables) and the domain workflow input." >&2
    exit 2
  fi
  if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; then
    echo "Invalid domain name." >&2
    exit 2
  fi
  if [[ "${DOMAIN,,}" != "${ALLOWED_DOMAIN,,}" ]]; then
    echo "Out-of-scope domain: enter the exact LAB_ALLOWED_DOMAIN value." >&2
    exit 2
  fi
fi

PORT=8765
TARGET_URL='http://127.0.0.1:8765'
NUCLEI_TEMPLATE='/templates/lab-debug.yaml'
if [[ "$LAB_TARGET" == 'juice-shop' ]]; then
  PORT=3000
  TARGET_URL='http://127.0.0.1:3000'
  NUCLEI_TEMPLATE='/templates/lab-juice-shop.yaml'
fi

TARGET_DESCRIPTION="$TARGET_URL (application hosted on the runner)"
if [[ "$TOOL" == subfinder ]]; then
  TARGET_DESCRIPTION="$DOMAIN (passive sources, authorized project domain)"
fi
cat > "$OUT/execution-context.txt" <<META
Repository: ${GITHUB_REPOSITORY:-local-run}
Run ID: ${GITHUB_RUN_ID:-local}
GitHub actor (workflow initiator): ${GITHUB_ACTOR:-local}
Tool: $TOOL
Profile: $PROFILE
Selected local lab: $LAB_TARGET
Target: $TARGET_DESCRIPTION
UTC timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Notice: A cloud runner does NOT provide anonymity. Run identifiers, account activity, and logs may be correlated.
META

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [[ "$ip" =~ ^[0-9.]+$ ]]; then
    printf 'Egress IP reported by an external service: %s\n' "$ip" | tee -a "$OUT/execution-context.txt"
  else
    printf 'Egress IP: unavailable for this run.\n' | tee -a "$OUT/execution-context.txt"
  fi
fi

PID=""
CONTAINER=""
cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  if [[ -n "$CONTAINER" ]]; then
    docker logs "$CONTAINER" > "$OUT/target-server.log" 2>&1 || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$TOOL" != 'subfinder' ]]; then
  if [[ "$LAB_TARGET" == 'miniapp' ]]; then
    echo 'Starting the demo application at 127.0.0.1:8765.'
    python3 lab/app.py > "$OUT/target-server.log" 2>&1 &
    PID=$!
  else
    echo 'Starting OWASP Juice Shop at 127.0.0.1:3000 (Docker image pull may take some time).'
    CONTAINER="offensive-juice-shop-$$"
    docker run -d --name "$CONTAINER" -p 127.0.0.1:3000:3000 bkimminich/juice-shop > /dev/null
  fi
  ready=false
  for attempt in {1..60}; do
    if curl -fsS --max-time 2 "$TARGET_URL" > /dev/null; then
      ready=true
      break
    fi
    sleep 2
  done
  if [[ "$ready" != true ]]; then
    echo "Local lab target $LAB_TARGET did not become ready in time." >&2
    if [[ -n "$CONTAINER" ]]; then docker logs "$CONTAINER" || true; fi
    if [[ -n "$PID" ]]; then cat "$OUT/target-server.log"; fi
    exit 1
  fi
fi

echo "Tool: $TOOL | Profile: $PROFILE | Lab target: $LAB_TARGET | Started at: $(date -u '+%H:%M:%SZ')"
case "$TOOL" in
  nmap)
    if ! command -v nmap > /dev/null; then
      echo 'Installing Nmap from Ubuntu packages...'
      sudo apt-get update -qq
      sudo apt-get install -y -qq nmap
    fi
    args=(-sT -Pn -p "$PORT" --max-retries 1 --host-timeout 30s -oX "$OUT/nmap.xml")
    if [[ "$PROFILE" == 'detailed' ]]; then args+=(-sV --version-light); fi
    timeout 55s nmap "${args[@]}" 127.0.0.1 2>&1 | tee "$OUT/nmap.txt"
    ;;
  subfinder)
    echo "Starting passive subdomain discovery for the authorized domain: $DOMAIN"
    minutes=1
    if [[ "$PROFILE" == 'detailed' ]]; then minutes=2; fi
    timeout 145s docker run --rm projectdiscovery/subfinder:latest \
      -d "$DOMAIN" -silent -oJ -rl 2 -max-time "$minutes" \
      2>&1 | tee "$OUT/subfinder.jsonl"
    ;;
  httpx)
    args=(-u "$TARGET_URL" -sc -title -server -json -silent -rl 2 -timeout 5 -retries 0 -nfs)
    if [[ "$PROFILE" == 'detailed' ]]; then args+=(-td -cl); fi
    timeout 80s docker run --rm --network host projectdiscovery/httpx:latest \
      "${args[@]}" 2>&1 | tee "$OUT/httpx.jsonl"
    ;;
  nuclei)
    timeout 90s docker run --rm --network host \
      -v "$(pwd)/templates:/templates:ro" projectdiscovery/nuclei:latest \
      -u "$TARGET_URL" -t "$NUCLEI_TEMPLATE" \
      -jsonl -silent -duc -or -rl 2 -c 1 -timeout 5 \
      2>&1 | tee "$OUT/nuclei.jsonl"
    ;;
esac
printf 'Execution completed: %s UTC\n' "$(date -u '+%H:%M:%S')" | tee -a "$OUT/execution-context.txt"
