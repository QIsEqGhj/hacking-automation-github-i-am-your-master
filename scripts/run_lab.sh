#!/usr/bin/env bash
set -Eeuo pipefail

TOOL="${TOOL:-nmap}"
PROFILE="${PROFILE:-quick}"
TARGET_MODE="${TARGET_MODE:-local}"
LAB_TARGET="${LAB_TARGET:-miniapp}"
TARGET_DOMAIN="${TARGET_DOMAIN:-}"
TARGET_IP="${TARGET_IP:-}"
TARGET_URL_INPUT="${TARGET_URL:-}"
PORTS="${PORTS:-80,443}"
OUT="${RESULT_DIR:-$(pwd)/results}"
mkdir -p "$OUT"

case "$TOOL" in nmap|subfinder|httpx|nuclei) ;; *) echo "Invalid tool: $TOOL" >&2; exit 2;; esac
case "$PROFILE" in quick|detailed) ;; *) echo "Invalid profile: $PROFILE" >&2; exit 2;; esac
case "$TARGET_MODE" in local|external) ;; *) echo "Invalid target mode: $TARGET_MODE" >&2; exit 2;; esac
case "$LAB_TARGET" in miniapp|juice-shop) ;; *) echo "Invalid local lab: $LAB_TARGET" >&2; exit 2;; esac
if [[ "$TOOL" == subfinder && "$TARGET_MODE" != external ]]; then
  echo 'Subfinder needs target_mode=external and an authorized project domain.' >&2
  exit 2
fi

if [[ "$TARGET_MODE" == external ]]; then
  # Require exactly one input. Values are passed as arguments, never shell commands.
  count=0
  for candidate in "$TARGET_DOMAIN" "$TARGET_IP" "$TARGET_URL_INPUT"; do
    if [[ -n "$candidate" ]]; then ((count += 1)); fi
  done
  if ((count != 1)); then
    echo 'External mode requires exactly one of target_domain, target_ip, or target_url.' >&2
    exit 2
  fi
  if [[ -n "$TARGET_DOMAIN" ]]; then
    TARGET="$TARGET_DOMAIN"
    INPUT_KIND=domain
  elif [[ -n "$TARGET_IP" ]]; then
    TARGET="$TARGET_IP"
    INPUT_KIND=ip
  else
    TARGET="$TARGET_URL_INPUT"
    INPUT_KIND=url
  fi
  case "$TOOL:$INPUT_KIND" in
    nmap:domain|nmap:ip|subfinder:domain|httpx:domain|httpx:ip|httpx:url|nuclei:url) ;;
    *) echo "Tool '$TOOL' does not accept target input '$INPUT_KIND'." >&2; exit 2 ;;
  esac
  python3 scripts/normalize_target.py --tool "$TOOL" --target "$TARGET" --ports "$PORTS" > "$OUT/target.json"
  HOST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["host"])' "$OUT/target.json")
  TARGET_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["url"])' "$OUT/target.json")
  TARGET_PORTS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ports"])' "$OUT/target.json")
  IPV6=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ipv6"]).lower())' "$OUT/target.json")
  DESCRIPTION="$TARGET (externally hosted project target)"
  NUCLEI_TEMPLATE='/templates/external-https-headers.yaml'
else
  PORT=8765
  TARGET_URL='http://127.0.0.1:8765'
  NUCLEI_TEMPLATE='/templates/lab-debug.yaml'
  if [[ "$LAB_TARGET" == juice-shop ]]; then
    PORT=3000
    TARGET_URL='http://127.0.0.1:3000'
    NUCLEI_TEMPLATE='/templates/lab-juice-shop.yaml'
  fi
  HOST='127.0.0.1'
  TARGET_PORTS="$PORT"
  IPV6=false
  DESCRIPTION="$TARGET_URL (application started inside this runner)"
  printf '{"host":"127.0.0.1","url":"%s","ports":"%s","ipv6":false}
' "$TARGET_URL" "$TARGET_PORTS" > "$OUT/target.json"
fi

cat > "$OUT/execution-context.txt" <<META
Repository: ${GITHUB_REPOSITORY:-local-run}
Run ID: ${GITHUB_RUN_ID:-local}
GitHub actor: ${GITHUB_ACTOR:-local}
Tool: $TOOL
Profile: $PROFILE
Target mode: $TARGET_MODE
Target: $DESCRIPTION
UTC timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Notice: Cloud runners do not provide anonymity; account and execution data may be correlated.
META

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [[ "$ip" =~ ^[0-9.]+$ ]]; then
    echo "Egress IP reported by an external service: $ip" >> "$OUT/execution-context.txt"
  else
    echo 'Egress IP: unavailable' >> "$OUT/execution-context.txt"
  fi
fi

PID=''
CONTAINER=''
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  if [[ -n "$CONTAINER" ]]; then
    docker logs "$CONTAINER" > "$OUT/target-server.log" 2>&1 || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$TARGET_MODE" == local ]]; then
  if [[ "$LAB_TARGET" == miniapp ]]; then
    echo 'Starting local demo app on 127.0.0.1:8765'
    python3 lab/app.py > "$OUT/target-server.log" 2>&1 &
    PID=$!
  else
    echo 'Starting OWASP Juice Shop on 127.0.0.1:3000'
    CONTAINER="offensive-juice-shop-$$"
    docker run -d --name "$CONTAINER" -p 127.0.0.1:3000:3000 bkimminich/juice-shop > /dev/null
  fi
  ready=false
  for attempt in {1..60}; do
    if curl -fsS --max-time 2 "$TARGET_URL" >/dev/null; then ready=true; break; fi
    sleep 2
  done
  if [[ "$ready" != true ]]; then
    echo "Local target $LAB_TARGET did not start in time" >&2
    if [[ -n "$CONTAINER" ]]; then docker logs "$CONTAINER" || true; fi
    if [[ -n "$PID" ]]; then cat "$OUT/target-server.log"; fi
    exit 1
  fi
fi

echo "Tool: $TOOL | Profile: $PROFILE | Target mode: $TARGET_MODE"
case "$TOOL" in
  nmap)
    if ! command -v nmap >/dev/null; then
      echo 'Installing Nmap from Ubuntu packages...'
      sudo apt-get update -qq && sudo apt-get install -y -qq nmap
    fi
    args=(-sT -Pn -p "$TARGET_PORTS" --max-retries 1 --host-timeout 30s -oX "$OUT/nmap.xml")
    if [[ "$IPV6" == true ]]; then args+=(-6); fi
    if [[ "$PROFILE" == detailed ]]; then args+=(-sV --version-light); fi
    timeout 55s nmap "${args[@]}" "$HOST" 2>&1 | tee "$OUT/nmap.txt"
    ;;
  subfinder)
    echo "Running passive discovery for project domain: $HOST"
    minutes=1
    if [[ "$PROFILE" == detailed ]]; then minutes=2; fi
    timeout 145s docker run --rm projectdiscovery/subfinder:latest \
      -d "$HOST" -silent -oJ -rl 2 -max-time "$minutes" 2>&1 | tee "$OUT/subfinder.jsonl"
    ;;
  httpx)
    args=(-u "$TARGET_URL" -sc -title -server -json -silent -rl 2 -timeout 5 -retries 0 -nfs)
    if [[ "$PROFILE" == detailed ]]; then args+=(-td -cl); fi
    timeout 80s docker run --rm --network host projectdiscovery/httpx:latest \
      "${args[@]}" 2>&1 | tee "$OUT/httpx.jsonl"
    ;;
  nuclei)
    timeout 90s docker run --rm --network host -v "$(pwd)/templates:/templates:ro" \
      projectdiscovery/nuclei:latest -u "$TARGET_URL" -t "$NUCLEI_TEMPLATE" \
      -jsonl -silent -duc -or -rl 2 -c 1 -timeout 5 2>&1 | tee "$OUT/nuclei.jsonl"
    ;;
esac
printf 'Execution completed at %s UTC
' "$(date -u '+%H:%M:%S')" >> "$OUT/execution-context.txt"
