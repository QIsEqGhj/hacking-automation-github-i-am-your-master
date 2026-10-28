#!/usr/bin/env bash
set -Eeuo pipefail

TOOL="${TOOL:-nmap}"
PROFILE="${PROFILE:-quick}"
TARGET_MODE="${TARGET_MODE:-local}"
LAB_TARGET="${LAB_TARGET:-miniapp}"
TARGET_DOMAIN="${TARGET_DOMAIN:-}"
TARGET_IP="${TARGET_IP:-}"
TARGET_URL_INPUT="${TARGET_URL:-}"
INPUT_KIND=local
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
echo "Target: $DESCRIPTION"
echo 'Starting connectivity preflight (diagnostic only; not a scan result)...'
python3 scripts/preflight.py --host "$HOST" --url "$TARGET_URL" --tool "$TOOL" --output "$OUT/preflight.json" | tee "$OUT/preflight.log"

# Keep stdout/stderr separate from machine-readable JSONL results. The tool's
# real exit code and elapsed time are recorded even when its result file is empty.
: > "$OUT/tool.log"
RUN_STATUS=0
RUN_SECONDS=0
run_logged() {
  local started=$SECONDS
  printf 'Executing:' | tee -a "$OUT/tool.log"
  printf ' %q' "$@" | tee -a "$OUT/tool.log"
  printf '\n' | tee -a "$OUT/tool.log"
  set +e
  "$@" 2>&1 | tee -a "$OUT/tool.log"
  RUN_STATUS=${PIPESTATUS[0]}
  set -e
  RUN_SECONDS=$((SECONDS-started))
  echo "Command exit code: $RUN_STATUS; elapsed: ${RUN_SECONDS}s" | tee -a "$OUT/tool.log"
}

case "$TOOL" in
  nmap)
    if ! command -v nmap >/dev/null; then
      echo 'Installing Nmap from Ubuntu packages...'
      sudo apt-get update -qq && sudo apt-get install -y -qq nmap
    fi
    nmap --version | head -n 2 | tee -a "$OUT/tool.log"
    args=(-sT -Pn -p "$TARGET_PORTS" --max-retries 2 --host-timeout 90s -v
          -oX "$OUT/nmap.xml" -oN "$OUT/nmap.txt")
    if [[ "$IPV6" == true ]]; then args+=(-6); fi
    if [[ "$PROFILE" == detailed ]]; then args+=(-sV --version-light); fi
    run_logged timeout 130s nmap "${args[@]}" "$HOST"
    ;;
  subfinder)
    echo "Passive discovery: $HOST. Empty output can be valid when public sources contain no entries." | tee -a "$OUT/tool.log"
    minutes=2
    if [[ "$PROFILE" == detailed ]]; then minutes=3; fi
    # Mount result directory so JSONL is written by Subfinder itself, not parsed from logs.
    run_logged timeout 215s docker run --rm -v "$OUT:/results" projectdiscovery/subfinder:latest \
      -d "$HOST" -oJ -o /results/subfinder.jsonl -v -rl 5 -max-time "$minutes" -duc
    ;;
  httpx)
    # For domains/IPs allow httpx's normal HTTPS-to-HTTP fallback. For explicit
    # URLs, preserve the requested protocol. This fixes silent missing results.
    HTTPX_INPUT="$TARGET_URL"
    args=(-u "$HTTPX_INPUT" -sc -title -server -location -cl -json -rl 3 -timeout 8 -retries 1 -nc)
    if [[ "$TARGET_MODE" == external && "$INPUT_KIND" != url ]]; then
      HTTPX_INPUT="$HOST"
      args=(-u "$HTTPX_INPUT" -sc -title -server -location -cl -json -rl 3 -timeout 8 -retries 1 -nc)
    else
      args+=(-nfs)
    fi
    if [[ "$PROFILE" == detailed ]]; then args+=(-td); fi
    args+=(-o /results/httpx.jsonl)
    run_logged timeout 100s docker run --rm --network host -v "$OUT:/results" \
      projectdiscovery/httpx:latest "${args[@]}"
    ;;
  nuclei)
    templates=( -t "$NUCLEI_TEMPLATE" )
    if [[ "$TARGET_MODE" == external ]]; then
      # A positive HTTP response is useful evidence even when no header issue is found.
      templates+=( -t /templates/external-https-response.yaml )
    fi
    run_logged timeout 130s docker run --rm --network host -v "$(pwd)/templates:/templates:ro" -v "$OUT:/results" \
      projectdiscovery/nuclei:latest -u "$TARGET_URL" "${templates[@]}" \
      -jsonl -o /results/nuclei.jsonl -nc -duc -or -rl 2 -c 1 -timeout 8
    ;;
esac

export RUN_STATUS RUN_SECONDS
python3 - "$OUT/tool-execution.json" "$TOOL" "$PROFILE" "$TARGET_MODE" <<'PY_RUNTIME'
import json, os, pathlib, sys
from datetime import datetime, timezone
path, tool, profile, mode = sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
    'tool': tool, 'profile': profile, 'target_mode': mode,
    'exit_code': int(os.environ['RUN_STATUS']),
    'elapsed_seconds': int(os.environ['RUN_SECONDS']),
    'completed_at_utc': datetime.now(timezone.utc).isoformat(),
}, indent=2) + '\n')
PY_RUNTIME
if [[ "$RUN_STATUS" -ne 0 ]]; then
  echo "ERROR: $TOOL exited with code $RUN_STATUS. Inspect tool.log, preflight.json and GitHub job logs." >&2
  exit "$RUN_STATUS"
fi
printf 'Execution completed at %s UTC\n' "$(date -u '+%H:%M:%S')" >> "$OUT/execution-context.txt"
