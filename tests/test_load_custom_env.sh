#!/bin/sh
# Standalone test for the custom_env.ini parser. Verifies:
#   1. legitimate KEY="value" lines are exported
#   2. injection attempts are rejected (no shell evaluation)
#   3. unknown keys are silently dropped (with log)
#   4. format errors (no =, no quotes, bad chars) are rejected
#
# Run with: sh tests/test_load_custom_env.sh
#
# This script reproduces load_custom_env verbatim from src/init.sh so a
# failure points to the right place. If you change one, change both.

set -u
# Disable strict mode while running expect_check (the check itself does
# not need pipefail / errexit and we want clean failure reporting).
test_check() {
    set +u
    ( eval "$1" )
}

PASS=0
FAIL=0

# Counters
# `set` in sh prints each variable on two lines (one single-quoted, one
# double-quoted), so we filter to the single-quoted form to get a true
# unique count.
count_env() {
    env | grep -E "^CNAUTO=|^IPV6=|^CNFALL=|^CN_TRACKER=|^USE_HOSTS=|^USE_MARK_DATA=|^ADDINFO=|^SHUFFLE=|^HTTP_FILE=|^SAFEMODE=|^EXPIRED_FLUSH=|^AUTO_FORWARD=|^AUTO_FORWARD_CHECK=|^SOCKS5=|^SERVER_IP=|^CUSTOM_FORWARD=|^DNSPORT=|^RULES_TTL=|^CUSTOM_FORWARD_TTL=|^QUERY_TIME=|^UPDATE=|^DNS_SERVERNAME=|^TZ=|^DEVLOG=" | wc -l
}

reset_env() {
    # Wipe any parser-set env vars. Use env -i to start from a clean slate
    # so the next test's count is accurate.
    for v in CNAUTO IPV6 CNFALL CN_TRACKER USE_HOSTS USE_MARK_DATA ADDINFO \
             SHUFFLE HTTP_FILE SAFEMODE EXPIRED_FLUSH AUTO_FORWARD \
             AUTO_FORWARD_CHECK SOCKS5 SERVER_IP CUSTOM_FORWARD DNSPORT \
             RULES_TTL CUSTOM_FORWARD_TTL QUERY_TIME UPDATE DNS_SERVERNAME \
             TZ DEVLOG; do
        unset "$v" 2>/dev/null || true
    done
}

run_case() {
    desc=$1
    ini_content=$2
    expect_count=$3
    expect_check=$4  # shell snippet that exits 0 if expectations met
    expect_log=$5    # substring that must (or must not, with !) appear in log

    reset_env
    : >/tmp/env_custom_parse.log
    tmp=$(mktemp)
    printf '%s\n' "$ini_content" >"$tmp"

    # Inline the parser with the path pointing to the temp file.
    # NB: we use INPUTFILE as a placeholder rather than literally writing
    # </data/custom_env.ini in the heredoc, because that line would be
    # interpreted as a stdin redirect by bash and stripped from the file.
    sed "s|INPUTFILE|$tmp|g" /dev/stdin >/tmp/parser.sh <<'PARSER'
#!/bin/sh
load_custom_env() {
    : >/tmp/env_custom_parse.log
    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line=${raw_line#"${raw_line%%[![:space:]]*}"}
        case "$line" in
            ""|\#*) continue ;;
        esac
        case "$line" in
            *=*) key=${line%%=*}; value=${line#*=} ;;
            *)   echo "REJECT (no '='): $line" >>/tmp/env_custom_parse.log; continue ;;
        esac
        case "$key" in
            ''|*[!A-Z0-9_]*)
                echo "REJECT (bad key): $key" >>/tmp/env_custom_parse.log
                continue
                ;;
        esac
        case "$value" in
            \"*\") value=${value#\"}; value=${value%\"} ;;
        esac
        case "$key" in
            CNAUTO|IPV6|CNFALL|CN_TRACKER|USE_HOSTS|USE_MARK_DATA|ADDINFO|\
SHUFFLE|HTTP_FILE|SAFEMODE|EXPIRED_FLUSH|AUTO_FORWARD|\
AUTO_FORWARD_CHECK)
                case "$value" in
                    yes|no|lite|trnc|only6|yes_only6|"") ;;
                    *) echo "REJECT (bad $key): $value" >>/tmp/env_custom_parse.log; continue ;;
                esac
                ;;
            SOCKS5|SERVER_IP|CUSTOM_FORWARD)
                case "$value" in
                    *[!A-Za-z0-9._\[\]@:\-]*)
                        echo "REJECT (bad $key chars): $value" >>/tmp/env_custom_parse.log
                        continue
                        ;;
                esac
                ;;
            DNSPORT|RULES_TTL|CUSTOM_FORWARD_TTL)
                case "$value" in
                    ''|*[!0-9]*)
                        echo "REJECT (bad $key): $value" >>/tmp/env_custom_parse.log
                        continue
                        ;;
                esac
                ;;
            QUERY_TIME)
                case "$value" in
                    ''|*[!0-9ms]*)
                        echo "REJECT (bad $key): $value" >>/tmp/env_custom_parse.log
                        continue
                        ;;
                esac
                ;;
            UPDATE)
                case "$value" in
                    daily|weekly|monthly|no|"") ;;
                    *) echo "REJECT (bad $key): $value" >>/tmp/env_custom_parse.log; continue ;;
                esac
                ;;
            DNS_SERVERNAME|TZ|DEVLOG)
                case "$value" in
                    *[\$\`\\\"\'\(\)\{\}\[\]\;\&\|\<\>\*]*)
                        echo "REJECT (bad $key metachar): $value" >>/tmp/env_custom_parse.log
                        continue
                        ;;
                esac
                ;;
            *)
                echo "REJECT (unknown key): $key" >>/tmp/env_custom_parse.log
                continue
                ;;
        esac
        export "$key=$value"
    done < INPUTFILE
}
PARSER
    . /tmp/parser.sh
    load_custom_env

    got=$(count_env)
    log_content=$(cat /tmp/env_custom_parse.log)
    rm -f "$tmp" /tmp/parser.sh /tmp/parser2.sh

    ok=1
    [ "$got" = "$expect_count" ] || ok=0
    if [ -n "$expect_check" ]; then
        ( set +u; eval "$expect_check" ) || ok=0
    fi
    if [ -n "$expect_log" ]; then
        case "$expect_log" in
            "!"*) needle=${expect_log#!}; case "$log_content" in *"$needle"*) ok=0 ;; esac ;;
            *)   case "$log_content" in *"$expect_log"*) ;; *) ok=0 ;; esac ;;
        esac
    fi

    if [ "$ok" = "1" ]; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc"
        echo "  got count=$got want=$expect_count"
        echo "  log: $log_content"
        FAIL=$((FAIL + 1))
    fi
    reset_env
}

# Case 1: legitimate values pass through
run_case "legit CNAUTO=yes" \
    'CNAUTO="yes"' \
    "1" \
    '[ "$CNAUTO" = "yes" ]' \
    ""

run_case "legit SOCKS5 with credentials" \
    'SOCKS5="user:pass@1.2.3.4:1080"' \
    "1" \
    '[ "$SOCKS5" = "user:pass@1.2.3.4:1080" ]' \
    ""

run_case "legit DNSPORT=5353" \
    'DNSPORT="5353"' \
    "1" \
    '[ "$DNSPORT" = "5353" ]' \
    ""

run_case "legit CUSTOM_FORWARD IPv6" \
    'CUSTOM_FORWARD="[2606:4700:4700::1111]:53"' \
    "1" \
    '[ "$CUSTOM_FORWARD" = "[2606:4700:4700::1111]:53" ]' \
    ""

run_case "legit QUERY_TIME=2000ms" \
    'QUERY_TIME="2000ms"' \
    "1" \
    '[ "$QUERY_TIME" = "2000ms" ]' \
    ""

run_case "legit UPDATE=weekly" \
    'UPDATE="weekly"' \
    "1" \
    '[ "$UPDATE" = "weekly" ]' \
    ""

# Case 2: injection attempts must be REJECTED
run_case "injection: shell metachar in SHUFFLE" \
    'SHUFFLE="yes\"; rm -rf / #"' \
    "0" \
    "" \
    "REJECT (bad SHUFFLE"

run_case "injection: command subst in SOCKS5" \
    'SOCKS5="1.2.3.4:53\`whoami\`"' \
    "0" \
    "" \
    "REJECT (bad SOCKS5 chars)"

run_case "injection: bad DNSPORT (non-digit)" \
    'DNSPORT="53; ls"' \
    "0" \
    "" \
    "REJECT (bad DNSPORT)"

run_case "injection: unknown key" \
    'EVIL_KEY="rm -rf /"' \
    "0" \
    "" \
    "REJECT (unknown key)"

run_case "injection: lowercase key (whitelist is uppercase only)" \
    'cnauto="yes"' \
    "0" \
    "" \
    "REJECT (bad key)"

run_case "injection: missing =" \
    'CNAUTO "yes"' \
    "0" \
    "" \
    "REJECT (no '=')"

run_case "injection: bad IPV6 value (not in enum)" \
    'IPV6="v6only"' \
    "0" \
    "" \
    "REJECT (bad IPV6)"

# Case 3: comments and blank lines are skipped silently
run_case "comments and blank lines ignored" \
    '# this is a comment
CNAUTO="yes"

# another comment
IPV6="no"' \
    "2" \
    '[ "$CNAUTO" = "yes" ] && [ "$IPV6" = "no" ]' \
    ""

# Case 4: a hostile mix
run_case "hostile mix: legit + 3 attacks" \
    'CNAUTO="yes"
EVIL=";rm -rf /"
SOCKS5="1.2.3.4:53;ls"
SERVER_IP="not.an.ip;cat /etc/passwd"' \
    "1" \
    '[ "$CNAUTO" = "yes" ]' \
    "REJECT"

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" = "0" ]
