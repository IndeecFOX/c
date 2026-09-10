#!/bin/sh

BASE_DIR="/opt/zator/extra_strats"          # тут же лежат TCP_*_list.txt - всё в одном месте, без tmp

RESULT_LOG="/opt/tmp/blocked_domains.log"       # чистый лог: только домен -> результат
DEBUG_LOG="/opt/tmp/blocked_domains_debug.log"  # подробности, для диагностики
RECENT_FILE="$BASE_DIR/dnscheck_recent"          # недавно проверенные домены (анти-дубль)
DOWN_FILE="/tmp/dnscheck_api_down"          # метка "API лежит до такого-то времени" - недолговечная, tmp норм
RESP1_FILE="/tmp/dnscheck_resp1.json"       # тело ответа шага 1 (check) - одноразовое, tmp норм
RESP2_FILE="/tmp/dnscheck_resp2.txt"        # тело ответа шага 2 (probe) - одноразовое, tmp норм
SUCCESS_TTL=864000                           # сек — успешный результат не перепроверяем секунд (864000 = 10 суток)
FAIL_COOLDOWN=3                             # сек — после ошибки (500/000/и т.п.) ждём совсем недолго
DOWN_COOLDOWN=3                            # сек — пауза после ошибки API
RETRY_MAX_ATTEMPTS=3                        # сколько раз пробовать один шаг, пока не 500/000
RETRY_DELAY=3                               # сек между попытками
CHECHECK_LIST="$BASE_DIR/TCP_Custom.txt"      # сюда копим домены с вердиктом sni_block/tspu_block/cdn_block
SKIP_WL_LIST="$BASE_DIR/skip_wl.txt"        # готовые whitelist-ответы, тоже скипаем; сюда же копим новые whitelist
SKIP_LISTS="$BASE_DIR/TCP_RKN_list.txt $BASE_DIR/TCP_YT_list.txt $BASE_DIR/TCP_Discord.txt $BASE_DIR/TCP_Custom.txt $CHECHECK_LIST $SKIP_WL_LIST"
SKIP_RU_DOMAINS=1                           # 1 - не проверять .ru домены вообще (по умолчанию), 0 - проверять как обычно
ENABLE_RESULT_LOG=0                         # 1 - писать в blocked_domains.log (по умолчанию), 0 - выключить лог совсем
DEBUG=0                                     # 1 - писать подробности в DEBUG_LOG

dbg() {
    [ "$DEBUG" = "1" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEBUG_LOG"
}

log_result() {
    [ "$ENABLE_RESULT_LOG" = "1" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$RESULT_LOG"
}

# Одноразовая нормализация файлов списков: убирает \r (Windows-переносы),
# приводит к нижнему регистру, обрезает пробелы и краевые точки, убирает
# пустые строки и дубли. Запускать вручную после правки списков руками:
#   /opt/etc/dns_check.sh normalize
# После этого рантайм-проверка (in_skip_lists) остаётся простым grep,
# без какой-либо обработки текста на каждый DNS-запрос.
normalize_skip_lists() {
    for f in $SKIP_LISTS; do
        [ -f "$f" ] || continue
        tmp="${f}.normtmp"
        tr -d '\r' < "$f" | tr 'A-Z' 'a-z' | sed 's/^[ \t]*//;s/[ \t]*$//;s/^\.*//;s/\.*$//' | grep -v '^$' | sort -u > "$tmp"
        mv "$tmp" "$f"
        echo "Нормализован: $f ($(wc -l < "$f") строк)"
    done
}

if [ "$1" = "normalize" ]; then
    normalize_skip_lists
    exit 0
fi

# Проверяет домен (и его родительские домены) по всем файлам из SKIP_LISTS.
# example.sub.ru совпадёт и с "example.sub.ru", и с "sub.ru", и с "ru".
# При совпадении печатает путь к файлу, где нашлось, в stdout.
# ВАЖНО: файлы списков должны быть заранее нормализованы (без \r, в нижнем
# регистре, без краевых точек/пробелов) - см. normalize_skip_lists() ниже,
# запускается один раз вручную. Наши собственные дописывания в checheck.txt/
# skip_wl.txt и так уже чистые (домен из tcpdump), поэтому рантайм-проверка -
# это просто grep без какой-либо обработки текста, дёшево по CPU.
in_skip_lists() {
    d0="$1"
    for f in $SKIP_LISTS; do
        [ -f "$f" ] || continue
        d="$d0"
        while [ -n "$d" ]; do
            if grep -qxF "$d" "$f" 2>/dev/null; then
                echo "$f"
                return 0
            fi
            case "$d" in
                *.*) d="${d#*.}" ;;
                *) break ;;
            esac
        done
    done
    return 1
}

# Дёргает URL, пока не получит HTTP 200 (или пока не кончатся попытки).
# $1 - url, $2 - файл для тела ответа. Печатает итоговый http_code в stdout.
# Возврат: 0 - успех (200), 2 - 404 (домен не найден, ретраить бессмысленно),
# 1 - так и не дождались 200 за все попытки.
fetch_retry() {
    url="$1"
    outfile="$2"
    attempt=1
    while [ "$attempt" -le "$RETRY_MAX_ATTEMPTS" ]; do
        code=$(/opt/bin/curl -s -o "$outfile" --max-time 8 -w "%{http_code}" "$url")
        if [ "$code" = "200" ] && [ -s "$outfile" ]; then
            echo "$code"
            return 0
        fi
        if [ "$code" = "404" ]; then
            echo "$code"
            return 2
        fi
        dbg "HTTP $code (попытка $attempt/$RETRY_MAX_ATTEMPTS), повтор через ${RETRY_DELAY}с: $url"
        attempt=$((attempt + 1))
        [ "$attempt" -le "$RETRY_MAX_ATTEMPTS" ] && sleep "$RETRY_DELAY"
    done
    echo "$code"
    return 1
}

mkdir -p "$BASE_DIR" 2>/dev/null
mkdir -p "$(dirname "$RESULT_LOG")" 2>/dev/null
[ -f "$RECENT_FILE" ] || : > "$RECENT_FILE" 2>/dev/null

killall tcpdump 2>/dev/null

log_result "Демон запущен"

/opt/bin/tcpdump -i lo -nn -l "udp port 53" 2>/dev/null | while read -r line; do

    case "$line" in
        *" A? "*)

            # Извлекаем домен
            domain=""
            set -- $line
            while [ $# -gt 0 ]; do
                if [ "$1" = "A?" ]; then
                    domain="$2"
                    break
                fi
                shift
            done

            domain=$(echo "$domain" | sed 's/\.$//' | tr 'A-Z' 'a-z')

            # Игнорируем пустые строки, локальный мусор, запросы к самому cheburcheck
            # и googlevideo.com с любыми поддоменами (CDN видео, смысла проверять нет)
            if [ -z "$domain" ] || [ "$domain" = "retracker.local" ] || [ "$domain" = "cheburcheck.ru" ] || echo "$domain" | grep -qE "\.(lan|local|home)$|(^|\.)googlevideo\.com$"; then
                continue
            fi

            # Флаг: не проверять .ru домены вообще (по умолчанию включено)
            if [ "$SKIP_RU_DOMAINS" = "1" ] && echo "$domain" | grep -qE "\.ru$"; then
                log_result "$domain -> SKIP (.ru, флаг SKIP_RU_DOMAINS)"
                continue
            fi

            # Домен уже есть в одном из локальных списков - смысла дёргать API нет, скипаем
            skip_list=$(in_skip_lists "$domain")
            if [ -n "$skip_list" ]; then
                log_result "$domain -> SKIP (список: $(basename "$skip_list"))"
                continue
            fi

            now=$(date '+%s')

            # Анти-дубль: успешный результат не перепроверяем SUCCESS_TTL (сутки),
            # результат с ошибкой (500/000/и т.п.) держим в кеше только FAIL_COOLDOWN (3с) -
            # чтобы не долбить упавший API, но и не тормозить ретрай, когда он поднимется.
            # Запись статуса делаем ПОСЛЕ фактической проверки (см. record_status ниже),
            # тут только чистим протухшие записи и смотрим, есть ли живая запись по домену.
            : > "${RECENT_FILE}.tmp"
            skip=0
            skip_status=""
            skip_ts=""
            while read -r ts st d; do
                [ -z "$ts" ] && continue
                valid=0
                if [ "$st" = "ok" ] && [ $((now - ts)) -lt "$SUCCESS_TTL" ]; then
                    valid=1
                elif [ "$st" = "err" ] && [ $((now - ts)) -lt "$FAIL_COOLDOWN" ]; then
                    valid=1
                fi
                if [ "$valid" -eq 1 ]; then
                    echo "$ts $st $d" >> "${RECENT_FILE}.tmp"
                    if [ "$d" = "$domain" ]; then
                        skip=1
                        skip_status="$st"
                        skip_ts="$ts"
                    fi
                fi
            done < "$RECENT_FILE"
            mv "${RECENT_FILE}.tmp" "$RECENT_FILE"
            if [ "$skip" -eq 1 ]; then
                if [ "$skip_status" = "ok" ]; then
                    left=$((SUCCESS_TTL - (now - skip_ts)))
                else
                    left=$((FAIL_COOLDOWN - (now - skip_ts)))
                fi
                log_result "$domain -> SKIP (TTL кэш: $skip_status, ещё ${left}с)"
                continue
            fi

            # Circuit breaker: если недавно API уже отвечал ошибкой - не долбим его,
            # молча пропускаем домен до истечения паузы
            if [ -f "$DOWN_FILE" ]; then
                down_until=$(cat "$DOWN_FILE" 2>/dev/null)
                if [ -n "$down_until" ] && [ "$now" -lt "$down_until" ]; then
                    continue
                fi
            fi

            dbg "Проверяем через API: $domain"

            # ШАГ 1: /api/v1/check?target=<домен> -> получаем ID (с ретраями до 200)
            http_code=$(fetch_retry "https://cheburcheck.ru/api/v1/check?target=${domain}" "$RESP1_FILE")
            step1_ok=$?
            response=$(cat "$RESP1_FILE" 2>/dev/null)
            dbg "Ответ API1 (HTTP $http_code): $response"

            if [ "$step1_ok" -eq 2 ]; then
                log_result "$domain -> SKIP (404, не найден)"
                echo "$now ok $domain" >> "$RECENT_FILE"
                continue
            fi

            if [ "$step1_ok" -ne 0 ]; then
                log_result "$domain -> ERROR (HTTP ${http_code:-000})"
                echo "$now err $domain" >> "$RECENT_FILE"
                echo $((now + DOWN_COOLDOWN)) > "$DOWN_FILE"
                continue
            fi
            rm -f "$DOWN_FILE"

            check_id=$(echo "$response" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
            dbg "Получен ID: $check_id"

            if [ -z "$check_id" ]; then
                log_result "$domain -> ERROR (no id in response)"
                echo "$now err $domain" >> "$RECENT_FILE"
                continue
            fi

            sleep 2

            # ШАГ 2: /api/v1/probe/<id> -> SSE-поток (с ретраями до 200)
            http_code2=$(fetch_retry "https://cheburcheck.ru/api/v1/probe/${check_id}" "$RESP2_FILE")
            step2_ok=$?
            probe_data=$(cat "$RESP2_FILE" 2>/dev/null)
            dbg "Данные API2 (HTTP $http_code2): $probe_data"

            if [ "$step2_ok" -eq 2 ]; then
                log_result "$domain -> SKIP (404, не найден)"
                echo "$now ok $domain" >> "$RECENT_FILE"
                continue
            fi

            if [ "$step2_ok" -ne 0 ]; then
                log_result "$domain -> ERROR (probe HTTP ${http_code2:-000})"
                echo "$now err $domain" >> "$RECENT_FILE"
                echo $((now + DOWN_COOLDOWN)) > "$DOWN_FILE"
                continue
            fi

            # Достаём data-строки, идущие сразу за "event:result", и берём из них verdicts
            verdict=$(printf '%s\n' "$probe_data" \
                | awk '/^event:result/ { getline; if ($0 ~ /^data:/) print }' \
                | sed -n 's/.*"verdicts":\[\(.*\)\].*/\1/p' \
                | tr ',' '\n' \
                | tr -d '"' \
                | sed 's/^[ \t]*//;s/[ \t]*$//' \
                | sort -u \
                | tr '\n' ',' \
                | sed 's/,$//')

            [ -z "$verdict" ] && verdict="unknown"

            log_result "$domain -> $verdict"
            echo "$now ok $domain" >> "$RECENT_FILE"

            # Приоритет: если в вердикте есть whitelist - домен считаем доступным
            # и кладём ТОЛЬКО в SKIP_WL_LIST, даже если рядом затесался sni_block/
            # tspu_block/cdn_block (например "tspu_block,whitelist" - это whitelist).
            # Иначе, если есть один из блокирующих вердиктов - кладём в CHECHECK_LIST.
            if printf '%s\n' "$verdict" | tr ',' '\n' | grep -qx "whitelist"; then
                if ! grep -qxF "$domain" "$SKIP_WL_LIST" 2>/dev/null; then
                    echo "$domain" >> "$SKIP_WL_LIST"
                    dbg "Добавлен в $SKIP_WL_LIST: $domain"
                fi
            elif printf '%s\n' "$verdict" | tr ',' '\n' | grep -qxE "sni_block|tspu_block|cdn_block"; then
                if ! grep -qxF "$domain" "$CHECHECK_LIST" 2>/dev/null; then
                    echo "$domain" >> "$CHECHECK_LIST"
                    dbg "Добавлен в $CHECHECK_LIST: $domain"
                fi
            fi
            ;;
    esac
done
