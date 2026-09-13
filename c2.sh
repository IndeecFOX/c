#!/bin/sh

#Наиболее интересные настройки
CDN_RECLASSIFY_ENABLED=1                    # Добавлять домены с заблокированных CDN диапазонов в TCP_custom запрета

ENABLE_RESULT_LOG=0                         # 1 - писать в blocked_domains.log (по умолчанию), 0 - выключить лог совсем
RESULT_LOG="/tmp/blocked_domains.log"       # чистый лог: только домен -> результат
LOG_MAX_BYTES=$((5 * 1024 * 1024))          # 5 МБ - порог, после которого лог обрезается
LOG_KEEP_LINES=20000                         # сколько последних строк оставить при обрезке
SUCCESS_TTL=864000                           # сек — успешный результат не перепроверяем секунд (864000 = 10 суток)
SKIP_RU_DOMAINS=1                           # 1 - не проверять .ru домены вообще (по умолчанию), 0 - проверять как обычно
BASE_DIR="/opt/zator/extra_strats"
CHECHECK_LIST="$BASE_DIR/TCP_Custom.txt"      # сюда копим домены с вердиктом sni_block/tspu_block/cdn_block
PRECHECK_ENABLED=1                          # 1 - перед cheburcheck пробовать загрузить страницу с помощью curl (по умолчанию)
PRECHECK_MIN_BYTES=34000                    # (34000) 34 КБ - если курл скачал хотя бы столько, считаем домен доступным
PRECHECK_TIMEOUT=5                          # сек - таймаут на саму предпроверку курлом

SKIP_LISTS="$BASE_DIR/TCP_RKN_list.txt $BASE_DIR/TCP_YT_list.txt $BASE_DIR/TCP_Discord.txt $BASE_DIR/TCP_Custom.txt $CHECHECK_LIST $SKIP_WL_LIST"
RECENT_FILE="$BASE_DIR/dnscheck_recent"          # недавно проверенные домены (анти-дубль) - на флеше, переживает перезагрузку
RECENT_FILE_TMP="/tmp/dnscheck_recent.tmp"       # черновик для перезаписи RECENT_FILE - в RAM, не грузит флеш на каждый чих
DOWN_FILE="/tmp/dnscheck_api_down"          # метка "API лежит до такого-то времени" - недолговечная, tmp норм
RESP1_FILE="/tmp/dnscheck_resp1.json"       # тело ответа шага 1 (check) - одноразовое, tmp норм
RESP2_FILE="/tmp/dnscheck_resp2.txt"        # тело ответа шага 2 (probe) - одноразовое, tmp норм
NXDOMAIN_TTL=3600                           # сек — для "домена нет" кэш короче (1 час): вдруг это была временная заминка резолвера
FAIL_COOLDOWN=3                             # сек — после ошибки (500/000/и т.п.) ждём совсем недолго
DOWN_COOLDOWN=3                            # сек — пауза после ошибки API
RETRY_MAX_ATTEMPTS=6                        # сколько раз пробовать один шаг, пока не 500/000
RETRY_DELAY=3                               # сек между попытками
SKIP_WL_LIST="$BASE_DIR/skip_wl.txt"        # готовые whitelist-ответы, тоже скипаем; сюда же копим новые whitelist
PRECHECK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
DEBUG=0                                     # 1 - писать подробности в DEBUG_LOG
DEBUG_LOG="/tmp/blocked_domains_debug.log"  # подробности, для диагностики

# Размер файла БЕЗ чтения всего содержимого (только метаданные) - через stat.
# Если stat недоступен (редкость на entware) - fallback на wc -c (читает файл).
file_size() {
    sz=$(stat -c%s "$1" 2>/dev/null)
    if [ -z "$sz" ]; then
        sz=$(wc -c < "$1" 2>/dev/null)
    fi
    echo "${sz:-0}"
}

# Если файл лога превысил LOG_MAX_BYTES - обрезаем до последних LOG_KEEP_LINES
# строк. tail читает весь файл, но это происходит РЕДКО (только при
# превышении порога), а не на каждую запись - основная проверка (file_size)
# дешёвая и гоняется на каждый вызов log_result/dbg без ощутимой нагрузки.
rotate_log_if_needed() {
    f="$1"
    [ -f "$f" ] || return 0
    size=$(file_size "$f")
    if [ "$size" -gt "$LOG_MAX_BYTES" ]; then
        tail -n "$LOG_KEEP_LINES" "$f" > "${f}.rotatetmp" 2>/dev/null
        mv "${f}.rotatetmp" "$f"
    fi
}

dbg() {
    [ "$DEBUG" = "1" ] || return 0
    rotate_log_if_needed "$DEBUG_LOG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEBUG_LOG"
}

log_result() {
    # $1 - маркер: "+" реально ходили в cheburcheck на этом шаге, "-" скип без API
    # $2 - текст сообщения
    [ "$ENABLE_RESULT_LOG" = "1" ] || return 0
    rotate_log_if_needed "$RESULT_LOG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1 $2" >> "$RESULT_LOG"
}

# Не логируем повторно ОДНО И ТО ЖЕ событие skip по одному домену чаще, чем
# раз в LOG_SUPPRESS_WINDOW сек - иначе пачка одинаковых DNS-запросов подряд
# (браузер часто шлёт несколько сразу) засоряет лог десятком идентичных строк.
LOG_SUPPRESS_WINDOW=5
SUPPRESS_FILE="/tmp/dnscheck_log_suppress"
should_log_skip() {
    d="$1"
    last=$(grep -m1 "^$d " "$SUPPRESS_FILE" 2>/dev/null | awk '{print $2}')
    if [ -n "$last" ] && [ $((now - last)) -lt "$LOG_SUPPRESS_WINDOW" ]; then
        return 1
    fi
    grep -v "^$d " "$SUPPRESS_FILE" 2>/dev/null > "${SUPPRESS_FILE}.tmp"
    echo "$d $now" >> "${SUPPRESS_FILE}.tmp"
    mv "${SUPPRESS_FILE}.tmp" "$SUPPRESS_FILE"
    return 0
}

# Спрашивает у ЛОКАЛЬНОГО резолвера (127.0.0.1, тот же, что уже ответил
# клиенту - обычно даёт мгновенный ответ из кеша), существует ли домен
# вообще, ДО похода в cheburcheck API. Если у домена нет DNS-записи вовсе
# - незачем ходить в API, которое всё равно никогда не ответит по
# несуществующему домену. Делаем 2 попытки с паузой - чтобы разовая заминка
# резолвера (а не реальное отсутствие домена) не была принята за NXDOMAIN.
# Возврат: 0 - домен резолвится (или не удалось выяснить - лучше перепроверить
# через API), 1 - обе попытки говорят, что домена нет.
domain_has_dns_record() {
    d="$1"
    attempt=1
    while [ "$attempt" -le 2 ]; do
        if command -v nslookup >/dev/null 2>&1; then
            out=$(nslookup "$d" 127.0.0.1 2>&1)
        elif [ -x /opt/bin/nslookup ]; then
            out=$(/opt/bin/nslookup "$d" 127.0.0.1 2>&1)
        elif command -v busybox >/dev/null 2>&1; then
            out=$(busybox nslookup "$d" 127.0.0.1 2>&1)
        else
            dbg "nslookup не найден ни в PATH, ни в /opt/bin, ни через busybox - проверку пропускаем"
            return 0
        fi
        dbg "nslookup $d (попытка $attempt): $out"
        if ! echo "$out" | grep -qiE "can't resolve|can't find|NXDOMAIN|no answer|temporary failure in name resolution"; then
            return 0
        fi
        attempt=$((attempt + 1))
        [ "$attempt" -le 2 ] && sleep 1
    done
    return 1
}

# Пробует САМИ загрузить главную страницу домена под видом браузера (curl с
# браузерным User-Agent), прежде чем идти в cheburcheck. Если удалось
# скачать хотя бы PRECHECK_MIN_BYTES байт - домен явно доступен, и смысла
# гонять его через двухшаговый cheburcheck API нет вообще. Если не удалось
# (обрыв, таймаут, слишком маленький ответ) - это НЕ означает, что домен
# заблокирован (мало ли что на самой странице) - тогда просто идём в
# cheburcheck как обычно, для точного вердикта.
domain_precheck_ok() {
    d="$1"
    size=$(/opt/bin/curl -s -o /dev/null -L -k --max-time "$PRECHECK_TIMEOUT" -A "$PRECHECK_UA" -w "%{size_download}" "https://${d}/" 2>/dev/null)
    [ -z "$size" ] && size=0
    dbg "Предпроверка $d: скачано ${size} байт (порог ${PRECHECK_MIN_BYTES})"
    [ "$size" -ge "$PRECHECK_MIN_BYTES" ]
}

# Проверяет, непустое ли поле "cdn_providers" в ответе ШАГА 1 (/api/v1/check).
# Логика подсмотрена на самой странице cheburcheck: если домен числится на
# известном CDN-диапазоне (cdn_providers непустой), точный вердикт "ok" от
# пробинга страница показывает как "CDN Блок" - "whitelist" эта подмена НЕ
# затрагивает никогда (см. xe() на странице: n === 'ok' ? 'cdn_block' : n).
response_has_cdn_providers() {
    inner=$(echo "$1" | grep -o '"cdn_providers":{[^}]*}' | sed 's/^"cdn_providers":{//; s/}$//')
    [ -n "$inner" ]
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

log_result "-" "Демон запущен"

/opt/bin/tcpdump -i br0 -nn -l "udp port 53" 2>/dev/null | while read -r line; do

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
            now=$(date '+%s')

            # Игнорируем пустые строки, локальный мусор, запросы к самому cheburcheck
            # и googlevideo.com с любыми поддоменами (CDN видео, смысла проверять нет)
            if [ -z "$domain" ] || [ "$domain" = "retracker.local" ] || [ "$domain" = "cheburcheck.ru" ] || echo "$domain" | grep -qE "\.(lan|local|home)$|(^|\.)googlevideo\.com$"; then
                continue
            fi

            # Флаг: не проверять .ru домены вообще (по умолчанию включено)
            if [ "$SKIP_RU_DOMAINS" = "1" ] && echo "$domain" | grep -qE "\.ru$"; then
                should_log_skip "$domain" && log_result "-" "$domain -> SKIP (.ru, флаг SKIP_RU_DOMAINS)"
                continue
            fi

            # Домен уже есть в одном из локальных списков - смысла дёргать API нет, скипаем
            skip_list=$(in_skip_lists "$domain")
            if [ -n "$skip_list" ]; then
                should_log_skip "$domain" && log_result "-" "$domain -> SKIP (список: $(basename "$skip_list"))"
                continue
            fi

            # Анти-дубль: успешный результат не перепроверяем SUCCESS_TTL (10 суток),
            # результат с ошибкой (500/000/и т.п.) держим в кеше только FAIL_COOLDOWN -
            # чтобы не долбить упавший API, но и не тормозить ретрай, когда он поднимется.
            # (Эскалация кулдауна больше не нужна: несуществующие домены теперь
            # отсеиваются через nslookup ДО API - см. domain_has_dns_record ниже,
            # так что до бесконечных повторных 500 просто не доходит.)
            # Черновик перезаписи - в /tmp (RAM), финальный mv на флеш - одной операцией,
            # без промежуточных построчных записей на флеш во время самого цикла чтения.
            : > "$RECENT_FILE_TMP"
            skip=0
            skip_status=""
            skip_ts=""
            while read -r ts st d; do
                [ -z "$ts" ] && continue
                valid=0
                if [ "$st" = "ok" ] && [ $((now - ts)) -lt "$SUCCESS_TTL" ]; then
                    valid=1
                elif [ "$st" = "nx" ] && [ $((now - ts)) -lt "$NXDOMAIN_TTL" ]; then
                    valid=1
                elif [ "$st" = "err" ] && [ $((now - ts)) -lt "$FAIL_COOLDOWN" ]; then
                    valid=1
                fi
                if [ "$valid" -eq 1 ]; then
                    echo "$ts $st $d" >> "$RECENT_FILE_TMP"
                    if [ "$d" = "$domain" ]; then
                        skip=1
                        skip_status="$st"
                        skip_ts="$ts"
                    fi
                fi
            done < "$RECENT_FILE"
            mv "$RECENT_FILE_TMP" "$RECENT_FILE"
            if [ "$skip" -eq 1 ]; then
                if [ "$skip_status" = "ok" ]; then
                    left=$((SUCCESS_TTL - (now - skip_ts)))
                elif [ "$skip_status" = "nx" ]; then
                    left=$((NXDOMAIN_TTL - (now - skip_ts)))
                else
                    left=$((FAIL_COOLDOWN - (now - skip_ts)))
                fi
                should_log_skip "$domain" && log_result "-" "$domain -> SKIP (TTL кэш: $skip_status, ещё ${left}с)"
                continue
            fi

            # Если у домена вообще нет DNS-записи - в API идти незачем, оно всё
            # равно бесконечно будет 500-ть по несуществующему домену. Проверяем
            # ТОЛЬКО тут (после анти-дубля), чтобы не дёргать nslookup на домены,
            # которые и так уже в TTL-кэше. Кэшируем как nx на NXDOMAIN_TTL (час,
            # короче обычного SUCCESS_TTL - на случай если это была ложная тревога).
            if ! domain_has_dns_record "$domain"; then
                should_log_skip "$domain" && log_result "-" "$domain -> SKIP (нет DNS-записи, локальный резолвер не подтвердил)"
                echo "$now nx $domain" >> "$RECENT_FILE"
                continue
            fi

            # Предпроверка: пробуем сами загрузить страницу под видом браузера.
            # Если получилось (>= PRECHECK_MIN_BYTES) - домен явно доступен,
            # в cheburcheck за этим не идём вообще.
            if [ "$PRECHECK_ENABLED" = "1" ] && domain_precheck_ok "$domain"; then
                should_log_skip "$domain" && log_result "-" "$domain -> OK (предпроверка curl, >= ${PRECHECK_MIN_BYTES} байт)"
                echo "$now ok $domain" >> "$RECENT_FILE"
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
                should_log_skip "$domain" && log_result "+" "$domain -> SKIP (404, не найден)"
                echo "$now ok $domain" >> "$RECENT_FILE"
                continue
            fi

            if [ "$step1_ok" -ne 0 ]; then
                log_result "+" "$domain -> ERROR (HTTP ${http_code:-000})"
                echo "$now err $domain" >> "$RECENT_FILE"
                echo $((now + DOWN_COOLDOWN)) > "$DOWN_FILE"
                continue
            fi
            rm -f "$DOWN_FILE"

            check_id=$(echo "$response" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
            dbg "Получен ID: $check_id"

            # Домен на известном CDN-диапазоне? Нужно для переклассификации
            # точного "ok" в "cdn_block" ниже, после получения вердикта.
            if [ "$CDN_RECLASSIFY_ENABLED" = "1" ] && response_has_cdn_providers "$response"; then
                has_cdn=1
                dbg "$domain: cdn_providers непустой - точный ok будет переклассифицирован в cdn_block"
            else
                has_cdn=0
            fi

            if [ -z "$check_id" ]; then
                log_result "+" "$domain -> ERROR (no id in response)"
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
                should_log_skip "$domain" && log_result "+" "$domain -> SKIP (404, не найден)"
                echo "$now ok $domain" >> "$RECENT_FILE"
                continue
            fi

            if [ "$step2_ok" -ne 0 ]; then
                log_result "+" "$domain -> ERROR (probe HTTP ${http_code2:-000})"
                echo "$now err $domain" >> "$RECENT_FILE"
                echo $((now + DOWN_COOLDOWN)) > "$DOWN_FILE"
                continue
            fi

            # Достаём data-строки, идущие сразу за "event:result", и берём из них verdicts.
            # Если has_cdn=1 - точное "ok" (и только "ok", "whitelist" не трогаем)
            # переклассифицируем в "cdn_block" ДО дедупликации - как на самой странице.
            verdict=$(printf '%s\n' "$probe_data" \
                | awk '/^event:result/ { getline; if ($0 ~ /^data:/) print }' \
                | sed -n 's/.*"verdicts":\[\(.*\)\].*/\1/p' \
                | tr ',' '\n' \
                | tr -d '"' \
                | sed 's/^[ \t]*//;s/[ \t]*$//' \
                | { if [ "$has_cdn" = "1" ]; then sed 's/^ok$/cdn_block/'; else cat; fi; } \
                | sort -u \
                | tr '\n' ',' \
                | sed 's/,$//')

            [ -z "$verdict" ] && verdict="unknown"

            # Исключение: cdn_block + whitelist ОДНОВРЕМЕННО - это не "домен доступен",
            # а единичный TSPU-обход на одном из проб-хостов (у него внезапно стали
            # доступны все CDN), из-за которого этот один хост дал "whitelist", пока
            # остальные видят реальный CDN-блок. В этом случае итог - именно cdn_block,
            # whitelist из финального вердикта убираем.
            if printf '%s\n' "$verdict" | tr ',' '\n' | grep -qx "cdn_block" \
               && printf '%s\n' "$verdict" | tr ',' '\n' | grep -qx "whitelist"; then
                dbg "$domain: cdn_block+whitelist одновременно - считаем исключением (TSPU-обход), итог cdn_block"
                verdict="cdn_block"
            fi

            log_result "+" "$domain -> $verdict"
            echo "$now ok $domain" >> "$RECENT_FILE"

            # Приоритет: если в вердикте есть whitelist - домен считаем доступным
            # и кладём ТОЛЬКО в SKIP_WL_LIST, даже если рядом затесался sni_block/
            # tspu_block (например "tspu_block,whitelist" - это whitelist).
            # cdn_block+whitelist сюда уже не попадёт - см. исключение выше, там
            # whitelist из вердикта убирается заранее.
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
