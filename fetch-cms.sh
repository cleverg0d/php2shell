#!/usr/bin/env bash
# Download and extract the REAL applications used by the coverage demo.
# The exploit chain is app-independent (it fires pre-RINIT), so these are real
# unmodified app checkouts, not stub files. Drupal is the one exception: its
# unconfigured index.php fatals, which breaks the two-request leak (see README).
# usage: ./fetch-cms.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WWW=$HERE/coverage/www
mkdir -p "$WWW"

fetch() { # name url
  local name=$1 url=$2
  echo "[+] $name"
  case "$name" in
    wordpress)
      curl -sSL -m 600 -A "Mozilla/5.0" -o /tmp/wp.tar.gz "$url"
      tar xzf /tmp/wp.tar.gz -C "$WWW"
      ;;
    joomla)
      curl -sSL -m 600 -A "Mozilla/5.0" -o /tmp/j.tar.gz "$url"
      mkdir -p "$WWW/joomla" && tar xzf /tmp/j.tar.gz -C "$WWW/joomla"
      ;;
    mediawiki)
      curl -sSL -m 900 -A "Mozilla/5.0" -o /tmp/mw.tar.gz "$url"
      tar xzf /tmp/mw.tar.gz -C "$WWW" && mv "$WWW"/mediawiki-* "$WWW/mediawiki"
      ;;
    phpbb)
      curl -sSL -m 600 -o /tmp/pb.tar.gz "$url"
      tar xzf /tmp/pb.tar.gz -C "$WWW" && mv "$WWW"/phpbb-* "$WWW/phpbb"
      [ -d "$WWW/phpbb/phpBB" ] && { mv "$WWW/phpbb/phpBB" "$WWW/phpbb_web" && rm -rf "$WWW/phpbb" && mv "$WWW/phpbb_web" "$WWW/phpbb"; }
      ;;
    drupal)
      curl -sSL -m 600 -o /tmp/dr.tar.gz "$url"
      tar xzf /tmp/dr.tar.gz -C "$WWW" && mv "$WWW"/drupal-* "$WWW/drupal"
      ;;
  esac
  [ -f "$WWW/$name/index.php" ] && echo "    ok: $name/index.php"
}

fetch wordpress "https://wordpress.org/latest.tar.gz"
fetch joomla "https://downloads.joomla.org/cms/joomla5/5-2-4/Joomla_5-2-4-Stable-Full_Package.tar.gz"
fetch mediawiki "https://releases.wikimedia.org/mediawiki/1.42/mediawiki-1.42.1.tar.gz"
fetch phpbb "https://codeload.github.com/phpbb/phpbb/tar.gz/refs/tags/release-3.3.19"
fetch drupal "https://codeload.github.com/drupal/drupal/tar.gz/refs/tags/11.4.10"

printf '<?php echo "OK\\n"; ?>\n' > "$WWW/plain/index.php"
echo "[+] done"
