#!/bin/sh
# Uploads every dataset that changed since its last upload to the `data` release of
# tn3w/opendata. Run by opendata-publish.service.
set -eu
export GH_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/github")"
export GH_CONFIG_DIR="$STATE_DIRECTORY/gh"
public=/srv/www/data.tn3w.dev
cd "$STATE_DIRECTORY"

publish() {
    source=$public/$1
    name=$2
    [ -f "$source" ] && [ "$source" -nt "$name.sent" ] || return 0
    ln -sf "$source" "$name"
    gh release upload data "$name" --clobber --repo tn3w/opendata
    touch -r "$source" "$name.sent"
}

publish abuse/ips.txt abuse.txt
publish abuse/ips.json abuse.json
publish crawlers/ips.txt crawlers.txt
publish crawlers/ips.json crawlers.json
publish rdns/v4/all.tsv.xz rdns-v4.tsv.xz
