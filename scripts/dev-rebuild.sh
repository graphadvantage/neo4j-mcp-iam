#!/usr/bin/env sh
set -eu

OUT="${OUT:-bin/neo4j-iam-mcp}"
INSTALL_TO="${INSTALL_TO:-}"
INTERVAL="${INTERVAL:-2}"

checksum() {
  find . \
    \( -path './.git' -o -path './bin' -o -path './dist' -o -path './specifications' \) -prune \
    -o \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name 'manifest.json' -o -name 'Taskfile.yml' \) \
    -type f -print0 |
    sort -z |
    xargs -0 shasum |
    shasum
}

rebuild() {
  mkdir -p "$(dirname "$OUT")"
  echo "dev-rebuild: building $OUT"
  GOCACHE="${GOCACHE:-/private/tmp/neo4j-mcp-iam-go-cache}" go build -C cmd/neo4j-mcp -o "../../$OUT"

  if [ -n "$INSTALL_TO" ]; then
    echo "dev-rebuild: installing $INSTALL_TO"
    install -m 0755 "$OUT" "$INSTALL_TO"
  fi
}

last=""
while true; do
  current="$(checksum)"
  if [ "$current" != "$last" ]; then
    if rebuild; then
      last="$current"
      echo "dev-rebuild: ready"
    else
      echo "dev-rebuild: build failed; waiting for next change" >&2
    fi
  fi
  sleep "$INTERVAL"
done
