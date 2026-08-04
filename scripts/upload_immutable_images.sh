#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <bucket> <language-prefix>" >&2
  exit 2
fi

bucket="$1"
prefix="${2#/}"
prefix="${prefix%/}"
cache_control="public,max-age=31536000,immutable"

for image in \
  hacktricks-summer-discount-2026-v1.webp \
  arte-badge-v1.webp \
  grte-badge-v1.webp \
  azrte-badge-v1.webp; do
  source_path="./book/images/${image}"
  if [ ! -f "$source_path" ]; then
    echo "Missing immutable image: $source_path" >&2
    exit 1
  fi
  aws s3 cp "$source_path" "s3://${bucket}/${prefix}/images/${image}" \
    --only-show-errors \
    --content-type image/webp \
    --cache-control "$cache_control"
done
