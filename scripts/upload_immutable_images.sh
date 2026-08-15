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
  key="${prefix}/images/${image}"
  local_etag="\"$(md5sum "$source_path" | cut -d' ' -f1)\""
  remote_state="$(aws s3api head-object \
    --bucket "$bucket" \
    --key "$key" \
    --query '[ETag,CacheControl,ContentType]' \
    --output text 2>/dev/null || true)"
  read -r remote_etag remote_cache_control remote_content_type <<< "$remote_state"
  if [ "$remote_etag" = "$local_etag" ] \
    && [ "$remote_cache_control" = "$cache_control" ] \
    && [ "$remote_content_type" = "image/webp" ]; then
    echo "Immutable image already current: $key"
    continue
  fi
  aws s3 cp "$source_path" "s3://${bucket}/${key}" \
    --only-show-errors \
    --content-type image/webp \
    --cache-control "$cache_control"
done
