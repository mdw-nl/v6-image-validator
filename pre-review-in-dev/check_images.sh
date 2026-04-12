#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KNOWN_GOOD_CSV="$SCRIPT_DIR/known_digests_from_github.csv"
KNOWN_AFFECTED_CSV="$SCRIPT_DIR/known_affected_digests.csv"

for f in "$KNOWN_GOOD_CSV" "$KNOWN_AFFECTED_CSV"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

known_good="$(awk -F, 'NR > 1 { print $4 }' "$KNOWN_GOOD_CSV" | sort -u)"
known_affected="$(awk -F, 'NR > 1 && $4 != "" && $4 != "[currently unknown]" { print $4 }' "$KNOWN_AFFECTED_CSV" | sort -u)"

cutoff="2026-01-01T00:00:00Z"
malware_targets="/usr/bin/checkAppend /usr/bin/dockerd /wrapper.sh"

safe=""
affected_and_files=""
affected_no_files=""
files_not_affected=""
unknown_2026=""
unknown_pre2026=""

image_ids="$(docker image ls -q | sort -u)"
[ -z "$image_ids" ] && { echo "No local images found."; exit 0; }

container_usage=""
_cids="$(docker ps -aq 2>/dev/null || true)"
if [ -n "$_cids" ]; then
  container_usage="$(docker inspect --format '{{.Image}} {{.State.StartedAt}}' $_cids 2>/dev/null || true)"
fi

total="$(printf '%s\n' "$image_ids" | wc -l)"
current=0

for image_id in $image_ids; do
  current=$((current + 1))

  created="$(docker image inspect --format '{{.Created}}' "$image_id" 2>/dev/null || true)"
  [ -z "$created" ] && continue

  repo_tags="$(docker image inspect --format '{{range .RepoTags}}{{println .}}{{end}}' "$image_id" 2>/dev/null || true)"
  repo_digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_id" 2>/dev/null || true)"
  [ -z "$repo_tags" ] && continue

  usage_info="never run"
  if [ -n "$container_usage" ]; then
    full_image_id="$(docker image inspect --format '{{.Id}}' "$image_id" 2>/dev/null || true)"
    _matches="$(printf '%s\n' "$container_usage" | grep "${full_image_id} " | grep -v ' 0001-01-01' || true)"
    if [ -n "$_matches" ]; then
      _last_started="$(printf '%s\n' "$_matches" | awk '{print $2}' | sort -r | head -1)"
      usage_info="last run ${_last_started%%T*}"
    fi
  fi

  is_harbor=0
  while IFS= read -r repo_tag; do
    [ -z "$repo_tag" ] && continue
    case "$repo_tag" in harbor2*) is_harbor=1; break ;; esac
  done <<< "$repo_tags"
  [ "$is_harbor" -eq 0 ] && continue

  digest=""
  if [ -n "$repo_digests" ]; then
    while IFS= read -r rd; do
      [ -z "$rd" ] && continue
      case "$rd" in harbor2*) digest="${rd#*@}"; break ;; esac
    done <<< "$repo_digests"
    if [ -z "$digest" ]; then
      digest="$(printf '%s\n' "$repo_digests" | head -1)"
      digest="${digest#*@}"
    fi
  fi

  printf '\r[%d/%d] Scanning %s ...' "$current" "$total" "$image_id" >&2

  found_files=""
  cid="$(docker create --network none "$image_id" true 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    for target in $malware_targets; do
      if docker cp "$cid:$target" - >/dev/null 2>&1; then
        if [ -n "$found_files" ]; then
          found_files="${found_files};${target}"
        else
          found_files="$target"
        fi
      fi
    done
    docker rm -f "$cid" >/dev/null 2>&1 || true
  fi

  while IFS= read -r repo_tag; do
    [ -z "$repo_tag" ] && continue
    case "$repo_tag" in
      harbor2*)
        image_name="${repo_tag%:*}"
        tag="${repo_tag##*:}"
        date_short="${created%%T*}"

        in_good=0
        in_affected=0
        has_files=0

        [ -n "$digest" ] && printf '%s\n' "$known_good" | grep -Fxq "$digest" && in_good=1
        [ -n "$digest" ] && printf '%s\n' "$known_affected" | grep -Fxq "$digest" && in_affected=1
        [ -n "$found_files" ] && has_files=1

        line="  ${image_name}:${tag}  (${digest:-no digest})  built ${date_short}  [${usage_info}]"

        if [ "$in_good" -eq 1 ]; then
          safe="${safe}${line}
"
        elif [ "$in_affected" -eq 1 ] && [ "$has_files" -eq 1 ]; then
          affected_and_files="${affected_and_files}${line}
    files: ${found_files}
"
        elif [ "$in_affected" -eq 1 ]; then
          affected_no_files="${affected_no_files}${line}
"
        elif [ "$has_files" -eq 1 ]; then
          files_not_affected="${files_not_affected}${line}
    files: ${found_files}
"
        elif [ "$created" \< "$cutoff" ]; then
          unknown_pre2026="${unknown_pre2026}${line}
"
        else
          unknown_2026="${unknown_2026}${line}
"
        fi
        ;;
    esac
  done <<< "$repo_tags"
done

printf '\r%*s\r' 80 '' >&2

echo "============================================================"
echo "           DOCKER IMAGE VALIDATION REPORT"
echo "============================================================"
echo ""

echo "--- SAFE (digest in known good list) ---"
[ -n "$safe" ] && printf '%s' "$safe" || echo "  (none)"
echo ""

echo "--- KNOWN AFFECTED + MALWARE FILES FOUND ---"
[ -n "$affected_and_files" ] && printf '%s' "$affected_and_files" || echo "  (none)"
echo ""

echo "--- KNOWN AFFECTED (digest in affected list, no malware files found) ---"
[ -n "$affected_no_files" ] && printf '%s' "$affected_no_files" || echo "  (none)"
echo ""

echo "--- MALWARE FILES FOUND (digest NOT in affected list) ---"
[ -n "$files_not_affected" ] && printf '%s' "$files_not_affected" || echo "  (none)"
echo ""

echo "--- UNKNOWN (digest not in either list, built 2026+) ---"
[ -n "$unknown_2026" ] && printf '%s' "$unknown_2026" || echo "  (none)"
echo ""

echo "--- UNKNOWN (built before 2026 — not expected in list) ---"
[ -n "$unknown_pre2026" ] && printf '%s' "$unknown_pre2026" || echo "  (none)"
echo ""
echo "============================================================"
echo "Done."
