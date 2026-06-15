#!/usr/bin/env bash
# SYNTRIASS Overlay — fleet management foundation. Offline-first (air-gap
# compatible): the inventory and health records are plain files that travel on
# removable media; nothing here contacts the network. Designed for 100+ nodes.
#
# Inventory is a TSV: node_id<TAB>fingerprint<TAB>profile<TAB>posture<TAB>health<TAB>last_seen
#   profile  : strategic-command | tactical-comms | legacy-migration
#   posture  : FullPqc | EncryptedFallback | FailClosed   (no plaintext posture exists)
#   health   : ok | degraded | down | unknown
#
# Subcommands:
#   init <inventory>
#   add  <inventory> <node_id> <fingerprint> <profile>
#   import-node <inventory> <node_id> <profile> <identity-export-file>
#   distribute  <inventory> <outdir>          per-profile offline policy bundles + assignment manifest
#   ingest-health <inventory> <health-file>   update a node's posture/health/last_seen
#   status <inventory> [--stale-secs N]       aggregate identity/posture/health report
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/lib.sh" ]; then . "$HERE/lib.sh"; else
  log(){ printf '[syntriass] %s\n' "$*"; }; die(){ printf '[syntriass] FATAL: %s\n' "$*" >&2; exit 1; }
fi
TAB="$(printf '\t')"
VALID_PROFILES="strategic-command tactical-comms legacy-migration"
VALID_POSTURES="FullPqc EncryptedFallback FailClosed"

is_in() { case " $2 " in *" $1 "*) return 0;; *) return 1;; esac; }

cmd="${1:-}"; shift || true
case "$cmd" in
  init)
    inv="${1:?usage: init <inventory>}"
    [ -e "$inv" ] && die "$inv exists"
    printf '# node_id\tfingerprint\tprofile\tposture\thealth\tlast_seen\n' > "$inv"
    log "initialised fleet inventory: $inv"
    ;;

  add)
    inv="${1:?}"; id="${2:?}"; fp="${3:?}"; prof="${4:?node_id fingerprint profile}"
    is_in "$prof" "$VALID_PROFILES" || die "bad profile '$prof' (want: $VALID_PROFILES)"
    grep -qP "^${id}\t" "$inv" 2>/dev/null && die "node '$id' already present"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$fp" "$prof" "unknown" "unknown" "0" >> "$inv"
    log "added node $id ($prof, fp=$fp)"
    ;;

  import-node)
    inv="${1:?}"; id="${2:?}"; prof="${3:?}"; exp="${4:?node_id profile export-file}"
    [ -f "$exp" ] || die "no such export: $exp"
    fp="$(sed -n 's/^fingerprint=//p' "$exp" | head -1)"
    [ -n "$fp" ] || die "$exp has no fingerprint (not an identity export?)"
    "$0" add "$inv" "$id" "$fp" "$prof"
    ;;

  distribute)
    inv="${1:?}"; out="${2:?usage: distribute <inventory> <outdir>}"
    mkdir -p "$out"
    # one offline policy bundle per profile actually used, + a per-node assignment manifest
    : > "$out/assignments.tsv"
    used=""
    while IFS="$TAB" read -r id fp prof posture health seen; do
      case "$id" in '#'*|'') continue;; esac
      is_in "$prof" "$used" || used="$used $prof"
      printf '%s\t%s\t%s\n' "$id" "$fp" "$prof" >> "$out/assignments.tsv"
    done < "$inv"
    for prof in $used; do
      case "$prof" in
        strategic-command|tactical-comms) suite=nist768;;
        legacy-migration) suite=nist768;;  # hybrid; legacy interop
        *) suite=nist768;;
      esac
      if [ -x "$HERE/airgap.sh" ]; then
        "$HERE/airgap.sh" make-policy-bundle "$suite" "$out/policy-${prof}.tar.gz" >/dev/null
      fi
      printf 'profile %s -> suite %s -> %s\n' "$prof" "$suite" "$out/policy-${prof}.tar.gz"
    done
    n=$(grep -c "$TAB" "$out/assignments.tsv" 2>/dev/null || echo 0)
    log "distribution prepared for $n nodes; bundles + assignments.tsv in $out (carry to nodes offline)"
    ;;

  ingest-health)
    inv="${1:?}"; hf="${2:?usage: ingest-health <inventory> <health-file>}"
    # health file lines: node_id<TAB>posture<TAB>health<TAB>epoch
    [ -f "$hf" ] || die "no such health file: $hf"
    tmp="$(mktemp)"
    cp "$inv" "$tmp"
    while IFS="$TAB" read -r id posture health epoch; do
      case "$id" in '#'*|'') continue;; esac
      is_in "$posture" "$VALID_POSTURES" || { warn "node $id bad posture '$posture' — ignoring"; continue; }
      awk -v id="$id" -v po="$posture" -v he="$health" -v ep="$epoch" 'BEGIN{FS=OFS="\t"}
        $1==id {$4=po; $5=he; $6=ep} {print}' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
    done < "$hf"
    mv "$tmp" "$inv"
    log "ingested health from $hf"
    ;;

  status)
    inv="${1:?usage: status <inventory> [--stale-secs N]}"; shift || true
    stale=86400; [ "${1:-}" = "--stale-secs" ] && stale="$2"
    now="$(date -u +%s)"
    awk -v now="$now" -v stale="$stale" 'BEGIN{FS="\t"}
      /^#/||/^$/{next}
      { total++; prof[$3]++; post[$4]++; heal[$5]++;
        if ($6+0>0 && now-$6>stale){stalecnt++} else if($6+0==0){neverseen++} }
      END{
        printf "==== SYNTRIASS fleet status (%d nodes) ====\n", total;
        printf "-- by profile --\n"; for(k in prof) printf "  %-18s %d\n", k, prof[k];
        printf "-- by posture --\n"; for(k in post) printf "  %-18s %d\n", k, post[k];
        printf "-- by health  --\n"; for(k in heal) printf "  %-18s %d\n", k, heal[k];
        printf "-- liveness --\n";
        printf "  %-18s %d\n", "never-reported", neverseen+0;
        printf "  %-18s %d (>%ds since last report)\n", "stale", stalecnt+0, stale;
        if (post["FailClosed"]+0>0) printf "  ALERT: %d node(s) FailClosed\n", post["FailClosed"];
      }' "$inv"
    ;;

  *) sed -n '2,22p' "$0"; exit 1;;
esac
