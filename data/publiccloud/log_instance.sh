#!/bin/bash
# Continously read the serial console from a given publiccloud instance
# Usage: ./log_instance.sh (start|stop) (EC2|AZURE|GCE) <instance_id> <host> [zone]

COMMAND=$1
PROVIDER=$2
INSTANCE_ID=$3
HOST=$4
ZONE=$5
OUTPUT_DIR=/tmp/log_instance/"$INSTANCE_ID"
LOCK=${OUTPUT_DIR}/.lock
CNT_FILE=${OUTPUT_DIR}/.cnt
PID_FILE=${OUTPUT_DIR}/pid
SSH_OPTS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KMP_MERGE="$SCRIPT_DIR/kmp_merge"

ec2_is_running()
{
    [ -f "$PID_FILE" ] || return 1
    kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

trim_crlf_edges() {
    local f="$1"

    # trim leading CR/LF
    while [ -s "$f" ]; do
        first_hex=$(head -c 1 "$f" | od -An -tx1 | tr -d ' \n')
        case "$first_hex" in
            0a|0d)
                tail -c +2 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
                ;;
            *)
                break
                ;;
        esac
    done

    # trim trailing CR/LF
    while [ -s "$f" ]; do
        last_hex=$(tail -c 1 "$f" | od -An -tx1 | tr -d ' \n')
        case "$last_hex" in
            0a|0d)
                truncate -s -1 "$f"
                ;;
            *)
                break
                ;;
        esac
    done
}

ec2_serial_snapshot_prefix="ec2-serial-snapshot"

ec2_read_serial()
{
    local cur="${OUTPUT_DIR}/ec2.cur"

    aws ec2 get-console-output \
        --instance-id "$INSTANCE_ID" \
        --latest \
        --query Output \
        --output text \
        > "$cur" 2>>"${OUTPUT_DIR}/stderr" || return 0

    local unix_timestamp
    unix_timestamp=$(date +%s)

    local debug="${OUTPUT_DIR}/${ec2_serial_snapshot_prefix}.${unix_timestamp}"

    trim_crlf_edges "$cur"
    mv "$cur" "$debug"
}

ec2_start_log()
{
    ec2_is_running && exit 2
    ( while true; do ec2_read_serial; sleep 5; done; ) &
    echo $! > "$PID_FILE"
}

ec2_merge_logs()
{
    local out="${OUTPUT_DIR}/serial.log"
    local tmp="${OUTPUT_DIR}/serial.tmp"

    ls -1 "${OUTPUT_DIR}/$ec2_serial_snapshot_prefix".* \
        | sort -t. -k3,3n > "${OUTPUT_DIR}/logs_to_merge.txt"

    # nothing to merge
    [ "$(wc -l < ${OUTPUT_DIR}/logs_to_merge.txt)" -eq 0 ] && return 0

    # start with the first snapshot
    cp "$(head -n1 ${OUTPUT_DIR}/logs_to_merge.txt)" "$out"

    # merge subsequent snapshots
    tail -n +2 "${OUTPUT_DIR}/logs_to_merge.txt" | while read -r next; do
        "$KMP_MERGE" "$out" "$next" > "$tmp"
        mv "$tmp" "$out"
    done

    # rm "${OUTPUT_DIR}/logs_to_merge.txt" "$tmp"
}

ec2_prune_logs()
{
    local threshold=40

    # collect snapshots safely
    shopt -s nullglob
    local snapshots=( "${OUTPUT_DIR}/${ec2_serial_snapshot_prefix}".* )
    shopt -u nullglob

    # nothing to do
    (( ${#snapshots[@]} < 2 )) && return 0

    # sort by timestamp
    printf '%s\n' "${snapshots[@]}" \
        | sort -t. -k3,3n > "${OUTPUT_DIR}/logs_to_prune.txt"

    # load full paths
    mapfile -t files_full < "${OUTPUT_DIR}/logs_to_prune.txt"

    # derive basenames (what ssdeep uses internally)
    local files=()
    for f in "${files_full[@]}"; do
        files+=( "$(basename "$f")" )
    done

    # generate fuzzy hashes
    ssdeep -b "${files_full[@]}" > "${OUTPUT_DIR}/hashes.ssdeep"

    # full comparison graph
    ssdeep -k "${OUTPUT_DIR}/hashes.ssdeep" \
              "${OUTPUT_DIR}/hashes.ssdeep" > "${OUTPUT_DIR}/compare.out"

    # build similarity lookup: sim[left|right] = score
    declare -A sim

    while read -r left _ right score; do
        score=${score//[()]/}
        sim["$left|$right"]=$score
        sim["$right|$left"]=$score
    done < <(awk '{print $1,$2,$3,$NF}' "${OUTPUT_DIR}/compare.out")

    # pruning pass
    local keep="${files[0]}"
    echo "KEEP   ${OUTPUT_DIR}/${keep} (baseline)"

    for ((i=1; i<${#files[@]}-1; i++)); do
        local cur="${files[i]}"
        local key="${OUTPUT_DIR}/hashes.ssdeep:${cur}|${OUTPUT_DIR}/hashes.ssdeep:${keep}"
        local score="${sim[$key]}"

        if [[ -n "$score" && "$score" -ge "$threshold" ]]; then
            echo "REMOVE ${OUTPUT_DIR}/${cur} (${score}% similar to ${keep})"
            rm -f "${OUTPUT_DIR}/${cur}"
        else
            echo "KEEP   ${OUTPUT_DIR}/${cur} (${score}% similar to ${keep})"
            keep="$cur"
        fi
    done

    echo "KEEP   ${OUTPUT_DIR}/${files[-1]} (last snapshot)"

    # cleanup (optional)
    # rm -f "${OUTPUT_DIR}/logs_to_prune.txt" \
    #       "${OUTPUT_DIR}/hashes.ssdeep" \
    #       "${OUTPUT_DIR}/compare.out"
}

ec2_dedup_logs()
{
    shopt -s nullglob
    local snapshots=( "${OUTPUT_DIR}/${ec2_serial_snapshot_prefix}".* )
    shopt -u nullglob
    declare -A seen_hashes
    for snapshot in "${snapshots[@]}"; do
        local hash
        hash=$(sha256sum "$snapshot" | awk '{print $1}')
        if [[ -n "${seen_hashes[$hash]}" ]]; then
            echo "DUPLICATE: Removing identical snapshot $snapshot"
            rm -f "$snapshot"
        else
            seen_hashes["$hash"]=1
        fi
    done
}


ec2_process_logs()
{
    ec2_dedup_logs
    ec2_prune_logs
    ec2_merge_logs
}

ec2_stop_log()
{
    ec2_is_running || return 0
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"

    ec2_process_logs
}

gce_read_serial()
{
    ( flock -w 10 -e 9 || exit 1;

        rstart=0
        tmpfile="${OUTPUT_DIR}/tmp.txt"
        ofile="${OUTPUT_DIR}/serial_port_1.log"
        errfile="${OUTPUT_DIR}/stderr"
        max_loop=42

        while [ $max_loop -gt 1 ] ; do
            max_loop=$((max_loop -1))
            [ -f "$errfile" ] &&
                rstart=$( grep -oP -- '--start=\d+' "$errfile" | grep -oP '\d+' || echo 0)

            gcloud compute instances get-serial-port-output "$INSTANCE_ID" --port 1 \
                --zone "$ZONE" --start="$rstart" > "$tmpfile" 2> "$errfile"
            grep 'WARNING:' "$errfile" >> "$ofile" || true
            newstart=$(grep -oP -- '--start=\d+' "$errfile" | grep -oP '\d+')
            if [ "$rstart" -eq "$newstart" ]; then
                rm "$tmpfile"
                break
            else
                cat "$tmpfile" >> "$ofile"
                rm "$tmpfile"
            fi
        done
    ) 9> "${LOCK}"
}

gce_is_running()
{
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(< "$PID_FILE");
        if kill -0 "$pid" > /dev/null 2>&1 ; then
            return 0;
        fi
    fi
    return 1
}

gce_start_log()
{
    gce_is_running && exit 2;
    ( while true; do gce_read_serial; sleep 30; done; ) &
    echo $! > "$PID_FILE"
}

gce_stop_log()
{
    # Use flock to wait max 60s that gce_read_serial() is ready. And kill during
    # the 30s sleep afterwards. If flock fail, just kill the bg process.
    (flock -w 60 -e 9 || exit 1
        gce_is_running && kill -9 "$(< "$PID_FILE" )"
        rm "$PID_FILE"
    ) 9> "${LOCK}"
}

azure_start_log()
{

    inc_unique_counter
    set +e
    az vm boot-diagnostics get-boot-log --ids "$INSTANCE_ID" > "${OUTPUT_DIR}/$CNT""_boot_log_start.txt" 2>&1
    set -e
    # shellcheck disable=2086
    nohup ssh $SSH_OPTS "azureuser@${HOST}" -- sudo dmesg -c -w > "${OUTPUT_DIR}/${CNT}_dmesg.log" 2>&1 &
    echo $! > "$PID_FILE"

    true;
}

azure_stop_log()
{
    read_unique_counter
    set +e
    # give some time for azure to write something
    sleep 30
    az vm boot-diagnostics get-boot-log --ids "$INSTANCE_ID" > "${OUTPUT_DIR}/$CNT""_boot_log_stop.txt" 2>&1
    set -e
    if [ -f "$PID_FILE" ]; then
      kill -9 "$(< "$PID_FILE")" || echo "Process already stopped"
      rm "$PID_FILE"
    fi
}

openstack_start_log()
{
    read_unique_counter
    set +e
    openstack server start "$INSTANCE_ID" > "${OUTPUT_DIR}/$CNT""_boot_log_start.txt" 2>&1
    set -e
}

openstack_stop_log()
{
    read_unique_counter
    set +e
    openstack server stop "$INSTANCE_ID" > "${OUTPUT_DIR}/$CNT""_boot_log_start.txt" 2>&1
    set -e
}

read_unique_counter()
{
    CNT=$(printf "%03d" "$(cat "$CNT_FILE" 2> /dev/null)")
}

inc_unique_counter()
{
    if [ -f "$CNT_FILE" ]; then
        CNT=$(( $(cat "$CNT_FILE") + 1 ))
        echo $CNT > "$CNT_FILE"
        CNT=$(printf "%03d" "$CNT")
    else
        CNT="000"
        echo 0 > "$CNT_FILE"
    fi
}

error() {
    local parent_lineno=$1
    local code=${2:-1}
    echo "Error on line ${parent_lineno}"
    exit "${code}"
}

trap 'error ${LINENO}' ERR
set -e

if [ $# -lt 4 ]; then
    echo  "$0 (start|stop) (EC2|AZURE|GCE) <instance_id> <host> [zone]"
    exit 2;
fi
mkdir -p "$OUTPUT_DIR"

case $PROVIDER in
    EC2)
        ec2_"${COMMAND}"_log
        ;;
    AZURE|Azure)
        azure_"${COMMAND}"_log
        ;;
    GCE)
        gce_"${COMMAND}"_log
        ;;
    OPENSTACK)
        openstack_"${COMMAND}"_log
        ;;
    *)
        echo "Unknown provider $PROVIDER given";
        exit 2;
        ;;
esac
