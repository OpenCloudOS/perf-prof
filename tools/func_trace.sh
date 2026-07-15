#!/bin/bash
# Assemble and run a perf-prof python command for func_trace.py.
#
# Usage:
#   ./func_trace.sh -b BINARY [-u FUNC]... [-k FUNC]... [perf-prof options]
#
# The script owns only three options; everything else is passed through
# verbatim to perf-prof.
#
#   -b BINARY   target binary (required if any -u is given)
#   -u FUNC     uprobe + uretprobe on FUNC inside BINARY (repeatable)
#   -k FUNC     kprobe + kretprobe on kernel FUNC (repeatable)
#   -h          help
#   -n          dry-run: print the assembled command, do not exec
#
# Any other argument is forwarded to perf-prof (e.g. -p, -C, -i, -m, -o).
# --order is injected automatically if the user did not already pass it,
# because a function's entry and return may be observed on different CPUs
# and only strict time-order guarantees correct pairing.
# If no `--` separator is present in the pass-through args, the default
# python module `<script_dir>/func_trace.py` is appended.
#
# Example:
#   ./func_trace.sh \
#     -b /path/to/target_binary \
#     -u root_func_A \
#     -u child_func_1 \
#     -k some_kernel_func \
#     -p $(pgrep -x target_binary | head -1) \
#     -i 5000

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
default_py="$script_dir/func_trace.py"

usage() {
    awk 'NR==1{next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

binary=""
user_funcs=()
kern_funcs=()
passthrough=()
dry_run=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b)  binary="$2"; shift 2 ;;
        -b*) binary="${1#-b}"; shift ;;
        -u)  user_funcs+=("$2"); shift 2 ;;
        -u*) user_funcs+=("${1#-u}"); shift ;;
        -k)  kern_funcs+=("$2"); shift 2 ;;
        -k*) kern_funcs+=("${1#-k}"); shift ;;
        -n)  dry_run=1; shift ;;
        -h|--help) usage 0 ;;
        --)  shift; passthrough+=(-- "$@"); break ;;
        *)   passthrough+=("$1"); shift ;;
    esac
done

if [[ ${#user_funcs[@]} -eq 0 && ${#kern_funcs[@]} -eq 0 ]]; then
    echo "error: at least one -u FUNC or -k FUNC required" >&2
    usage 1 >&2
fi

if [[ ${#user_funcs[@]} -gt 0 ]]; then
    [[ -n "$binary" ]] || { echo "error: -b BINARY required when using -u" >&2; exit 1; }
    [[ -e "$binary" ]] || { echo "error: binary not found: $binary" >&2; exit 1; }
fi

events=()
for f in "${user_funcs[@]}"; do
    events+=("uprobe:${binary}:${f}" "uretprobe:${binary}:${f}")
done
for f in "${kern_funcs[@]}"; do
    events+=("kprobe:${f}" "kretprobe:${f}")
done

IFS=',' event_arg="${events[*]}"

# Inject --order unless the user already asked for it. Entry/return of the
# same function can be observed on different CPUs, so strict time-order
# merging across per-CPU ringbuffers is required for correct pairing.
has_order=0
for a in "${passthrough[@]:-}"; do
    [[ "$a" == "--order" ]] && { has_order=1; break; }
done
if (( ! has_order )); then
    if [[ ${#passthrough[@]} -gt 0 ]]; then
        passthrough=(--order "${passthrough[@]}")
    else
        passthrough=(--order)
    fi
fi

# If user did not supply `--`, append the default python module.
has_dashdash=0
for a in "${passthrough[@]:-}"; do
    [[ "$a" == "--" ]] && { has_dashdash=1; break; }
done
if (( ! has_dashdash )); then
    [[ -f "$default_py" ]] || { echo "error: default python script not found: $default_py" >&2; exit 1; }
    passthrough+=(-- "$default_py")
fi

cmd=(perf-prof python -e "$event_arg" "${passthrough[@]}")

if (( dry_run )); then
    printf '%q ' "${cmd[@]}"; echo
    exit 0
fi

exec "${cmd[@]}"
