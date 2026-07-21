#!/usr/bin/env -S perf-prof python -e kvm:kvm_userspace_exit,syscalls:sys_enter_ioctl/cmd==0xAE80/ --order -m 16
#
# kvm_userspace_exit_latency.py - QEMU userspace-exit handling latency
#
# Measures how long QEMU spends handling a KVM userspace exit: from
# kvm:kvm_userspace_exit (KVM returns to userspace) to the next
# ioctl(KVM_RUN) issued on the same vcpu thread (QEMU re-enters KVM).
#
# Pairing: keyed by common_pid (vcpu thread). The thread may be scheduled
# off / migrated across CPUs between the two events, so --order is needed.
#
# KVM_RUN ioctl number = _IO(KVMIO=0xAE, 0x80) = 0xAE80. Filtered in-kernel
# to avoid capturing every ioctl the process makes.
#
# Statistics per (reason [, vcpu-tid]) group:
#   COUNT, TOTAL, MIN, P50, P95, P99, MAX (all in us)
#
# Interval behavior:
#   Without -i:  print once at __exit__ over the whole run.
#   With -i ms:  print each interval, then reset. (No separate cumulative.)
#
# Usage:
#   perf-prof python \
#       -e 'kvm:kvm_userspace_exit,syscalls:sys_enter_ioctl/cmd==0xAE80/' \
#       --order -m 16 -p <qemu_pid> [-i 1000] \
#       -- kvm_userspace_exit_latency.py [options]
#   or:
#   chmod +x kvm_userspace_exit_latency.py
#   ./kvm_userspace_exit_latency.py -p <qemu_pid>
#
# Notes:
#   -m 16 (64KB / instance) is enough for typical userspace-exit rates.
#   If stderr shows 'lost N events', double -m (32 / 64 / 128 ...).
#
# Options:
#   --than <dur>    Print each pair whose latency > threshold (e.g. 20us, 5ms, 1s)
#   --top <n>       Top N rows to display (default: 20)
#   --sort <field>  Sort by: total, count, max, p99 (default: total)
#   --per-tid       Group by (vcpu-tid, reason) instead of reason
#
# Examples:
#   # One-shot per-reason latency of qemu pid 12345 (Ctrl-C to finish)
#   ./kvm_userspace_exit_latency.py -p 12345
#
#   # Periodic report every 1s
#   ./kvm_userspace_exit_latency.py -p 12345 -i 1000
#
#   # Print each pair whose latency exceeds 500us
#   ./kvm_userspace_exit_latency.py -p 12345 --than 500us
#
#   # Per vcpu-thread breakdown, sort by max
#   ./kvm_userspace_exit_latency.py -p 12345 --per-tid --sort max

import argparse
import sys
from collections import defaultdict
from datetime import datetime


# KVM exit reason codes -> names (see include/uapi/linux/kvm.h)
KVM_EXIT_REASON_NAMES = {
    0:  "UNKNOWN",
    1:  "EXCEPTION",
    2:  "IO",
    3:  "HYPERCALL",
    4:  "DEBUG",
    5:  "HLT",
    6:  "MMIO",
    7:  "IRQ_WINDOW_OPEN",
    8:  "SHUTDOWN",
    9:  "FAIL_ENTRY",
    10: "INTR",
    11: "SET_TPR",
    12: "TPR_ACCESS",
    13: "S390_SIEIC",
    14: "S390_RESET",
    15: "DCR",
    16: "NMI",
    17: "INTERNAL_ERROR",
    18: "OSI",
    19: "PAPR_HCALL",
    20: "S390_UCONTROL",
    21: "WATCHDOG",
    22: "S390_TSCH",
    23: "EPR",
    24: "SYSTEM_EVENT",
    25: "S390_STSI",
    26: "IOAPIC_EOI",
    27: "HYPERV",
}


def reason_name(code):
    """Format the exit code. code<0 = errno (restart/error), code>=0 = reason.
    Called only at output time; keep it off the fast path."""
    if code < 0:
        return "restart" if code == -4 else "error(%d)" % (-code)
    return KVM_EXIT_REASON_NAMES.get(code, "UNKNOWN(%d)" % code)


def _parse_duration_ns(s):
    """Parse a duration string like '20us', '5ms', '1s', '500ns', or bare
    number (interpreted as us for backward compat). Returns nanoseconds."""
    s = s.strip().lower()
    for suffix, mul in (("ns", 1), ("us", 1000), ("ms", 1_000_000),
                        ("s", 1_000_000_000)):
        if s.endswith(suffix):
            return int(float(s[:-len(suffix)]) * mul)
    return int(float(s) * 1000)  # bare number = us


EXAMPLES = """\
perf-prof options (consumed by the outer perf-prof python driver, not this
script; pass them BEFORE '--' or use directly when running via shebang):
  -p <pid,...>          Attach to processes (usually the qemu pid)
  -t <tid,...>          Attach to specific threads (e.g. vcpu tids)
  -C <cpu[-cpu],...>    Attach to specific CPUs
  --cgroups <re>        Attach to cgroups matching regex
  -i <ms>               Report interval in milliseconds (0 = only at exit)
  -m <pages>            Perf ringbuffer size per instance (power of 2,
                        default 16 = 64KB/instance; double it if events are lost)
  -o <file>             Redirect stdout/stderr to file
  --watermark <0-100>   Wake-up watermark, lower = more real-time
Run  'perf-prof python -h'  for the full list.

Examples:
  # One-shot report for qemu pid 12345, print at Ctrl-C
  %(prog)s -p 12345

  # Report every 1s
  %(prog)s -p 12345 -i 1000

  # Print each pair whose latency > 500us, and dump both events
  %(prog)s -p 12345 --than 500us

  # Same but 5ms threshold
  %(prog)s -p 12345 --than 5ms

  # Per vcpu-thread breakdown, sort by max latency
  %(prog)s -p 12345 --per-tid --sort max

  # Top 5 reasons by p99
  %(prog)s -p 12345 --top 5 --sort p99

  # Only monitor CPUs 0-3 of the qemu process
  %(prog)s -p 12345 -C 0-3 -i 1000
"""


# ---------------- CLI ----------------

parser = argparse.ArgumentParser(
    description="QEMU userspace-exit handling latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=EXAMPLES)
parser.add_argument("--than", type=_parse_duration_ns, default=0,
                    help="Print each pair whose latency > threshold (e.g. 20us, 5ms, 1s; bare number = us)")
parser.add_argument("--top", type=int, default=20,
                    help="Top N rows to display (default: 20)")
parser.add_argument("--sort", choices=["total", "count", "max", "p99"],
                    default="total", help="Sort field (default: total)")
parser.add_argument("--per-tid", action="store_true",
                    help="Group by (vcpu-tid, reason) instead of reason")
args = parser.parse_args()


# ---------------- state ----------------

# vcpu tid -> (exit_time_ns, code:int)
#   code >= 0: reason; code < 0: errno (restart/error)
pending = {}

# bucket key -> list of latency_ns
#   per_tid=False:  key = code:int
#   per_tid=True :  key = (tid:int, code:int)
records = defaultdict(list)

unmatched_run = 0       # KVM_RUN ioctl without a matching pending exit


# ---------------- helpers ----------------

def _fmt_us(ns):
    return "%.2f" % (ns / 1000.0)


def _pct(sorted_ns, p):
    """Percentile from an already-sorted list. p in [0,100]."""
    n = len(sorted_ns)
    if n == 0:
        return 0
    # nearest-rank method
    idx = int((p / 100.0) * (n - 1))
    return sorted_ns[idx]


SORT_IDX = {"count": 0, "total": 1, "max": 2, "p99": 3}


def _summarize(records_dict):
    """records_dict: {key -> [latency_ns,...]}  ->  list of (thread_str, reason_str, count, total, min, p50, p95, p99, max)."""
    rows = []
    for key, lats in records_dict.items():
        if not lats:
            continue
        if isinstance(key, tuple):
            thread, reason = "%d" % key[0], reason_name(key[1])
        else:
            thread, reason = "-", reason_name(key)
        lats.sort()
        total = sum(lats)
        rows.append((
            thread, reason, len(lats), total,
            lats[0],                # min
            _pct(lats, 50),         # p50
            _pct(lats, 95),         # p95
            _pct(lats, 99),         # p99
            lats[-1],               # max
        ))
    return rows


def _print_table(rows, top_n, sort_field):
    if not rows:
        return
    # column indices: thread(0) reason(1) count(2) total(3) min(4) p50(5) p95(6) p99(7) max(8)
    sort_col = {"count": 2, "total": 3, "max": 8, "p99": 7}[sort_field]
    rows.sort(key=lambda r: r[sort_col], reverse=True)
    rows = rows[:top_n]

    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if args.per_tid:
        header = "%-8s  %-16s %8s %12s %10s %10s %10s %10s %10s" % (
            "THREAD", "REASON", "COUNT", "TOTAL(us)", "MIN(us)", "P50(us)",
            "P95(us)", "P99(us)", "MAX(us)")
        print(header)
        print("-" * len(header))
        for thread, reason, cnt, total, mn, p50, p95, p99, mx in rows:
            print("%-8s  %-16s %8d %12s %10s %10s %10s %10s %10s" % (
                thread, reason, cnt, _fmt_us(total),
                _fmt_us(mn), _fmt_us(p50), _fmt_us(p95),
                _fmt_us(p99), _fmt_us(mx)))
    else:
        header = "%-16s %8s %12s %10s %10s %10s %10s %10s" % (
            "REASON", "COUNT", "TOTAL(us)", "MIN(us)", "P50(us)",
            "P95(us)", "P99(us)", "MAX(us)")
        print(header)
        print("-" * len(header))
        for _, reason, cnt, total, mn, p50, p95, p99, mx in rows:
            print("%-16s %8d %12s %10s %10s %10s %10s %10s" % (
                reason, cnt, _fmt_us(total),
                _fmt_us(mn), _fmt_us(p50), _fmt_us(p95),
                _fmt_us(p99), _fmt_us(mx)))
    print()


def _report():
    _print_table(_summarize(records), args.top, args.sort)


# ---------------- event handlers ----------------

def kvm__kvm_userspace_exit(event):
    tid = event.common_pid
    # Store a single signed int: errno if <0, otherwise reason.
    errno = event.errno
    code = errno if errno < 0 else event.reason
    # Keep the exit event itself when --than is set, so we can print it
    # later once the pair completes and passes the threshold.
    pending[tid] = (event._time, code, event if args.than > 0 else None)


def syscalls__sys_enter_ioctl(event):
    global unmatched_run
    tid = event.common_pid
    if tid not in pending:
        # First KVM_RUN of the vcpu thread, or a KVM_RUN that follows an
        # in-kernel-only exit (no userspace_exit emitted). Skip.
        unmatched_run += 1
        return
    exit_time, code, exit_event = pending.pop(tid)
    latency_ns = event._time - exit_time
    if latency_ns < 0:
        return

    bucket = (tid, code) if args.per_tid else code
    records[bucket].append(latency_ns)

    if args.than > 0 and latency_ns > args.than:
        exit_event.print()
        event.print()


# ---------------- lifecycle ----------------

def __init__():
    print("Waiting for kvm:kvm_userspace_exit / ioctl(KVM_RUN) events...")


def __interval__():
    global records
    _report()
    records = defaultdict(list)


def __exit__():
    if any(records.values()):
        _report()


def __lost__(lost_start, lost_end):
    pending.clear()
    sys.stderr.write("Warning: events lost, pending state cleared\n")