"""
Function call duration / relationship analyzer.

Uses __sample__ and parses event._event:
  uprobe:<func>    / uretprobe:<func>    -> user-space (branch marked |-)
  kprobe:<func>    / kretprobe:<func>    -> kernel-space (branch marked |→)

Tracked functions can be added or removed simply by changing perf-prof's -e
flag; no code edits required here.

Per-thread stack model: on entry push (func, path, start_ts); on return pop
the topmost matching frame, record duration, aggregate by full call path so
same-named callees under different roots stay independent.

Historical stats are cleared after every _dump so each interval reflects only
that window; pending (unreturned) frames are preserved across dumps.
"""

from collections import defaultdict
from datetime import datetime

# tid -> [(func, path_tuple, start_ns), ...]
call_stacks = defaultdict(list)

# path (root..leaf tuple of func names) -> list of durations (ns) in the
# CURRENT window. All aggregates (count/total/min/avg/p50/p95/p99/max) are
# derived from this list at dump time — exact percentiles, no approximation.
path_samples = defaultdict(list)

# func name -> True if seen via kprobe/kretprobe (kernel). Persists across
# windows so a kernel function keeps its [K] mark even in a later interval
# where it was not observed.
kernel_func = {}

unmatched_returns = 0


def _entry(tid, ts, func):
    stack = call_stacks[tid]
    parent_path = stack[-1][1] if stack else ()
    stack.append((func, parent_path + (func,), ts))


def _return(tid, ts, func):
    global unmatched_returns
    stack = call_stacks[tid]
    if not stack:
        unmatched_returns += 1
        return
    idx = None
    for i in range(len(stack) - 1, -1, -1):
        if stack[i][0] == func:
            idx = i
            break
    if idx is None:
        unmatched_returns += 1
        return
    _, path, start_ns = stack[idx]
    duration = ts - start_ns
    del stack[idx:]
    if not stack:
        del call_stacks[tid]
    if duration < 0:
        unmatched_returns += 1
        return
    path_samples[path].append(duration)


def __sample__(event):
    ev = event._event  # e.g. "uprobe:foo" / "kretprobe:bar"
    kind, _, func = ev.partition(':')
    if not func:
        return
    if kind in ('uprobe', 'kprobe'):
        if kind == 'kprobe':
            kernel_func[func] = True
        _entry(event._tid, event._time, func)
    elif kind in ('uretprobe', 'kretprobe'):
        if kind == 'kretprobe':
            kernel_func[func] = True
        _return(event._tid, event._time, func)


def _us(ns):
    return f"{ns / 1000.0:.2f}"


def _percentile(sorted_samples, pct):
    """Nearest-rank percentile on a pre-sorted list. `pct` in [0,100]."""
    n = len(sorted_samples)
    if n == 0:
        return 0
    # rank in [1, n]; ceil(pct/100 * n)
    rank = int((pct * n + 99) // 100)
    if rank < 1:
        rank = 1
    if rank > n:
        rank = n
    return sorted_samples[rank - 1]


LABEL_W = 44
NUM_W   = 8
TIME_W  = 11


COLS = ('N', 'TOTAL', 'MIN', 'AVG', 'P50', 'P95', 'P99', 'MAX')


def _fmt_row(label, count, total_ns, min_ns, avg_ns, p50, p95, p99, max_ns):
    vals = (_us(total_ns), _us(min_ns), _us(avg_ns),
            _us(p50), _us(p95), _us(p99), _us(max_ns))
    return (f"{label:<{LABEL_W}}"
            f"{count:>{NUM_W}}"
            + ''.join(f"{v:>{TIME_W}}" for v in vals))


def _prefix(depth, kernel=False):
    if depth == 0:
        return ''
    branch = '|→ ' if kernel else '|- '
    return '  ' + '|  ' * (depth - 1) + branch


def _dump():
    global unmatched_returns

    if path_samples:
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        # path -> children list, preserving first-seen (insertion) order
        children = defaultdict(list)
        for path in path_samples:
            children[path[:-1]].append(path)

        # Pre-compute sorted samples + all aggregates once per path.
        stats = {}
        for path, samples in path_samples.items():
            s = sorted(samples)
            n = len(s)
            total = sum(s)
            stats[path] = {
                'count':  n,
                'total':  total,
                'min':    s[0],
                'avg':    total / n,
                'p50':    _percentile(s, 50),
                'p95':    _percentile(s, 95),
                'p99':    _percentile(s, 99),
                'max':    s[-1],
            }

        header = (f"{'function':<{LABEL_W}}"
                  f"{'N':>{NUM_W}}"
                  + ''.join(f"{c + '(us)':>{TIME_W}}" for c in COLS[1:]))
        print(header)
        print('-' * len(header))

        def walk(path, depth):
            st = stats[path]
            name = path[-1]
            print(_fmt_row(_prefix(depth, kernel_func.get(name)) + name,
                           st['count'], st['total'], st['min'], st['avg'],
                           st['p50'], st['p95'], st['p99'], st['max']))
            for child in children.get(path, ()):
                walk(child, depth + 1)

        for root in children.get((), ()):
            walk(root, 0)

        unfinished = sum(len(s) for s in call_stacks.values())
        if unmatched_returns or unfinished:
            print(f"[anomalies] unmatched-returns={unmatched_returns} "
                  f"pending-frames={unfinished}")
        print()

    # Clear only per-window state; keep call_stacks so a call spanning the
    # dump boundary is recorded in the next window it completes in.
    path_samples.clear()
    unmatched_returns = 0


def __interval__():
    _dump()


def __exit__():
    _dump()
