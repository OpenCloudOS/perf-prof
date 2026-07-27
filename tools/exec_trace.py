#!/usr/bin/env -S perf-prof python -e sched:sched_process_exec//batch=1/ --order -m 64
#
# exec_trace.py - Snapshot the on-CPU process context on every event
#
# NOTE ON THE NAME: this script started as an exec-only tracer, hence the name
# and the default shebang. It has since been generalized: at every sampled
# event, it prints the on-CPU process's cmdline and /proc-based context. Use
# it whenever you have a tracepoint / kprobe / uprobe that marks an interesting
# moment and want to know "who was doing this, with what cmdline, from where,
# under which uid, launched by whom" -- e.g. someone unloading a kernel module,
# writing to a sysctl, opening a suspicious file, entering a rare syscall. The
# `exec_trace` name is retained for backwards compatibility; think of it as
# "trace anything, get exec-like context".
#
# The shebang defaults to sched:sched_process_exec so `./exec_trace.py` is a
# ready-made exec tracer. Override -e for anything else:
#   perf-prof python -e <EVENT> -- exec_trace.py [options]
#
# The event handler is `__sample__`, which perf-prof python calls for every
# event that has no event-specific handler. That is why any -e event works.
#
# When the sampled event has a `filename` field (e.g. sched:sched_process_exec,
# syscalls:sys_enter_execve), --name/--path match against it and it is
# appended after '(cmdline unavailable)' when /proc is unreachable. Events
# without `filename` are passed through; --name/--path are simply ignored.
#
# The PID used for /proc lookups is always `event._pid` (the PID recorded in
# the perf sample header, i.e. the task that was on-CPU when the event fired).
# We deliberately do NOT use `event.pid`: many events carry a `pid` field that
# means something else -- e.g. sched:sched_wakeup's `pid` is the wakee, not
# the runner. Using `_pid` keeps the /proc context consistent across arbitrary
# events. Events with _pid == 0 (idle task) are dropped -- /proc/0 has nothing
# useful.
#
# Usage:
#   # Default (shebang): every exec
#   chmod +x exec_trace.py
#   ./exec_trace.py [options]
#
#   # Any other event: who unloaded a module, who wrote to a sysctl, ...
#   perf-prof python -e 'kprobes:free_module' \
#       --order -m 64 -- exec_trace.py --parent --uid
#
#   perf-prof python -e 'syscalls:sys_enter_execve//batch=1/' \
#       --order -m 64 -- exec_trace.py [options]
#
# Options:
#   --name <pattern>  Filter by process name (shell wildcards: * ? []).
#                     Matches basename(event.filename). Ignored on events
#                     that don't carry a filename field. Repeatable.
#   --path <pattern>  Filter by full event.filename (wildcards). Ignored on
#                     events without filename. Repeatable.
#   --parent          Also print parent process (PPID + cmdline), read from
#                     /proc/<pid>/status at event time.
#   --cwd             Also print working directory, read from /proc/<pid>/cwd.
#   --uid             Also print uid/gid (real/effective) and loginuid,
#                     read from /proc/<pid>/{status,loginuid}.
#   --env KEY[,KEY..] Also print selected environment variables, read from
#                     /proc/<pid>/environ. Repeatable; comma-separated list.
#   --exe             Also print real executable path (readlink /proc/<pid>/exe).
#                     If the event has a `filename` field and its basename
#                     differs from the exe basename, a `filename:` line is
#                     appended (shebang / symlink / memfd / deleted).
#   --std             Also print stdin/stdout/stderr targets
#                     (readlink /proc/<pid>/fd/{0,1,2}).
#   --tree            Walk the PPid chain from the on-CPU process up to PID 1
#                     and print each level with its cmdline. Supersedes
#                     --parent. Stops early on unreachable PPid, loop, or
#                     depth cap (32 levels).
#

import sys
import os
import argparse
import fnmatch
from datetime import datetime

# Parse script arguments
parser = argparse.ArgumentParser(
    prog='exec_trace.py',
    description='Snapshot the on-CPU process context on every event.',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""\
Output layout:
  [YYYY-MM-DD HH:MM:SS.uuuuuu] CPU:N   PID:P   [event]   <cmdline>
      parent:   PPID:Q      <parent cmdline>          (--parent)
      cwd:      <path>                                (--cwd)
      uid:      uid=r/e gid=r/e loginuid=N            (--uid)
      env:      KEY=val KEY=val ...                   (--env KEY[,KEY..])
      exe:      <readlink /proc/<pid>/exe>            (--exe)
      filename: <event.filename>  (!= exe)            (--exe, mismatch only,
                                                       when event has filename)
      stdin:    <fd target>                           (--std)
      stdout:   <fd target>                           (--std)
      stderr:   <fd target>                           (--std)
      tree:                                            (--tree, always last)
          PID:1   /sbin/init
            `- PID:X   /usr/bin/sshd -D
              `- PID:Y   -bash
                `- PID:P   <cmdline of on-CPU process>

Examples:
  # Default: capture every exec (uses the shebang's -e sched:sched_process_exec)
  ./exec_trace.py

  # Same, filtered by name
  ./exec_trace.py --name ps
  ./exec_trace.py --name 'python*'
  ./exec_trace.py --path '/usr/local/bin/*'

  # Parent + cwd context: who launched it and from where
  ./exec_trace.py --parent --cwd

  # Full ancestor chain up to init -- who's ultimately responsible
  ./exec_trace.py --tree

  # Identity + LD_PRELOAD/PATH -- spot setuid escalation & lib hijack
  ./exec_trace.py --uid --env LD_PRELOAD,PATH

  # Real binary + stdio redirections -- spot shebang/memfd/deleted, and IO layout
  ./exec_trace.py --exe --std

  # Trace fork instead of exec (no filename field on this event)
  perf-prof python -e 'sched:sched_process_fork' \\
      --order -m 64 -- exec_trace.py --parent --cwd --uid

  # Trace any syscall entry, with cmdline context
  perf-prof python -e 'syscalls:sys_enter_openat' \\
      --order -m 64 -- exec_trace.py --parent

  # Who unloaded a kernel module? Full chain -- init->systemd->sshd->bash->rmmod
  perf-prof python -e 'kprobes:free_module' \\
      --order -m 64 -- exec_trace.py --tree --uid

  # Kernel-side filter for high-volume systems (much cheaper than --name)
  perf-prof python -e 'sched:sched_process_exec/filename~"*/ps"/batch=1/' \\
      --order -m 64 -- exec_trace.py

Notes:
  - When /proc is unreachable (process gone, wrong PID, ns mismatch), the
    main line always shows '(cmdline unavailable)'. If the event carries a
    `filename` field, it is appended after that marker so the "what was
    tried" is still visible.
  - For events without `filename`, --name / --path are ignored (nothing to
    match on) and the event passes through.
  - Context is read from /proc/<pid>/* at event time. Very short-lived
    processes can exit before /proc is readable -> the line marks '(gone)'
    or '(unavailable)'. The PID used is always event._pid (the sample-header
    PID, i.e. the task on-CPU when the event fired). Events sampled on the
    idle task (_pid == 0) are dropped -- /proc/0 has nothing useful.
""")
parser.add_argument('--name', action='append', default=[], metavar='PAT',
                    help='Filter by basename of event.filename '
                         '(wildcard, repeatable); ignored on events without filename')
parser.add_argument('--path', action='append', default=[], metavar='PAT',
                    help='Filter by full event.filename '
                         '(wildcard, repeatable); ignored on events without filename')
parser.add_argument('--parent', action='store_true',
                    help='Also print parent process (PPID + cmdline)')
parser.add_argument('--cwd', action='store_true',
                    help='Also print working directory')
parser.add_argument('--uid', action='store_true',
                    help='Also print uid/gid (real/effective) and loginuid')
parser.add_argument('--env', action='append', default=[], metavar='KEY[,KEY..]',
                    help='Also print selected env variables (comma-separated, repeatable)')
parser.add_argument('--exe', action='store_true',
                    help='Also print real executable path (/proc/<pid>/exe)')
parser.add_argument('--std', action='store_true',
                    help='Also print stdin/stdout/stderr targets (/proc/<pid>/fd/{0,1,2})')
parser.add_argument('--tree', action='store_true',
                    help='Print the full ancestor chain up to init (PID 1), '
                         'one level per line with cmdline; supersedes --parent')
args = parser.parse_args()

# Flatten --env KEY,KEY --env KEY into a single ordered list, drop dupes/blanks
env_keys = []
for spec in args.env:
    for k in spec.split(','):
        k = k.strip()
        if k and k not in env_keys:
            env_keys.append(k)

# Statistics
stats = {
    'total': 0,
    'matched': 0,
    'cmdline_ok': 0,
    'cmdline_fail': 0,
}


def _match(filename):
    """Check if event.filename matches any filter pattern.

    - No filter set    -> match all.
    - Event has no filename -> --name/--path can't be evaluated; ignore them
      and let the event through (so cross-event tracing with a name filter
      still works for events that happen to lack the field).
    - Filter set, filename present -> fnmatch on basename (--name) or full
      path (--path); any hit wins.
    """
    if not args.name and not args.path:
        return True
    if filename is None:
        return True
    basename = os.path.basename(filename)
    for pat in args.name:
        if fnmatch.fnmatch(basename, pat):
            return True
    for pat in args.path:
        if fnmatch.fnmatch(filename, pat):
            return True
    return False


def _read_proc_cmdline(pid):
    """Read and parse /proc/<pid>/cmdline, return cmdline string or None."""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            raw = f.read()
        if not raw:
            return None
        argv = raw.rstrip(b'\x00').split(b'\x00')
        return ' '.join(arg.decode('utf-8', errors='replace') for arg in argv)
    except (IOError, OSError):
        return None


def _read_ppid(pid):
    """Read PPid from /proc/<pid>/status, return int or None."""
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('PPid:'):
                    return int(line.split()[1])
    except (IOError, OSError, ValueError):
        return None
    return None


def _read_cwd(pid):
    """Read /proc/<pid>/cwd symlink, return path or None."""
    try:
        return os.readlink(f'/proc/{pid}/cwd')
    except (IOError, OSError):
        return None


def _read_uid_info(pid):
    """Return (ruid, euid, rgid, egid, loginuid) from /proc/<pid>/*.
    Any component may be None if unreadable."""
    ruid = euid = rgid = egid = loginuid = None
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    parts = line.split()
                    # Uid:  real  effective  saved  fs
                    ruid, euid = int(parts[1]), int(parts[2])
                elif line.startswith('Gid:'):
                    parts = line.split()
                    rgid, egid = int(parts[1]), int(parts[2])
                    break
    except (IOError, OSError, ValueError, IndexError):
        pass
    try:
        with open(f'/proc/{pid}/loginuid', 'r') as f:
            v = f.read().strip()
            if v:
                loginuid = int(v)
    except (IOError, OSError, ValueError):
        pass
    return ruid, euid, rgid, egid, loginuid


def _read_environ(pid, keys):
    """Read /proc/<pid>/environ, return dict of requested KEY -> value.
    Missing keys are omitted from the dict."""
    if not keys:
        return {}
    try:
        with open(f'/proc/{pid}/environ', 'rb') as f:
            raw = f.read()
    except (IOError, OSError):
        return {}
    wanted = set(keys)
    out = {}
    for item in raw.split(b'\x00'):
        if not item:
            continue
        eq = item.find(b'=')
        if eq <= 0:
            continue
        k = item[:eq].decode('utf-8', errors='replace')
        if k in wanted:
            out[k] = item[eq+1:].decode('utf-8', errors='replace')
            if len(out) == len(wanted):
                break
    return out


def _read_exe(pid):
    """Readlink /proc/<pid>/exe. Kernel appends ' (deleted)' when the inode
    is gone; we keep the marker verbatim so callers can spot it."""
    try:
        return os.readlink(f'/proc/{pid}/exe')
    except (IOError, OSError):
        return None


def _read_fd(pid, fd):
    """Readlink /proc/<pid>/fd/<fd>. Returns the target string, or None if the
    fd is closed / unreadable. Targets can be paths, 'pipe:[N]', 'socket:[N]',
    '/dev/pts/N', 'anon_inode:...', etc."""
    try:
        return os.readlink(f'/proc/{pid}/fd/{fd}')
    except (IOError, OSError):
        return None


def _event_filename(event):
    """Return event.filename if the event has that field, else None.

    Accessing a missing attribute on a PerfEvent raises AttributeError; treat
    that (and any decoding trouble) as "no filename on this event"."""
    try:
        return event.filename
    except (AttributeError, KeyError):
        return None


# PID 1 (init) cmdline cache. Populated at __init__ time when --tree is on;
# every event's ancestor walk terminates at PID 1, so caching the very hot
# top of the chain saves one /proc read per event. init changes its cmdline
# at most on service manager re-exec (systemctl daemon-reexec) -- rare enough
# that a session-lifetime cache is a safe trade for the saved I/O.
_INIT_CMDLINE = None


def __init__():
    """Called once before event processing starts."""
    global _INIT_CMDLINE
    if args.tree:
        _INIT_CMDLINE = _read_proc_cmdline(1)
    filters = args.name + args.path
    filter_str = ', '.join(filters) if filters else '(all)'
    ctx = []
    if args.parent and not args.tree: ctx.append('parent')
    if args.cwd:    ctx.append('cwd')
    if args.uid:    ctx.append('uid')
    if env_keys:    ctx.append('env=' + ','.join(env_keys))
    if args.exe:    ctx.append('exe')
    if args.std:    ctx.append('std')
    if args.tree:   ctx.append('tree')
    ctx_str = ', '.join(ctx) if ctx else '(none)'
    print(f"{'='*72}")
    print(f"  event tracer (default: sched:sched_process_exec)")
    print(f"  Filter:  {filter_str}")
    print(f"  Context: {ctx_str}")
    print(f"  Press Ctrl-C to stop.")
    print(f"{'='*72}")
    print()


def __exit__():
    """Called once before program exit."""
    sys.stderr = open(os.devnull, 'w')
    print()
    print(f"{'='*72}")
    print(f"  Summary:")
    print(f"    Total events:           {stats['total']}")
    print(f"    Matched:                {stats['matched']}")
    print(f"    Cmdline captured:       {stats['cmdline_ok']}")
    print(f"    Cmdline missed (exited):{stats['cmdline_fail']}")
    print(f"{'='*72}")


def __sample__(event):
    """Default handler: fires for every event without a name-specific handler."""
    stats['total'] += 1

    filename = _event_filename(event)
    if not _match(filename):
        return

    pid = event._pid
    # PID 0 is the idle task -- there's nothing readable under /proc/0 and
    # printing "swapper" per event is pure noise. Drop these silently; they
    # come from events sampled while the CPU was idle.
    if pid == 0:
        return

    stats['matched'] += 1
    cpu = event._cpu
    ev_name = event._event

    # Format timestamp
    realtime = event._realtime
    dt = datetime.fromtimestamp(realtime / 1e9)
    ts = dt.strftime('%Y-%m-%d %H:%M:%S') + f'.{realtime % 1000000000 // 1000:06d}'

    # Try to read full command line from /proc
    cmdline = _read_proc_cmdline(pid)

    if cmdline:
        stats['cmdline_ok'] += 1
        print(f"[{ts}] CPU:{cpu:<3d} PID:{pid:<7d} [{ev_name}] {cmdline}")
    else:
        stats['cmdline_fail'] += 1
        # /proc is unreachable (process gone, PID mismatch, etc). Always mark
        # the failure explicitly; append event.filename after it when the
        # event carries one, so the "what was tried" is still visible.
        suffix = f' {filename}' if filename else ''
        print(f"[{ts}] CPU:{cpu:<3d} PID:{pid:<7d} [{ev_name}] (cmdline unavailable){suffix}")

    # Optional context (read now, before parent may exit)
    # Layout: 4-space indent, label padded to 8, values aligned by :<7d for PID
    # --tree is intentionally emitted LAST: its output is multi-line and does
    # not fit the "label: value" alignment of the other rows, so keeping it
    # at the bottom avoids visually splitting the compact context block.
    if args.parent and not args.tree:
        # --tree already covers "who's the parent" (as its penultimate row),
        # so suppress --parent when both are on to avoid double-printing.
        ppid = _read_ppid(pid)
        if ppid is not None:
            pcmd = _read_proc_cmdline(ppid) or '(gone)'
            print(f"    {'parent:':<8} PPID:{ppid:<7d} {pcmd}")
        else:
            print(f"    {'parent:':<8} (unavailable)")

    if args.cwd:
        cwd = _read_cwd(pid)
        print(f"    {'cwd:':<8} {cwd if cwd else '(unavailable)'}")

    if args.uid:
        ruid, euid, rgid, egid, loginuid = _read_uid_info(pid)
        def _fmt(v): return str(v) if v is not None else '?'
        lu = _fmt(loginuid) if loginuid != 0xFFFFFFFF else '-'
        print(f"    {'uid:':<8} uid={_fmt(ruid)}/{_fmt(euid)} gid={_fmt(rgid)}/{_fmt(egid)} loginuid={lu}")

    if env_keys:
        env = _read_environ(pid, env_keys)
        # Keep the user's specified order; mark missing keys explicitly
        parts = [f"{k}={env[k]}" if k in env else f"{k}=(unset)" for k in env_keys]
        print(f"    {'env:':<8} {' '.join(parts)}")

    if args.exe:
        exe = _read_exe(pid)
        if exe is None:
            print(f"    {'exe:':<8} (unavailable)")
        else:
            # Strip kernel-appended ' (deleted)' before comparing basenames, but
            # keep the marker in the printed value so it's still visible.
            exe_cmp = exe[:-len(' (deleted)')] if exe.endswith(' (deleted)') else exe
            # Compare against filename only when the event actually carries one.
            if filename is None or os.path.basename(exe_cmp) == os.path.basename(filename):
                print(f"    {'exe:':<8} {exe}")
            else:
                # Mismatch: print exe first, then the raw event filename so the
                # reader can see both sides of the discrepancy (shebang, symlink,
                # memfd, deleted binary, etc.).
                print(f"    {'exe:':<8} {exe}")
                print(f"    {'filename:':<8} {filename}  (!= exe)")

    if args.std:
        # 0=stdin 1=stdout 2=stderr; each fd may be closed -> '(closed)'
        for fd, label in ((0, 'stdin'), (1, 'stdout'), (2, 'stderr')):
            tgt = _read_fd(pid, fd)
            print(f"    {label+':':<8} {tgt if tgt else '(closed)'}")

    if args.tree:
        # Walk PPid chain up to init (PID 1). Guard against read failures,
        # loops, and pathological depth so a broken /proc can't hang us.
        # Kept last so its multi-line output doesn't split the aligned
        # "label: value" rows above.
        MAX_DEPTH = 32
        chain = [(pid, cmdline)]   # start with the on-CPU process itself
        seen = {pid}
        cur = pid
        depth = 0
        stop_reason = None
        while depth < MAX_DEPTH:
            ppid = _read_ppid(cur)
            if ppid is None:
                stop_reason = 'ppid unavailable'
                break
            if ppid == 0:
                # PPid 0 is the kernel (swapper); typical for kthreads.
                stop_reason = 'reached kernel'
                break
            if ppid in seen:
                stop_reason = f'loop at PID {ppid}'
                break
            seen.add(ppid)
            if ppid == 1:
                # PID 1 cmdline is cached at startup -- init rarely changes
                # it (only on `systemctl daemon-reexec` style re-exec), and
                # every tree walk terminates here, so skip the per-event
                # /proc read.
                chain.append((1, _INIT_CMDLINE))
                break
            chain.append((ppid, _read_proc_cmdline(ppid)))
            cur = ppid
            depth += 1
        else:
            stop_reason = f'depth limit ({MAX_DEPTH})'

        # Print oldest-first, so pid 1 is at the top and the on-CPU process
        # is at the bottom -- reads like a call chain.
        print(f"    tree:")
        for level, (p, cmd) in enumerate(reversed(chain)):
            indent = '        ' + '  ' * level
            arrow = '' if level == 0 else '`- '
            shown = cmd if cmd else '(gone)'
            print(f"{indent}{arrow}PID:{p:<7d} {shown}")
        if stop_reason:
            print(f"        (stopped: {stop_reason})")