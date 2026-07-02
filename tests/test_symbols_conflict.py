#!/usr/bin/env python3

# Duplicate-symbol handling for --symbols and uprobe.
#
# Two callers of obj__find_name (now obj__find_name_all): the pprof-style
# --symbols command and uprobe event parsing. Both must detect names that
# exist at multiple distinct offsets in the same binary and either warn
# (--symbols) or reject (uprobe) with a candidate list.

from PerfProf import PerfProf
from conftest import result_check
import ctypes.util
import os
import subprocess
import pytest


def _libc_path():
    libc_name = ctypes.util.find_library('c')
    if not libc_name:
        return None
    for d in ('/lib64/', '/usr/lib64/', '/lib/x86_64-linux-gnu/'):
        p = d + libc_name
        if os.path.exists(p):
            return p
    return None


def _find_duplicate_symbol(libc):
    # Return (name, [off_hex, ...]) for a symbol that appears at 2+ distinct
    # offsets in libc, or (None, None) if none can be found.
    try:
        out = subprocess.Popen(['nm', '-D', libc],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True).communicate()[0]
    except FileNotFoundError:
        return None, None
    by_name = {}
    for line in out.splitlines():
        parts = line.split()
        # nm -D lines: "<addr> <type> <name>" for defined symbols.
        if len(parts) < 3:
            continue
        # Only consider defined text symbols with a real address; skip
        # undefined ('U') and version-only entries.
        if parts[-2] not in ('T', 'W', 'i'):
            continue
        try:
            off = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[-1]
        by_name.setdefault(name, set()).add(off)
    for name, offsets in by_name.items():
        if len(offsets) >= 2:
            return name, sorted('0x%x' % o for o in offsets)
    return None, None


def _find_unique_symbol(libc):
    # A libc symbol that appears at exactly one offset (used for the
    # non-conflicting positive test).
    try:
        out = subprocess.Popen(['nm', '-D', libc],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True).communicate()[0]
    except FileNotFoundError:
        return None
    by_name = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[-2] not in ('T', 'W', 'i'):
            continue
        try:
            int(parts[0], 16)
        except ValueError:
            continue
        by_name[parts[-1]] = by_name.get(parts[-1], 0) + 1
    for name, count in by_name.items():
        if count == 1 and name.replace('_', '').isalnum():
            return name
    return None


# --- --symbols: duplicate emits warning, keeps first-match on stdout ---------

def test_symbols_duplicate_stderr_warning():
    libc = _libc_path()
    if libc is None:
        pytest.skip("libc not found")
    name, offsets = _find_duplicate_symbol(libc)
    if name is None:
        pytest.skip("no duplicate symbol in libc — nothing to disambiguate")

    prof = PerfProf(['--symbols', libc])
    saw_stdout_offset = False
    saw_warning = False
    saw_candidates = False
    for std, line in prof.run(3, 0, input=name):
        if std == PerfProf.STDOUT and line.startswith('0x'):
            saw_stdout_offset = True
        if std == PerfProf.STDERR:
            low = line.lower()
            if 'warning' in low and name in line and 'candidates' in low:
                saw_warning = True
            if 'first match' in low:
                saw_candidates = True
    assert saw_stdout_offset, \
        "--symbols must still print an offset on stdout for backward compat"
    assert saw_warning, \
        "--symbols must warn on stderr when name has multiple offsets"
    assert saw_candidates, \
        "--symbols warning must mention first-match fallback"


# --- --symbols: unique symbol -> stdout offset, no warning -------------------

def test_symbols_unique_no_warning():
    libc = _libc_path()
    if libc is None:
        pytest.skip("libc not found")
    name = _find_unique_symbol(libc)
    if name is None:
        pytest.skip("no obviously-unique libc symbol found")

    prof = PerfProf(['--symbols', libc])
    saw_stdout_offset = False
    saw_warning = False
    for std, line in prof.run(3, 0, input=name):
        if std == PerfProf.STDOUT and line.startswith('0x'):
            saw_stdout_offset = True
        if std == PerfProf.STDERR and 'warning' in line.lower():
            saw_warning = True
    assert saw_stdout_offset
    assert not saw_warning, \
        "unique-symbol lookup must not emit a duplicate-candidates warning"


# --- uprobe: duplicate rejects with candidate list ---------------------------

def test_uprobe_duplicate_rejected_with_candidates():
    if not PerfProf.pmu_exists('uprobe'):
        pytest.skip("'uprobe' does not exist")
    libc = _libc_path()
    if libc is None:
        pytest.skip("libc not found")
    name, offsets = _find_duplicate_symbol(libc)
    if name is None:
        pytest.skip("no duplicate symbol in libc")

    e = 'uprobe:' + libc + ':' + name
    prof = PerfProf(['trace', '-e', e, '-m', '64', '-N', '1'])
    saw_candidates = False
    saw_try_one_of = False
    for std, line in prof.run(3, 0):
        if std == PerfProf.STDERR:
            low = line.lower()
            if 'candidates in' in low and name in line:
                saw_candidates = True
            if 'try one of' in low:
                saw_try_one_of = True
    assert saw_candidates, \
        "uprobe must reject duplicate name with a candidates message"
    assert saw_try_one_of, \
        "uprobe error must include a 'Try one of:' hint"


# --- uprobe: candidate offset from the error message actually resolves -------

def test_uprobe_candidate_offset_works(runtime, memleak_check):
    if not PerfProf.pmu_exists('uprobe'):
        pytest.skip("'uprobe' does not exist")
    libc = _libc_path()
    if libc is None:
        pytest.skip("libc not found")
    name, offsets = _find_duplicate_symbol(libc)
    if name is None or not offsets:
        pytest.skip("no duplicate symbol in libc")

    # Use the first candidate offset directly. This mirrors what a user
    # would do after reading the "Try one of:" hint.
    e = 'uprobe:' + libc + ':' + offsets[0]
    prof = PerfProf(['trace', '-e', e, '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)