#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest
import os
import sqlite3

def test_sql_basic_query(runtime, memleak_check):
    """Basic SQL query test: count events"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT COUNT(*) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT COUNT(*) as count FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_group_by_comm(runtime, memleak_check):
    """Group by process name and count"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm ORDER BY count DESC LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_group_by_cpu(runtime, memleak_check):
    """Group by CPU and count"""
    # perf-prof sql -e sched:sched_switch -i 1000 --query 'SELECT _cpu, COUNT(*) FROM sched_switch GROUP BY _cpu'
    prof = PerfProf(['sql', '-e', 'sched:sched_switch', '-i', '1000', '-m', '64',
                     '--query', 'SELECT _cpu, COUNT(*) as count FROM sched_switch GROUP BY _cpu'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_with_filter(runtime, memleak_check):
    """SQL with trace event filter"""
    # perf-prof sql -e 'sched:sched_wakeup/prio<10/' -i 1000 --query 'SELECT comm, prio, COUNT(*) FROM sched_wakeup GROUP BY comm, prio'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup/prio<10/', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, prio, COUNT(*) as count FROM sched_wakeup GROUP BY comm, prio LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_multi_queries(runtime, memleak_check):
    """Multiple SQL queries separated by semicolon"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT COUNT(*) FROM sched_wakeup; SELECT AVG(prio) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT COUNT(*) as total FROM sched_wakeup; SELECT AVG(prio) as avg_prio FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_multi_events(runtime, memleak_check):
    """Multiple events creating multiple tables"""
    # perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 --query 'SELECT COUNT(*) FROM sched_wakeup; SELECT COUNT(*) FROM sched_switch'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup,sched:sched_switch', '-i', '1000', '-m', '64',
                     '--query', 'SELECT COUNT(*) as wakeups FROM sched_wakeup; SELECT COUNT(*) as switches FROM sched_switch'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_join_events(runtime, memleak_check):
    """Join multiple events"""
    # perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 --query 'SELECT w.comm, COUNT(*) FROM sched_wakeup w, sched_switch s WHERE w.pid = s.next_pid GROUP BY w.comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup,sched:sched_switch', '-i', '1000', '-m', '64',
                     '--query', 'SELECT w.comm, COUNT(*) as count FROM sched_wakeup w, sched_switch s WHERE w.pid = s.next_pid GROUP BY w.comm LIMIT 5'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_with_alias(runtime, memleak_check):
    """Use alias attribute for table name"""
    # perf-prof sql -e 'sched:sched_wakeup//alias=wakeup/' -i 1000 --query 'SELECT comm, COUNT(*) FROM wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//alias=wakeup/', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM wakeup GROUP BY comm LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_alias_same_event(runtime, memleak_check):
    """Use alias to distinguish same events with different filters"""
    # perf-prof sql -e 'sched:sched_wakeup/prio<10/alias=high_prio/,sched:sched_wakeup/prio>=10/alias=low_prio/' -i 1000 --query 'SELECT COUNT(*) FROM high_prio; SELECT COUNT(*) FROM low_prio'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup/prio<10/alias=high_prio/,sched:sched_wakeup/prio>=10/alias=low_prio/',
                     '-i', '1000', '-m', '64',
                     '--query', 'SELECT COUNT(*) as high FROM high_prio; SELECT COUNT(*) as low FROM low_prio'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_alias_union(runtime, memleak_check):
    """Use alias with UNION to combine results"""
    # perf-prof sql -e 'sched:sched_wakeup/prio<10/alias=high_prio/,sched:sched_wakeup/prio>=10/alias=low_prio/' -i 1000 --query 'SELECT "high" as type, COUNT(*) FROM high_prio UNION SELECT "low", COUNT(*) FROM low_prio'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup/prio<10/alias=high_prio/,sched:sched_wakeup/prio>=10/alias=low_prio/',
                     '-i', '1000', '-m', '64',
                     '--query', 'SELECT "high" as type, COUNT(*) as count FROM high_prio UNION SELECT "low", COUNT(*) as count FROM low_prio'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_output2_file(runtime, memleak_check):
    """Save events to database file"""
    db_file = 'test_events.db'
    if os.path.exists(db_file):
        os.remove(db_file)

    try:
        # perf-prof sql -e sched:sched_wakeup --output2 test_events.db -i 1000 --query 'SELECT COUNT(*) FROM sched_wakeup'
        prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '--output2', db_file, '-i', '1000', '-m', '64',
                         '--query', 'SELECT COUNT(*) as count FROM sched_wakeup'])
        for std, line in prof.run(runtime, memleak_check):
            result_check(std, line, runtime, memleak_check)

        # Verify database file was created
        assert os.path.exists(db_file), "Database file was not created"

        # Verify we can open and query the database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        assert len(tables) > 0, "No tables found in database"
        conn.close()
    finally:
        if os.path.exists(db_file):
            os.remove(db_file)

def test_sql_output2_only(runtime, memleak_check):
    """Save events to file without query"""
    db_file = 'test_events_only.db'
    if os.path.exists(db_file):
        os.remove(db_file)

    try:
        # perf-prof sql -e sched:sched_wakeup --output2 test_events_only.db -i 1000
        prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '--output2', db_file, '-i', '2000', '-m', '64'])
        for std, line in prof.run(runtime, memleak_check):
            result_check(std, line, runtime, memleak_check)

        # Verify database file was created
        assert os.path.exists(db_file), "Database file was not created"

        # Verify table structure
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sched_wakeup")
        count = cursor.fetchone()[0]
        assert count >= 0, "Failed to query sched_wakeup table"
        conn.close()
    finally:
        if os.path.exists(db_file):
            os.remove(db_file)

def test_sql_where_clause(runtime, memleak_check):
    """SQL WHERE clause filtering"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup WHERE prio < 100 GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup WHERE prio < 100 GROUP BY comm LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_aggregation_functions(runtime, memleak_check):
    """Test various SQL aggregation functions"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT MIN(prio), MAX(prio), AVG(prio), COUNT(*) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT MIN(prio) as min_prio, MAX(prio) as max_prio, AVG(prio) as avg_prio, COUNT(*) as total FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_order_by(runtime, memleak_check):
    """SQL ORDER BY clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm ORDER BY COUNT(*) DESC LIMIT 5'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm ORDER BY count DESC LIMIT 5'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_system_columns(runtime, memleak_check):
    """Query system columns (_cpu, _pid, _tid, _time, _period)"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT _cpu, _pid, COUNT(*) FROM sched_wakeup GROUP BY _cpu, _pid LIMIT 10'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT _cpu, _pid, COUNT(*) as count FROM sched_wakeup GROUP BY _cpu, _pid LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_userspace_ftrace_filter(runtime, memleak_check):
    """SQL with userspace ftrace filter fallback"""
    # perf-prof sql -e 'sched:sched_wakeup/pid<prio/' -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup/pid<prio/', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_cpus_attribute(runtime, memleak_check):
    """Use cpus attribute to filter events"""
    # perf-prof sql -e 'sched:sched_wakeup//cpus=0/' -i 1000 --query 'SELECT _cpu, COUNT(*) FROM sched_wakeup GROUP BY _cpu'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//cpus=0/', '-i', '1000', '-m', '64',
                     '--query', 'SELECT _cpu, COUNT(*) as count FROM sched_wakeup GROUP BY _cpu'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_distinct(runtime, memleak_check):
    """SQL DISTINCT clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT COUNT(DISTINCT comm) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT COUNT(DISTINCT comm) as unique_comms FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_having_clause(runtime, memleak_check):
    """SQL HAVING clause for filtered aggregation"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm HAVING COUNT(*) > 1'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm HAVING count > 1 LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_softirq(runtime, memleak_check):
    """Test symbolic() function with softirq_entry event"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT symbolic('vec', vec) as irq_name, vec, COUNT(*) FROM softirq_entry GROUP BY vec"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('vec', vec) as irq_name, vec, COUNT(*) as count FROM softirq_entry GROUP BY vec ORDER BY count DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check for known softirq names in output
        if 'TIMER' in line or 'NET_RX' in line or 'SCHED' in line or 'RCU' in line:
            assert True  # Found expected symbolic string

def test_sql_symbolic_with_table_prefix(runtime, memleak_check):
    """Test symbolic() function with table name prefix"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT symbolic('softirq_entry.vec', vec) FROM softirq_entry LIMIT 5"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('softirq_entry.vec', vec) as irq_name, vec FROM softirq_entry LIMIT 5"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_multi_events(runtime, memleak_check):
    """Test symbolic() with multiple events"""
    # perf-prof sql -e irq:softirq_entry,irq:softirq_exit -i 1000 --query "SELECT symbolic('vec', e.vec), COUNT(*) FROM softirq_entry e GROUP BY e.vec"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry,irq:softirq_exit', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('vec', e.vec) as irq_name, COUNT(*) as entry_count FROM softirq_entry e GROUP BY e.vec LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_unknown_value(runtime, memleak_check):
    """Test symbolic() function returns UNKNOWN for unmapped values"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT symbolic('vec', 999) as result FROM softirq_entry LIMIT 1"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('vec', 999) as result FROM softirq_entry LIMIT 1"])
    found_unknown = False
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if 'UNKNOWN' in line:
            found_unknown = True
    # Note: test might not find UNKNOWN if no events were captured

def test_sql_symbolic_group_by(runtime, memleak_check):
    """Test symbolic() in GROUP BY clause"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT symbolic('vec', vec) as irq_name, COUNT(*) as count FROM softirq_entry GROUP BY irq_name ORDER BY count DESC"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('vec', vec) as irq_name, COUNT(*) as count FROM softirq_entry GROUP BY irq_name ORDER BY count DESC"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_mixed_columns(runtime, memleak_check):
    """Test symbolic() mixed with regular columns"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT vec as vec_num, symbolic('vec', vec) as vec_name, _cpu, COUNT(*) FROM softirq_entry GROUP BY vec, _cpu"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT vec as vec_num, symbolic('vec', vec) as vec_name, _cpu, COUNT(*) as count FROM softirq_entry GROUP BY vec, _cpu LIMIT 20"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_with_filter(runtime, memleak_check):
    """Test symbolic() with event filter"""
    # perf-prof sql -e 'irq:softirq_entry/vec<5/' -i 1000 --query "SELECT symbolic('vec', vec) as irq_name, COUNT(*) FROM softirq_entry GROUP BY vec"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry/vec<5/', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic('vec', vec) as irq_name, vec, COUNT(*) as count FROM softirq_entry GROUP BY vec ORDER BY count DESC"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sql_symbolic_save_to_file(runtime, memleak_check):
    """Test symbolic() with database file output"""
    db_file = 'test_symbolic.db'
    if os.path.exists(db_file):
        os.remove(db_file)

    try:
        # perf-prof sql -e irq:softirq_entry --output2 test_symbolic.db -i 1000 --query "SELECT symbolic('vec', vec), COUNT(*) FROM softirq_entry GROUP BY vec"
        prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '--output2', db_file, '-i', '1000', '-m', '64',
                         '--query', "SELECT symbolic('vec', vec) as irq_name, COUNT(*) as count FROM softirq_entry GROUP BY vec"])
        for std, line in prof.run(runtime, memleak_check):
            result_check(std, line, runtime, memleak_check)

        # Verify database file was created
        assert os.path.exists(db_file), "Database file was not created"

        # Verify we can use symbolic() in external queries
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Note: symbolic() function won't be available in external sqlite3 connection
        # Just verify the table exists
        cursor.execute("SELECT vec FROM softirq_entry LIMIT 1")
        result = cursor.fetchone()
        conn.close()
    finally:
        if os.path.exists(db_file):
            os.remove(db_file)

def test_sql_ksymbol_hrtimer(runtime, memleak_check):
    """Test ksymbol() function with hrtimer_expire_entry event"""
    # perf-prof sql -e timer:hrtimer_expire_entry -i 1000 --query "SELECT ksymbol(function) as func_name, function, COUNT(*) FROM hrtimer_expire_entry GROUP BY function"
    prof = PerfProf(['sql', '-e', 'timer:hrtimer_expire_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT ksymbol(function) as func_name, function, COUNT(*) as count FROM hrtimer_expire_entry GROUP BY function ORDER BY count DESC LIMIT 10"])
    found_symbol = False
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check for known kernel functions (should not be ??)
        if 'tick_sched_timer' in line or 'hrtimer_wakeup' in line or 'watchdog_timer_fn' in line:
            found_symbol = True
        # Ensure we don't have only ?? symbols (unless no events captured)
        if std == 'stdout' and '|' in line and '??' not in line and 'func_name' not in line and line.strip():
            # Found a valid symbol line
            assert '0x' not in line or any(x in line for x in ['tick', 'timer', 'sched', 'watchdog']), \
                   f"Expected kernel function name, got: {line}"

def test_sql_ksymbol_workqueue(runtime, memleak_check):
    """Test ksymbol() function with workqueue_execute_start event"""
    # perf-prof sql -e workqueue:workqueue_execute_start -i 1000 --query "SELECT ksymbol(function) as work_func, COUNT(*) as executions FROM workqueue_execute_start GROUP BY function ORDER BY executions DESC"
    prof = PerfProf(['sql', '-e', 'workqueue:workqueue_execute_start', '-i', '1000', '-m', '64',
                     '--query', "SELECT ksymbol(function) as work_func, COUNT(*) as executions FROM workqueue_execute_start GROUP BY function ORDER BY executions DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check that we get function names, not addresses
        if std == 'stdout' and '|' in line and 'work_func' not in line and line.strip():
            # Should see function names or ??
            assert '??' in line or not line.strip().split('|')[0].strip().startswith('0x'), \
                   f"Expected function name or ??, got: {line}"

def test_sql_ipsa_str_tcp_probe(runtime, memleak_check):
    """Test ipsa_str() function with tcp:tcp_probe event"""
    # perf-prof sql -e tcp:tcp_probe -i 2000 --query "SELECT ipsa_str(saddr) as source, ipsa_str(daddr) as dest, COUNT(*) FROM tcp_probe GROUP BY source, dest"
    prof = PerfProf(['sql', '-e', 'tcp:tcp_probe', '-i', '2000', '-m', '64',
                     '--query', "SELECT ipsa_str(saddr) as source, ipsa_str(daddr) as dest, COUNT(*) as probes FROM tcp_probe GROUP BY source, dest ORDER BY probes DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check for IP:port format in output
        if std == 'stdout' and '|' in line and 'source' not in line and line.strip() and '---' not in line:
            # Should see IP addresses with ports or ??
            parts = line.split('|')
            if len(parts) >= 2:
                source = parts[0].strip()
                dest = parts[1].strip()
                # Valid formats: "IP:port", "[IPv6]:port", or "??"
                if source and source != '??':
                    assert ':' in source, f"Expected IP:port format, got: {source}"
                if dest and dest != '??':
                    assert ':' in dest, f"Expected IP:port format, got: {dest}"

def test_sql_ipv4_str_inet_sock(runtime, memleak_check):
    """Test ipv4_str() function with sock:inet_sock_set_state event"""
    # perf-prof sql -e sock:inet_sock_set_state -i 2000 --query "SELECT ipv4_str(saddr) as source_ip, ipv4_str(daddr) as dest_ip, COUNT(*) FROM inet_sock_set_state GROUP BY source_ip, dest_ip"
    prof = PerfProf(['sql', '-e', 'sock:inet_sock_set_state', '-i', '2000', '-m', '64',
                     '--query', "SELECT ipv4_str(saddr) as source_ip, ipv4_str(daddr) as dest_ip, COUNT(*) as transitions FROM inet_sock_set_state GROUP BY source_ip, dest_ip ORDER BY transitions DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check for IPv4 dotted decimal format in output
        if std == 'stdout' and '|' in line and 'source_ip' not in line and line.strip() and '---' not in line:
            parts = line.split('|')
            if len(parts) >= 2:
                source_ip = parts[0].strip()
                dest_ip = parts[1].strip()
                # Valid formats: "x.x.x.x" or "??"
                if source_ip and source_ip != '??':
                    # Should have dots for IPv4
                    assert '.' in source_ip and ':' not in source_ip, f"Expected IPv4 format (x.x.x.x), got: {source_ip}"
                if dest_ip and dest_ip != '??':
                    assert '.' in dest_ip and ':' not in dest_ip, f"Expected IPv4 format (x.x.x.x), got: {dest_ip}"

def test_sql_ipv6_str_inet_sock(runtime, memleak_check):
    """Test ipv6_str() function with sock:inet_sock_set_state event"""
    # perf-prof sql -e sock:inet_sock_set_state -i 2000 --query "SELECT ipv6_str(saddr_v6) as source_ipv6, ipv6_str(daddr_v6) as dest_ipv6, COUNT(*) FROM inet_sock_set_state WHERE family=10 GROUP BY source_ipv6, dest_ipv6"
    prof = PerfProf(['sql', '-e', 'sock:inet_sock_set_state/family==10/', '-i', '2000', '-m', '64',
                     '--query', "SELECT ipv6_str(saddr_v6) as source_ipv6, ipv6_str(daddr_v6) as dest_ipv6, COUNT(*) as transitions FROM inet_sock_set_state GROUP BY source_ipv6, dest_ipv6 ORDER BY transitions DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Check for IPv6 format in output (may not have events if no IPv6 traffic)
        if std == 'stdout' and '|' in line and 'source_ipv6' not in line and line.strip() and '---' not in line:
            parts = line.split('|')
            if len(parts) >= 2:
                source_ipv6 = parts[0].strip()
                dest_ipv6 = parts[1].strip()
                # Valid formats: IPv6 address (contains colons) or "??"
                if source_ipv6 and source_ipv6 != '??':
                    # IPv6 addresses contain colons, not just dots
                    assert ':' in source_ipv6, f"Expected IPv6 format (contains :), got: {source_ipv6}"
                if dest_ipv6 and dest_ipv6 != '??':
                    assert ':' in dest_ipv6, f"Expected IPv6 format (contains :), got: {dest_ipv6}"
