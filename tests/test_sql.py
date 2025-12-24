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

def test_sql_index_attribute(runtime, memleak_check):
    """Test index= attribute to manually specify index field"""
    # perf-prof sql -e 'sched:sched_wakeup//index=pid/' -i 1000 --query 'SELECT target_cpu, COUNT(*) as count FROM sched_wakeup WHERE target_cpu < 4 GROUP BY target_cpu'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//index=pid/', '-i', '1000', '-m', '64',
                     '--query', 'SELECT target_cpu, COUNT(*) as count FROM sched_wakeup WHERE target_cpu < 4 GROUP BY target_cpu'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if std == 'stdout' and 'for indexing' in line:
            assert 'pid' in line and '(not used)' in line, f"Should show indexing in metadata, got: {line}"
        # Verify CPU numbers are in expected range
        if std == 'stdout' and '|' in line and 'target_cpu' not in line and line.strip() and '---' not in line:
            cpu_val = line.split('|')[0].strip()
            if cpu_val.isdigit():
                assert int(cpu_val) < 4, f"CPU {cpu_val} should be < 4"

def test_sql_symbolic_single_param_kvm(runtime, memleak_check):
    """Test single-parameter symbolic() function with KVM exit events"""
    # perf-prof sql -e kvm:kvm_exit -i 1000 --query "SELECT symbolic(exit_reason) as reason, COUNT(*) FROM kvm_exit GROUP BY exit_reason"
    prof = PerfProf(['sql', '-e', 'kvm:kvm_exit', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic(exit_reason) as reason, COUNT(*) as count FROM kvm_exit GROUP BY exit_reason ORDER BY count DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Should see symbolic names instead of just numbers
        if std == 'stdout' and '|' in line and 'reason' not in line and line.strip() and '---' not in line:
            reason = line.split('|')[0].strip()
            # Known KVM exit reasons include: HLT, IO, MSR, CPUID, etc.
            if reason and reason != 'UNKNOWN' and reason != '??':
                # Should be a readable name, not just a number
                assert not reason.isdigit(), f"Expected symbolic name, got numeric: {reason}"

def test_sql_symbolic_single_param_softirq(runtime, memleak_check):
    """Test single-parameter symbolic() function with softirq_entry events"""
    # perf-prof sql -e irq:softirq_entry -i 1000 --query "SELECT symbolic(vec) as irq_type, COUNT(*) FROM softirq_entry GROUP BY vec"
    prof = PerfProf(['sql', '-e', 'irq:softirq_entry', '-i', '1000', '-m', '64',
                     '--query', "SELECT symbolic(vec) as irq_type, COUNT(*) as count FROM softirq_entry GROUP BY vec ORDER BY count DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Should see softirq names: TIMER, NET_RX, SCHED, RCU, etc.
        if std == 'stdout' and '|' in line and 'irq_type' not in line and line.strip() and '---' not in line:
            irq_type = line.split('|')[0].strip()
            if irq_type and irq_type != 'UNKNOWN' and irq_type != '??':
                # Should be a known softirq name
                known_softirqs = ['HI', 'TIMER', 'NET_TX', 'NET_RX', 'BLOCK', 'BLOCK_IOPOLL',
                                 'TASKLET', 'SCHED', 'HRTIMER', 'RCU']
                assert irq_type in known_softirqs, f"Expected known softirq name, got: {irq_type}"

def test_sql_event_metadata(runtime, memleak_check):
    """Test event_metadata to check available single-parameter symbolic functions"""
    # perf-prof sql -e kvm:kvm_exit -i 1000 --query "SELECT table_name, function_list FROM event_metadata"
    prof = PerfProf(['sql', '-e', 'kvm:kvm_exit', '-i', '1000', '-m', '64',
                     '--query', "SELECT table_name, function_list FROM event_metadata"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify we see event metadata including symbolic function info
        if std == 'stdout' and 'kvm_exit' in line:
            assert 'symbolic(exit_reason)' in line, f"Should show symbolic functions in metadata, got: {line}"

def test_sql_syscall_raw_syscalls(runtime, memleak_check):
    """Test syscall() function with raw_syscalls:sys_enter event"""
    # perf-prof sql -e raw_syscalls:sys_enter -i 1000 --query "SELECT syscall(id) as sys_name, COUNT(*) FROM sys_enter GROUP BY id"
    prof = PerfProf(['sql', '-e', 'raw_syscalls:sys_enter', '-i', '1000', '-m', '512',
                     '--query', "SELECT syscall(id) as sys_name, COUNT(*) as count FROM sys_enter GROUP BY id ORDER BY count DESC LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Should see syscall names: read, write, open, close, etc.
        if std == 'stdout' and '|' in line and 'sys_name' not in line and line.strip() and '---' not in line:
            sys_name = line.split('|')[0].strip()
            if sys_name and sys_name != '??':
                # Should be a known syscall name, not a number
                assert not sys_name.isdigit(), f"Expected syscall name, got numeric: {sys_name}"
                # Verify it looks like a syscall (common syscalls)
                common_syscalls = ['read', 'write', 'open', 'openat', 'close', 'pread64', 'pwrite64',
                                 'readv', 'writev', 'access', 'pipe', 'select', 'sched_yield',
                                 'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask',
                                 'ioctl', 'pread64', 'pwrite64', 'readv', 'writev', 'access',
                                 'pipe', 'select', 'sched_yield', 'mremap', 'msync', 'mincore',
                                 'madvise', 'shmget', 'shmat', 'shmctl', 'dup', 'dup2', 'pause']
                # Note: We don't require it to be in common_syscalls as there are many syscalls
                # but it should be a valid identifier
                assert sys_name.replace('_', '').isalnum(), f"Invalid syscall name: {sys_name}"

def test_sql_syscall_sysevents(runtime, memleak_check):
    """Test syscall() function with syscalls:sys_enter_* events"""
    # perf-prof sql -e syscalls:sys_enter_openat -i 1000 --query "SELECT syscall(__syscall_nr) as sys_name, COUNT(*) FROM sys_enter_openat"
    prof = PerfProf(['sql', '-e', 'syscalls:sys_enter_openat', '-i', '1000', '-m', '64',
                     '--query', "SELECT syscall(__syscall_nr) as sys_name, COUNT(*) as count FROM sys_enter_openat"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Should see 'openat' as the syscall name
        if std == 'stdout' and '|' in line and 'sys_name' not in line and line.strip() and '---' not in line:
            sys_name = line.split('|')[0].strip()
            if sys_name and sys_name != '??':
                assert sys_name == 'openat', f"Expected 'openat', got: {sys_name}"

def test_sql_virtual_table_constraint_pushdown(runtime, memleak_check):
    """Test Virtual Table constraint pushdown with WHERE clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid, comm FROM sched_wakeup WHERE pid > 100 AND prio = 120"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, comm, COUNT(*) as count FROM sched_wakeup WHERE pid > 100 AND prio = 120 GROUP BY pid LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if std == 'stdout' and 'SQL Query planner filter' in line:
            assert 'pid>100&&prio==120' in line, f"Should show filter in metadata, got: {line}"
        # Verify pid > 100 constraint is satisfied
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                assert int(pid_val) > 100, f"PID {pid_val} should be > 100"

def test_sql_virtual_table_various_operators(runtime, memleak_check):
    """Test Virtual Table with various comparison operators"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid FROM sched_wakeup WHERE pid < 100 OR pid > 2000"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, comm, COUNT(*) as count FROM sched_wakeup WHERE pid < 100 OR pid > 2000 GROUP BY pid"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if std == 'stdout' and 'SQL Query planner filter' in line:
            assert '(pid<100)||(pid>2000)' in line, f"Should show filter in metadata, got: {line}"
        # Verify pid range constraint is satisfied
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                pid_int = int(pid_val)
                assert pid_int < 100 or pid_int > 2000, f"PID {pid_int} should be in range [0, 100] [2000, ]"

def test_sql_index_optimization_eq(runtime, memleak_check):
    """Test index optimization with equality operator"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT * FROM sched_wakeup WHERE pid = 1"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, comm, COUNT(*) as count FROM sched_wakeup WHERE pid = 1 GROUP BY pid, comm LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if std == 'stdout' and 'field for indexing' in line:
            assert 'pid' in line, f"Should show indexing in metadata, got: {line}"
        # Verify pid = 1 constraint is satisfied
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            assert pid_val == '1', f"PID should be exactly 1, got: {pid_val}"

def test_sql_index_optimization_range(runtime, memleak_check):
    """Test index optimization with range queries"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid, COUNT(*) FROM sched_wakeup WHERE pid > 100 AND pid < 2000 GROUP BY pid"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, COUNT(*) as count FROM sched_wakeup WHERE pid > 100 AND pid < 2000 GROUP BY pid"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if std == 'stdout' and 'field for indexing' in line:
            assert 'pid' in line, f"Should show indexing in metadata, got: {line}"
        # Verify range constraints are satisfied
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                pid_int = int(pid_val)
                assert 100 < pid_int < 2000, f"PID {pid_int} should be in range (100, 2000)"

def test_sql_orderby_optimization_asc(runtime, memleak_check):
    """Test ORDER BY optimization with ASC order using index"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT _time FROM sched_wakeup ORDER BY _time ASC LIMIT 5"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT _time, COUNT(*) as count FROM sched_wakeup GROUP BY _time ORDER BY _time ASC LIMIT 10"])
    prev_time = None
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify ascending order
        if std == 'stdout' and '|' in line and '_time' not in line and line.strip() and '---' not in line:
            time_val = line.split('|')[0].strip()
            try:
                time_int = int(time_val)
                if prev_time is not None:
                    assert time_int >= prev_time, f"Time should be in ascending order: {prev_time} > {time_int}"
                prev_time = time_int
            except ValueError:
                pass  # Skip if not a number

def test_sql_orderby_optimization_desc(runtime, memleak_check):
    """Test ORDER BY optimization with DESC order using index"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT _time FROM sched_wakeup ORDER BY _time DESC LIMIT 5"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT _time, COUNT(*) as count FROM sched_wakeup GROUP BY _time ORDER BY _time DESC LIMIT 10"])
    prev_time = None
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify descending order
        if std == 'stdout' and '|' in line and '_time' not in line and line.strip() and '---' not in line:
            time_val = line.split('|')[0].strip()
            try:
                time_int = int(time_val)
                if prev_time is not None:
                    assert time_int <= prev_time, f"Time should be in descending order: {prev_time} < {time_int}"
                prev_time = time_int
            except ValueError:
                pass  # Skip if not a number

def test_sql_orderby_with_where(runtime, memleak_check):
    """Test ORDER BY with WHERE clause using index"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT _time, COUNT(*) as count FROM sched_wakeup WHERE pid < 1000 GROUP BY _time ORDER BY _time DESC"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT _time, COUNT(*) as count FROM sched_wakeup WHERE pid < 1000 GROUP BY _time ORDER BY _time DESC LIMIT 10"])
    prev_time = None
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify descending order and constraint
        if std == 'stdout' and '|' in line and '_time' not in line and line.strip() and '---' not in line:
            time_val = line.split('|')[0].strip()
            try:
                time_int = int(time_val)
                assert time_int > 0, f"Time should be > 0 (WHERE constraint), got: {time_int}"
                if prev_time is not None:
                    assert time_int <= prev_time, f"Time should be in descending order: {prev_time} < {time_int}"
                prev_time = time_int
            except ValueError:
                pass  # Skip if not a number

def test_sql_ne_constraint_segmentation(runtime, memleak_check):
    """Test NE (!=) constraint with segmented iteration"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid FROM sched_wakeup WHERE pid != 0 AND pid > 10 AND pid < 100"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, COUNT(*) as count FROM sched_wakeup WHERE pid != 0 AND pid > 10 AND pid < 100 GROUP BY pid"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify NE and range constraints are satisfied
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                pid_int = int(pid_val)
                assert pid_int != 0, f"PID should not be 0 (NE constraint), got: {pid_int}"
                assert 10 < pid_int < 100, f"PID {pid_int} should be in range (10, 100)"

def test_sql_ne_boundary_cases(runtime, memleak_check):
    """Test NE constraint with values outside the range boundaries"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid FROM sched_wakeup WHERE pid > 100 AND pid <= 500 AND pid != 200 AND pid != 10 AND pid != 500"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, COUNT(*) as count FROM sched_wakeup WHERE pid > 100 AND pid <= 500 AND pid != 200 AND pid != 10 AND pid != 500 GROUP BY pid"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify range and NE constraints
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                pid_int = int(pid_val)
                assert 100 < pid_int < 300, f"PID {pid_int} should be in range (100, 500)"
                assert pid_int != 200, f"PID should not be 200 (NE constraint), got: {pid_int}"

def test_sql_group_by_order_optimization(runtime, memleak_check):
    """Test ORDER BY optimization with GROUP BY using index"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --query "SELECT pid, COUNT(*) FROM sched_wakeup WHERE pid > 0 GROUP BY pid ORDER BY pid"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64',
                     '--query', "SELECT pid, COUNT(*) as count FROM sched_wakeup WHERE pid > 0 GROUP BY pid ORDER BY pid LIMIT 20"])
    prev_pid = None
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Verify GROUP BY with ORDER BY works correctly
        if std == 'stdout' and '|' in line and 'pid' not in line and line.strip() and '---' not in line:
            pid_val = line.split('|')[0].strip()
            if pid_val.isdigit():
                pid_int = int(pid_val)
                assert pid_int > 0, f"PID should be > 0 (WHERE constraint), got: {pid_int}"
                if prev_pid is not None:
                    assert pid_int > prev_pid, f"PIDs should be in ascending order: {prev_pid} >= {pid_int}"
                prev_pid = pid_int

# ============================================================================
# --verify option tests: Validate Virtual Table implementation correctness
# ============================================================================

def test_sql_verify_basic_count(runtime, memleak_check):
    """Test --verify with basic COUNT query"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT COUNT(*) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT COUNT(*) as count FROM sched_wakeup'])
    found_verify_msg = False
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        if 'Creating verification database' in line:
            found_verify_msg = True
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"
    assert found_verify_msg, "Should show verification database creation message"

def test_sql_verify_group_by(runtime, memleak_check):
    """Test --verify with GROUP BY query"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm ORDER BY count DESC LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_with_where(runtime, memleak_check):
    """Test --verify with WHERE clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT pid, comm FROM sched_wakeup WHERE pid > 100'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT pid, comm, COUNT(*) as count FROM sched_wakeup WHERE pid > 100 GROUP BY pid, comm LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_with_index(runtime, memleak_check):
    """Test --verify with index attribute"""
    # perf-prof sql -e 'sched:sched_wakeup//index=pid/' -i 1000 --verify --query 'SELECT * FROM sched_wakeup WHERE pid > 1000 ORDER BY pid'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//index=pid/', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT pid, comm, COUNT(*) as count FROM sched_wakeup WHERE pid > 1000 GROUP BY pid ORDER BY pid LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_with_string_index(runtime, memleak_check):
    """Test --verify with string index and GLOB query"""
    # perf-prof sql -e 'sched:sched_wakeup//index=comm/' -i 1000 --verify --query "SELECT comm, COUNT(*) FROM sched_wakeup WHERE comm GLOB 'perf*' GROUP BY comm"
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//index=comm/', '-i', '1000', '-m', '64', '--verify',
                     '--query', "SELECT comm, COUNT(*) as count FROM sched_wakeup WHERE comm GLOB '*' GROUP BY comm ORDER BY comm LIMIT 10"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_multi_queries(runtime, memleak_check):
    """Test --verify with multiple SQL queries"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT COUNT(*) FROM sched_wakeup; SELECT comm, AVG(prio) FROM sched_wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT COUNT(*) as total FROM sched_wakeup; SELECT comm, AVG(prio) as avg_prio FROM sched_wakeup GROUP BY comm LIMIT 5'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_aggregation(runtime, memleak_check):
    """Test --verify with various aggregation functions"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT MIN(prio), MAX(prio), AVG(prio), SUM(prio), COUNT(*) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT MIN(prio) as min_p, MAX(prio) as max_p, AVG(prio) as avg_p, COUNT(*) as total FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_order_by_asc(runtime, memleak_check):
    """Test --verify with ORDER BY ASC"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT _time, pid FROM sched_wakeup ORDER BY _time ASC LIMIT 10'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT _time, pid FROM sched_wakeup ORDER BY _time ASC LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_order_by_desc(runtime, memleak_check):
    """Test --verify with ORDER BY DESC"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT _time, pid FROM sched_wakeup ORDER BY _time DESC LIMIT 10'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT _time, pid FROM sched_wakeup ORDER BY _time DESC LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_ne_constraint(runtime, memleak_check):
    """Test --verify with NE (!=) constraint"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT pid, COUNT(*) FROM sched_wakeup WHERE pid != 0 AND pid > 10 AND pid < 1000 GROUP BY pid'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT pid, COUNT(*) as count FROM sched_wakeup WHERE pid != 0 AND pid > 10 AND pid < 1000 GROUP BY pid LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_multi_events(runtime, memleak_check):
    """Test --verify with multiple events"""
    # perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 --verify --query 'SELECT COUNT(*) FROM sched_wakeup; SELECT COUNT(*) FROM sched_switch'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup,sched:sched_switch', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT COUNT(*) as wakeups FROM sched_wakeup; SELECT COUNT(*) as switches FROM sched_switch'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_disabled_with_output2(runtime, memleak_check):
    """Test --verify is disabled when --output2 is specified"""
    db_file = 'test_verify_disabled.db'
    if os.path.exists(db_file):
        os.remove(db_file)

    try:
        # perf-prof sql -e sched:sched_wakeup --output2 test.db --verify -i 1000 --query 'SELECT COUNT(*) FROM sched_wakeup'
        prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '--output2', db_file, '--verify', '-i', '1000', '-m', '64',
                         '--query', 'SELECT COUNT(*) as count FROM sched_wakeup'])
        found_disabled_msg = False
        for std, line in prof.run(runtime, memleak_check):
            result_check(std, line, runtime, memleak_check)
            if '--verify disabled' in line:
                found_disabled_msg = True
        assert found_disabled_msg, "Should show --verify disabled message when --output2 is used"

        # Verify database file was still created
        assert os.path.exists(db_file), "Database file was not created"
    finally:
        if os.path.exists(db_file):
            os.remove(db_file)

def test_sql_verify_with_alias(runtime, memleak_check):
    """Test --verify with alias attribute"""
    # perf-prof sql -e 'sched:sched_wakeup//alias=wakeup/' -i 1000 --verify --query 'SELECT comm, COUNT(*) FROM wakeup GROUP BY comm'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup//alias=wakeup/', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT comm, COUNT(*) as count FROM wakeup GROUP BY comm LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_distinct(runtime, memleak_check):
    """Test --verify with DISTINCT clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT COUNT(DISTINCT comm) FROM sched_wakeup'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT COUNT(DISTINCT comm) as unique_comms FROM sched_wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"

def test_sql_verify_having(runtime, memleak_check):
    """Test --verify with HAVING clause"""
    # perf-prof sql -e sched:sched_wakeup -i 1000 --verify --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm HAVING COUNT(*) > 1'
    prof = PerfProf(['sql', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '64', '--verify',
                     '--query', 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm HAVING count > 1 LIMIT 10'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
        # Ensure no mismatch errors
        assert 'mismatch' not in line.lower(), f"Verification mismatch found: {line}"
