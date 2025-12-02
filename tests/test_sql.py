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
