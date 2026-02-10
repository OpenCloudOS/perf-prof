#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest
import os
import tempfile
import subprocess
import sys
import glob
import shutil

# Test script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def write_script(content, suffix='.py'):
    """Write a Python script to a temporary file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix='perf_prof_test_')
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path

# Basic event counting script
COUNTER_SCRIPT = '''
count = 0

def __sample__(event):
    global count
    count += 1

def __interval__():
    global count
    print(f"Events: {count}")
    count = 0

def __exit__():
    print("Done")
'''

# Event-specific handler script
EVENT_HANDLER_SCRIPT = '''
wakeup_count = 0
switch_count = 0

def sched__sched_wakeup(event):
    global wakeup_count
    wakeup_count += 1
    # Access fields to verify lazy evaluation
    pid = event.pid
    comm = event.comm

def sched__sched_switch(event):
    global switch_count
    switch_count += 1
    # Access fields
    prev_comm = event.prev_comm
    next_comm = event.next_comm

def __interval__():
    global wakeup_count, switch_count
    print(f"wakeup: {wakeup_count}, switch: {switch_count}")
    wakeup_count = 0
    switch_count = 0
'''

# Field access test script
FIELD_ACCESS_SCRIPT = '''
def __sample__(event):
    # Test various access methods
    pid = event._pid
    tid = event._tid
    cpu = event._cpu
    time = event._time
    period = event._period

    # Test dict-style access
    pid2 = event['_pid']

    # Test get with default
    nonexistent = event.get('nonexistent', -1)

    # Test 'in' operator
    has_pid = '_pid' in event

    # Test keys(), values(), items()
    keys = event.keys()

    # Test len()
    num_fields = len(event)

    # Test iteration
    for name, value in event:
        pass

    # Test to_dict()
    d = event.to_dict()

def __interval__():
    print("field access ok")
'''

# Event print test script
PRINT_SCRIPT = '''
count = 0

def __sample__(event):
    global count
    count += 1
    if count <= 5:
        event.print()

def __interval__():
    print("printed events")
'''

# Callchain test script
CALLCHAIN_SCRIPT = '''
from collections import Counter

stacks = Counter()

def sched__sched_wakeup(event):
    callchain = event.get('_callchain', [])
    if callchain:
        # Build stack signature
        stack = []
        for frame in callchain[:5]:
            if frame['kernel']:
                stack.append(frame['symbol'])
        if stack:
            stacks[' <- '.join(stack)] += 1

def __interval__():
    print(f"Unique stacks: {len(stacks)}")
    for stack, count in stacks.most_common(3):
        print(f"  {count}: {stack[:60]}...")
'''

# Init/Exit test script
INIT_EXIT_SCRIPT = '''
initialized = False

def __init__():
    global initialized
    initialized = True
    print("INIT_CALLED")

def __sample__(event):
    global initialized
    if not initialized:
        raise Exception("Not initialized!")

def __exit__():
    print("EXIT_CALLED")
'''

# Lost events test script
LOST_SCRIPT = '''
lost_count = 0

def __lost__(lost_start, lost_end):
    global lost_count
    lost_count += 1
    print(f"Lost events: start={lost_start}, end={lost_end}")

def __sample__(event):
    pass

def __interval__():
    print(f"Lost callbacks: {lost_count}")
'''

# Alias test script
ALIAS_SCRIPT = '''
wakeup1_count = 0
wakeup2_count = 0

def sched__wakeup1(event):
    global wakeup1_count
    wakeup1_count += 1

def sched__wakeup2(event):
    global wakeup2_count
    wakeup2_count += 1

def __interval__():
    print(f"wakeup1: {wakeup1_count}, wakeup2: {wakeup2_count}")
'''

# Print stat test script (triggered by SIGUSR2)
PRINT_STAT_SCRIPT = '''
total_events = 0

def __sample__(event):
    global total_events
    total_events += 1

def __print_stat__(indent):
    """Called on SIGUSR2 signal."""
    prefix = ' ' * indent
    print(f"{prefix}PRINT_STAT_CALLED")
    print(f"{prefix}Total events: {total_events}", flush=True)

def __interval__():
    print(f"Events: {total_events}", flush=True)
'''

# Script arguments test script
ARGS_SCRIPT = '''
import sys

def __init__():
    print(f"sys.argv = {sys.argv}")
    # Verify arguments were passed
    if len(sys.argv) >= 3:
        print(f"arg1 = {sys.argv[1]}")
        print(f"arg2 = {sys.argv[2]}")

def __sample__(event):
    pass

def __interval__():
    print("args test ok")
'''

# Common fields test script
COMMON_FIELDS_SCRIPT = '''
def __sample__(event):
    # Test common fields from trace_entry
    common_flags = event.common_flags
    common_preempt_count = event.common_preempt_count
    common_pid = event.common_pid

def __interval__():
    print("common fields ok")
'''

# Realtime field test script
REALTIME_SCRIPT = '''
count = 0

def __sample__(event):
    global count
    count += 1
    if count <= 3:
        realtime = event._realtime
        print(f"realtime: {realtime}")

def __interval__():
    print("realtime test ok")
'''


class TestPythonBasic:
    """Basic python profiler tests"""

    def test_help_template(self, runtime, memleak_check):
        """Test help template generation"""
        prof = PerfProf(['python', '-e', 'sched:sched_wakeup', 'help'])
        output = []
        for std, line in prof.run(None, memleak_check):
            output.append(line)
            print(line, end='', flush=True)
        # Check that template was generated
        template = ''.join(output)
        assert 'def __sample__' in template or 'def sched__sched_wakeup' in template

    def test_help_multi_event(self, runtime, memleak_check):
        """Test help template generation with multiple events"""
        prof = PerfProf(['python', '-e', 'sched:sched_wakeup,sched:sched_switch', 'help'])
        output = []
        for std, line in prof.run(None, memleak_check):
            output.append(line)
            print(line, end='', flush=True)
        template = ''.join(output)
        assert 'sched__sched_wakeup' in template
        assert 'sched__sched_switch' in template

    def test_counter_script(self, runtime, memleak_check):
        """Test basic event counting"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_event_specific_handler(self, runtime, memleak_check):
        """Test event-specific handlers"""
        script_path = write_script(EVENT_HANDLER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup,sched:sched_switch', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonFieldAccess:
    """Test PerfEvent field access methods"""

    def test_field_access_methods(self, runtime, memleak_check):
        """Test various field access methods"""
        script_path = write_script(FIELD_ACCESS_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_common_fields(self, runtime, memleak_check):
        """Test access to common trace_entry fields"""
        script_path = write_script(COMMON_FIELDS_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_realtime_field(self, runtime, memleak_check):
        """Test _realtime lazy computed field"""
        script_path = write_script(REALTIME_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonCallbacks:
    """Test callback functions"""

    def test_init_exit_callbacks(self, runtime, memleak_check):
        """Test __init__ and __exit__ callbacks"""
        script_path = write_script(INIT_EXIT_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            init_called = False
            exit_called = False
            for std, line in prof.run(runtime, memleak_check):
                if 'INIT_CALLED' in line:
                    init_called = True
                if 'EXIT_CALLED' in line:
                    exit_called = True
                result_check(std, line, runtime, memleak_check)
            # Verify __init__ was called
            assert init_called, "__init__() callback was not called"
            # Verify __exit__ was called
            assert exit_called, "__exit__() callback was not called"
        finally:
            os.unlink(script_path)

    def test_lost_callback(self, runtime, memleak_check):
        """Test __lost__ callback"""
        script_path = write_script(LOST_SCRIPT)
        try:
            # Use small mmap pages to potentially trigger lost events
            # This test intentionally causes lost events to test the __lost__ callback
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup,sched:sched_switch', '-m', '1', '-i', '1000', '--order', script_path])
            for std, line in prof.run(runtime, memleak_check):
                # Allow lost events messages in this test
                if PerfProf.lost_events(line):
                    print(line, end='', flush=True)
                else:
                    result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonPrint:
    """Test event printing"""

    def test_event_print(self, runtime, memleak_check):
        """Test event.print() method"""
        script_path = write_script(PRINT_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonCallchain:
    """Test callchain/stack functionality"""

    def test_callchain_with_g_option(self, runtime, memleak_check):
        """Test callchain with -g option"""
        script_path = write_script(CALLCHAIN_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-g', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_callchain_with_stack_attr(self, runtime, memleak_check):
        """Test callchain with stack attribute"""
        script_path = write_script(CALLCHAIN_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup//stack/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonAlias:
    """Test event alias functionality"""

    def test_alias_handlers(self, runtime, memleak_check):
        """Test alias-specific handlers"""
        script_path = write_script(ALIAS_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup//alias=wakeup1/,sched:sched_wakeup//alias=wakeup2/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_help_with_alias(self, runtime, memleak_check):
        """Test help template with alias"""
        prof = PerfProf(['python', '-e', 'sched:sched_wakeup//alias=mywakeup/', 'help'])
        output = []
        for std, line in prof.run(None, memleak_check):
            output.append(line)
            print(line, end='', flush=True)
        template = ''.join(output)
        assert 'sched__mywakeup' in template


class TestPythonScriptArgs:
    """Test script argument passing"""

    def test_script_arguments(self, runtime, memleak_check):
        """Test passing arguments to script via sys.argv"""
        script_path = write_script(ARGS_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', '--', script_path, '--foo', 'bar'])
            found_args = False
            for std, line in prof.run(runtime, memleak_check):
                if 'arg1 = --foo' in line:
                    found_args = True
                result_check(std, line, runtime, memleak_check)
            # Verify script received the arguments
            assert found_args, "Script arguments were not passed via sys.argv"
        finally:
            os.unlink(script_path)


class TestPythonFilter:
    """Test event filtering"""

    def test_event_filter(self, runtime, memleak_check):
        """Test with trace event filter"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup/pid>0/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_cpu_filter(self, runtime, memleak_check):
        """Test with CPU filter"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0-1', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonAdvanced:
    """Advanced python profiler tests"""

    def test_order_option(self, runtime, memleak_check):
        """Test with --order option"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup,sched:sched_switch', '-C', '0', '-i', '1000', '-m', '128', '--order', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_exit_n_option(self, runtime, memleak_check):
        """Test with -N exit option"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-N', '100', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_multiple_cpus(self, runtime, memleak_check):
        """Test monitoring multiple CPUs"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-i', '1000', '-m', '128', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_user_callchain(self, runtime, memleak_check):
        """Test with user callchain option"""
        script_path = write_script(CALLCHAIN_SCRIPT)
        try:
            # Use larger mmap buffer to avoid lost events with user callchain
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-g', '--user-callchain', '-i', '1000', '-m', '256', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_no_kernel_callchain(self, runtime, memleak_check):
        """Test with no-kernel-callchain option"""
        script_path = write_script(CALLCHAIN_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-g', '--no-kernel-callchain', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonKprobe:
    """Test with kprobe events"""

    def test_kprobe_event(self, runtime, memleak_check):
        """Test with kprobe event"""
        if not PerfProf.pmu_exists('kprobe'):
            pytest.skip("'kprobe' does not exist")

        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'kprobe:try_to_wake_up', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_kretprobe_event(self, runtime, memleak_check):
        """Test with kretprobe event"""
        if not PerfProf.pmu_exists('kprobe'):
            pytest.skip("'kprobe' does not exist")

        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'kretprobe:try_to_wake_up', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)


class TestPythonPrintStat:
    """Test __print_stat__() callback triggered by SIGUSR2"""

    def test_print_stat_callback(self, runtime, memleak_check):
        """Test __print_stat__(indent) callback triggered by SIGUSR2 signal"""
        script_path = write_script(PRINT_STAT_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            print_stat_called = False
            # Use util_interval to automatically send SIGUSR2 periodically
            for std, line in prof.run(runtime, memleak_check, util_interval=2):
                if 'PRINT_STAT_CALLED' in line:
                    print_stat_called = True
                result_check(std, line, runtime, memleak_check)
            # Verify __print_stat__ was called
            assert print_stat_called, "__print_stat__() callback was not triggered by SIGUSR2"
        finally:
            os.unlink(script_path)

    def test_print_stat_with_indent(self, runtime, memleak_check):
        """Test __print_stat__(indent) receives indent parameter"""
        # Script that verifies indent parameter
        indent_script = '''
total_events = 0

def __sample__(event):
    global total_events
    total_events += 1

def __print_stat__(indent):
    """Called on SIGUSR2 signal with indent parameter."""
    # Print a marker with the indent value to verify it was passed
    print(f"INDENT_VALUE={indent}")
    prefix = ' ' * indent
    print(f"{prefix}Stats: {total_events} events", flush=True)

def __interval__():
    print(f"Events: {total_events}", flush=True)
'''
        script_path = write_script(indent_script)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            indent_received = False
            for std, line in prof.run(runtime, memleak_check, util_interval=2):
                if 'INDENT_VALUE=' in line:
                    indent_received = True
                    # The indent value should be an integer
                    indent_str = line.strip().split('=')[1]
                    assert indent_str.isdigit(), f"Indent value should be integer, got: {indent_str}"
                result_check(std, line, runtime, memleak_check)
            assert indent_received, "__print_stat__() did not receive indent parameter"
        finally:
            os.unlink(script_path)

    def test_print_stat_optional(self, runtime, memleak_check):
        """Test that __print_stat__ is optional - SIGUSR2 should not crash without it"""
        # Script without __print_stat__ function
        no_print_stat_script = '''
count = 0

def __sample__(event):
    global count
    count += 1

def __interval__():
    global count
    print(f"Events: {count}", flush=True)
    count = 0
'''
        script_path = write_script(no_print_stat_script)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            # Use util_interval to send SIGUSR2 - should not crash even without __print_stat__
            for std, line in prof.run(runtime, memleak_check, util_interval=2):
                result_check(std, line, runtime, memleak_check)
            # If we reach here without exception, the test passes
        finally:
            os.unlink(script_path)


# Cython module content for testing
CYTHON_MODULE_PYX = '''
count = 0

def __sample__(event):
    global count
    count += 1

def __interval__():
    global count
    print(f"CYTHON_EVENTS: {count}")
    count = 0

def __init__():
    print("CYTHON_INIT_CALLED")

def __exit__():
    print("CYTHON_EXIT_CALLED")
'''


def compile_cython_module(pyx_content, module_name):
    """
    Compile a Cython module and return the path to the .so file.
    Returns None if Cython is not available or compilation fails.
    """
    try:
        import Cython
    except ImportError:
        return None

    # Create temporary directory for compilation
    tmpdir = tempfile.mkdtemp(prefix='perf_prof_cython_')
    pyx_path = os.path.join(tmpdir, f'{module_name}.pyx')
    setup_path = os.path.join(tmpdir, 'setup.py')

    # Write .pyx file
    with open(pyx_path, 'w') as f:
        f.write(pyx_content)

    # Write setup.py
    setup_content = f'''
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize("{module_name}.pyx", language_level=3)
)
'''
    with open(setup_path, 'w') as f:
        f.write(setup_content)

    # Compile the module
    try:
        result = subprocess.run(
            [sys.executable, 'setup.py', 'build_ext', '--inplace'],
            cwd=tmpdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            timeout=60
        )
        if result.returncode != 0:
            print(f"Cython compilation failed: {result.stderr}")
            return None
    except Exception as e:
        print(f"Cython compilation error: {e}")
        return None

    # Find the compiled .so file
    so_files = glob.glob(os.path.join(tmpdir, f'{module_name}*.so'))
    if not so_files:
        print("No .so file found after compilation")
        return None

    return so_files[0], tmpdir


class TestPythonModuleTypes:
    """Test multiple module types support"""

    def test_module_name_only(self, runtime, memleak_check):
        """Test importing module by name only (without extension)"""
        # Create a module in a temporary directory
        tmpdir = tempfile.mkdtemp(prefix='perf_prof_module_')
        module_path = os.path.join(tmpdir, 'testmodule.py')

        module_content = '''
count = 0

def __sample__(event):
    global count
    count += 1

def __interval__():
    global count
    print(f"MODULE_NAME_EVENTS: {count}")
    count = 0

def __init__():
    print("MODULE_NAME_INIT")

def __exit__():
    print("MODULE_NAME_EXIT")
'''
        with open(module_path, 'w') as f:
            f.write(module_content)

        try:
            # Change to tmpdir and import by module name only
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', 'testmodule'])
                init_called = False
                exit_called = False
                loaded_msg = False
                for std, line in prof.run(runtime, memleak_check):
                    if 'MODULE_NAME_INIT' in line:
                        init_called = True
                    if 'MODULE_NAME_EXIT' in line:
                        exit_called = True
                    if 'Loaded module:' in line:
                        loaded_msg = True
                        print(line, end='', flush=True)
                    result_check(std, line, runtime, memleak_check)
                assert init_called, "__init__() was not called"
                assert exit_called, "__exit__() was not called"
                assert loaded_msg, "Module path was not printed"
            finally:
                os.chdir(old_cwd)
        finally:
            os.unlink(module_path)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_loaded_module_path_output(self, runtime, memleak_check):
        """Test that loaded module path is printed"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_path])
            loaded_path_found = False
            for std, line in prof.run(runtime, memleak_check):
                if 'Loaded module:' in line:
                    loaded_path_found = True
                    # Verify the path is in the output
                    assert script_path in line or os.path.basename(script_path).replace('.py', '') in line
                    print(line, end='', flush=True)
                result_check(std, line, runtime, memleak_check)
            assert loaded_path_found, "Module path was not printed on load"
        finally:
            os.unlink(script_path)

    def test_cython_module(self, runtime, memleak_check):
        """Test importing Cython compiled module (.so file)"""
        try:
            import Cython
        except ImportError:
            pytest.skip("Cython not available")

        result = compile_cython_module(CYTHON_MODULE_PYX, 'cython_test_module')
        if result is None:
            pytest.skip("Failed to compile Cython module")

        so_path, tmpdir = result
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', so_path])
            init_called = False
            exit_called = False
            events_counted = False
            for std, line in prof.run(runtime, memleak_check):
                if 'CYTHON_INIT_CALLED' in line:
                    init_called = True
                if 'CYTHON_EXIT_CALLED' in line:
                    exit_called = True
                if 'CYTHON_EVENTS:' in line:
                    events_counted = True
                result_check(std, line, runtime, memleak_check)
            assert init_called, "Cython module __init__() was not called"
            assert exit_called, "Cython module __exit__() was not called"
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_cython_module_by_name(self, runtime, memleak_check):
        """Test importing Cython module by name only"""
        try:
            import Cython
        except ImportError:
            pytest.skip("Cython not available")

        result = compile_cython_module(CYTHON_MODULE_PYX, 'cython_name_test')
        if result is None:
            pytest.skip("Failed to compile Cython module")

        so_path, tmpdir = result
        try:
            # Change to tmpdir and import by module name
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', 'cython_name_test'])
                init_called = False
                for std, line in prof.run(runtime, memleak_check):
                    if 'CYTHON_INIT_CALLED' in line:
                        init_called = True
                    result_check(std, line, runtime, memleak_check)
                assert init_called, "Cython module was not loaded by name"
            finally:
                os.chdir(old_cwd)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_absolute_path_script(self, runtime, memleak_check):
        """Test loading script with absolute path"""
        script_path = write_script(COUNTER_SCRIPT)
        abs_path = os.path.abspath(script_path)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', abs_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_relative_path_script(self, runtime, memleak_check):
        """Test loading script with relative path"""
        # Create script in current directory
        tmpdir = tempfile.mkdtemp(prefix='perf_prof_rel_')
        script_name = 'rel_test_script.py'
        script_path = os.path.join(tmpdir, script_name)

        with open(script_path, 'w') as f:
            f.write(COUNTER_SCRIPT)

        try:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                prof = PerfProf(['python', '-e', 'sched:sched_wakeup', '-C', '0', '-i', '1000', '-m', '64', script_name])
                for std, line in prof.run(runtime, memleak_check):
                    result_check(std, line, runtime, memleak_check)
            finally:
                os.chdir(old_cwd)
        finally:
            os.unlink(script_path)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_module_not_found_error(self, runtime, memleak_check):
        """Test error message when module is not found"""
        prof = PerfProf(['python', '-e', 'sched:sched_wakeup', 'nonexistent_module_xyz123'])
        error_found = False
        for std, line in prof.run(None, memleak_check):
            if 'Failed to load Python module' in line or 'ModuleNotFoundError' in line:
                error_found = True
            print(line, end='', flush=True)
        assert error_found, "Expected error message for non-existent module"


# =============================================================================
# Profiler event source test scripts
# =============================================================================

# Profile event source - basic counting
PROFILE_COUNTER_SCRIPT = '''
count = 0

def profile(event):
    global count
    count += 1

def __interval__():
    global count
    print(f"ProfileEvents: {count}")
    count = 0
'''

# Profile event source - field access
PROFILE_FIELD_SCRIPT = '''
def profile(event):
    # Common fields
    pid = event._pid
    tid = event._tid
    time = event._time
    cpu = event._cpu

    # Profiler-specific fields from sample_type
    pid2 = event.pid
    tid2 = event.tid
    t = event.time
    c = event.cpu
    read = event.read

    # read should be a dict with 'value' key
    assert isinstance(read, dict), f"read should be dict, got {type(read)}"
    assert 'value' in read, f"read dict should have 'value' key, got {read.keys()}"

    # Test dict-style access
    pid3 = event['_pid']

    # Test get with default
    nonexistent = event.get('nonexistent', -1)
    assert nonexistent == -1

    # Test 'in' operator
    assert '_pid' in event
    assert 'pid' in event
    assert 'read' in event

    # Test keys(), len()
    keys = event.keys()
    assert 'pid' in keys
    assert 'read' in keys
    num_fields = len(event)

    # Test to_dict()
    d = event.to_dict()
    assert isinstance(d, dict)

def __interval__():
    print("profile field access ok")
'''

# Page-faults event source - field access
PAGE_FAULTS_FIELD_SCRIPT = '''
def page_faults(event):
    # Common fields
    pid = event._pid
    tid = event._tid
    cpu = event._cpu

    # page-faults specific fields
    ip = event.ip
    addr = event.addr

    assert isinstance(ip, int), f"ip should be int, got {type(ip)}"
    assert isinstance(addr, int), f"addr should be int, got {type(addr)}"

def __interval__():
    print("page-faults field access ok")
'''

# Page-faults with callchain and regs_user
PAGE_FAULTS_CALLCHAIN_SCRIPT = '''
has_callchain = False
has_regs = False

def page_faults(event):
    global has_callchain, has_regs
    callchain = event.get('callchain', None)
    if callchain is not None:
        has_callchain = True
        assert isinstance(callchain, list), f"callchain should be list, got {type(callchain)}"
        if callchain:
            frame = callchain[0]
            assert 'symbol' in frame
            assert 'addr' in frame

    regs = event.get('regs_user', None)
    if regs is not None:
        has_regs = True
        assert isinstance(regs, dict), f"regs_user should be dict, got {type(regs)}"
        assert 'abi' in regs, f"regs_user should have 'abi', got {regs.keys()}"

def __interval__():
    print(f"callchain={has_callchain} regs={has_regs}")
'''

# Profile event source - event.print()
PROFILE_PRINT_SCRIPT = '''
count = 0

def profile(event):
    global count
    count += 1
    if count <= 3:
        event.print()

def __interval__():
    print("profile print ok")
'''

# Combined tracepoint + profiler event source
COMBINED_SCRIPT = '''
tp_count = 0
prof_count = 0

def sched__sched_wakeup(event):
    global tp_count
    tp_count += 1
    # Verify tracepoint fields
    pid = event.pid
    comm = event.comm

def profile(event):
    global prof_count
    prof_count += 1
    # Verify profiler fields
    pid = event.pid
    read = event.read

def __interval__():
    print(f"tp={tp_count} prof={prof_count}")
'''


class TestPythonProfilerEventSource:
    """Test profiler event source (dev_tp) support"""

    def test_profile_basic_counting(self, runtime, memleak_check):
        """Test profile as profiler event source with basic counting"""
        script_path = write_script(PROFILE_COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'profile', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_profile_field_access(self, runtime, memleak_check):
        """Test profile event field access: pid, tid, time, cpu, read"""
        script_path = write_script(PROFILE_FIELD_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'profile/-F 99/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_profile_with_callchain(self, runtime, memleak_check):
        """Test profile event source with callchain (-g)"""
        script_path = write_script(COUNTER_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'profile/-F 99 -g/', '-C', '0', '-i', '1000', '-m', '128', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_profile_event_print(self, runtime, memleak_check):
        """Test event.print() for profiler events"""
        script_path = write_script(PROFILE_PRINT_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'profile/-F 99/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_page_faults_field_access(self, runtime, memleak_check):
        """Test page-faults as profiler event source with field access"""
        script_path = write_script(PAGE_FAULTS_FIELD_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'page-faults/-N 10/', '-C', '0', '-i', '1000', '-m', '64', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_page_faults_callchain_and_regs(self, runtime, memleak_check):
        """Test page-faults with callchain and regs_user dict"""
        script_path = write_script(PAGE_FAULTS_CALLCHAIN_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'page-faults/-g -N 10/', '-C', '0', '-i', '1000', '-m', '128', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_combined_tracepoint_and_profiler(self, runtime, memleak_check):
        """Test combined tracepoint + profiler event source"""
        script_path = write_script(COMBINED_SCRIPT)
        try:
            prof = PerfProf(['python', '-e', 'sched:sched_wakeup,profile/-F 99/', '--order', '-C', '0', '-i', '1000', '-m', '128', script_path])
            for std, line in prof.run(runtime, memleak_check):
                result_check(std, line, runtime, memleak_check)
        finally:
            os.unlink(script_path)

    def test_profile_help_template(self, runtime, memleak_check):
        """Test help template generation for profiler event source"""
        prof = PerfProf(['python', '-e', 'profile', 'help'])
        output = []
        for std, line in prof.run(None, memleak_check):
            output.append(line)
            print(line, end='', flush=True)
        template = ''.join(output)
        # Should have profiler-specific handler
        assert 'def profile(event)' in template
        # Should have Profiler events section in comments
        assert 'Profiler events' in template

    def test_combined_help_template(self, runtime, memleak_check):
        """Test help template with mixed tracepoint + profiler events"""
        prof = PerfProf(['python', '-e', 'sched:sched_wakeup,profile', 'help'])
        output = []
        for std, line in prof.run(None, memleak_check):
            output.append(line)
            print(line, end='', flush=True)
        template = ''.join(output)
        assert 'def sched__sched_wakeup(event)' in template
        assert 'def profile(event)' in template
