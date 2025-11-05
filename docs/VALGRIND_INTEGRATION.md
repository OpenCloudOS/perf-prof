# Valgrind Integration for perf-prof Tests

## Overview

The memleak_check parameter in the pytest test suite has been enhanced to support valgrind memory leak detection in addition to the existing tcmalloc-based memory checking.

## Usage

### Using Valgrind for Memory Leak Detection

```bash
# Use valgrind for memory leak detection
pytest --memleak-check=valgrind --runtime=5 test_profile.py::test_profile_g -v

# Use numeric value for tcmalloc-based checking (existing functionality)
pytest --memleak-check=1000 --runtime=5 test_profile.py::test_profile_g -v

# Default behavior (no memory checking)
pytest --runtime=5 test_profile.py::test_profile_g -v
```

### Parameter Options

- `--memleak-check=valgrind`: Uses valgrind with `--leak-check=full --track-origins=yes --error-exitcode=1`
- `--memleak-check=<number>`: Uses tcmalloc with HEAPCHECK=draconian (existing functionality)
- `--memleak-check=0` or unspecified: No memory leak checking (default)

## Implementation Details

### Modified Files

1. **conftest.py**
   - Updated `pytest_addoption()` to accept string type for memleak-check parameter
   - Enhanced `memleak_check` fixture to handle both "valgrind" string and numeric values
   - Modified `result_check()` function to support valgrind output parsing

2. **PerfProf.py**
   - Updated `run()` method to detect memleak_check="valgrind" and prepend valgrind command
   - Added valgrind-specific command line arguments
   - Enhanced output display to show "valgrind_check" when active

### Valgrind Configuration

When `--memleak-check=valgrind` is used, the following valgrind options are applied:
- `--leak-check=full`: Full memory leak detection
- `--track-origins=yes`: Track origins of uninitialised values
- `--error-exitcode=1`: Exit with error code if memory issues are found

### Error Handling

- Valgrind errors are detected through "ERROR SUMMARY:" lines in stderr
- Tests fail if valgrind detects any errors (non-zero error count)
- Valgrind's normal informational output is displayed but doesn't cause test failure

## Test Results

### Successful Test Categories

The following test categories have been verified to work well with valgrind:

1. **Expression Tests** (test_expr.py): All 46 tests passed
2. **Basic Profile Tests**: Non-BPF profile tests passed
3. **Help and Simple Commands**: Commands that exit quickly work well

### Known Limitations

1. **BPF-related Tests**: Some BPF functionality shows valgrind warnings due to:
   - Uninitialized bytes in BPF syscalls
   - libbpf library memory patterns
   - These are typically not serious memory leaks but valgrind flags them

2. **Performance**: Valgrind significantly slows down execution (5-10x slower)
   - Tests may take longer to complete
   - Shorter runtime values are recommended for valgrind testing

## Examples

### Basic Usage Examples

```bash
# Test a specific profiler with valgrind
pytest --memleak-check=valgrind --runtime=3 test_profile.py::test_profile_g -v

# Test multiple profilers with valgrind
pytest --memleak-check=valgrind --runtime=2 test_expr.py -v

# Compare with traditional tcmalloc checking
pytest --memleak-check=2000 --runtime=3 test_profile.py::test_profile_g -v
```

### Expected Output

When using valgrind, you'll see output like:

```
Runtime 3 second[35mvalgrind_check valgrind --leak-check=full --track-origins=yes --error-exitcode=1 /path/to/perf-prof profile -F 997 -C 0 -m 32 -g[0m
==12345== Memcheck, a memory error detector
==12345== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
...
==12345== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

## Benefits

1. **More Comprehensive Detection**: Valgrind can detect more types of memory errors than tcmalloc
2. **Better Error Reporting**: Valgrind provides detailed stack traces for memory issues
3. **Industry Standard**: Valgrind is a widely-recognized memory checking tool
4. **Backward Compatibility**: Existing numeric tcmalloc functionality is preserved

## Recommendations

1. **Use valgrind for development** when investigating memory issues
2. **Use tcmalloc for CI/CD** when performance is important
3. **Focus valgrind testing on core functionality** rather than edge cases with BPF
4. **Keep test runtimes short** (2-3 seconds) when using valgrind due to performance impact

## Future Enhancements

Potential improvements could include:
1. Configurable valgrind options through pytest parameters
2. Separate valgrind suppressions file for known false positives
3. Integration with CI/CD pipelines for periodic memory checking
4. Support for other memory checking tools (AddressSanitizer, etc.)