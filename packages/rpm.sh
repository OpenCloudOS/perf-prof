#!/bin/sh

tag=$1

if [ -z "$tag" ]
then
  echo "Usage: $0 <package tag> [--compat]" 1>&2
  echo "  --compat  Enable standalone python and glibc 2.17 compatibility" 1>&2
  exit 0
fi

# Check for --compat flag
compat=0
for arg in "$@"; do
    case "$arg" in
        --compat) compat=1 ;;
    esac
done

# Strip 'v' prefix from version if present (for rpmbuild %{version})
# GitHub strips 'v' from directory name: v1.6.0 -> perf-prof-1.6.0
version="${tag#v}"

sym_ver_le_217()
{
    local sym=$1
    readelf -sW /lib64/libc.so.6 | grep "${sym}@" | awk -v sym=$sym '
        index($NF, sym) == 1 {syms[$NF]++}
        END {
            for (i in syms) {
                if (match(i, "GLIBC_([0-9]+).([0-9]+)", arr)) {
                    major = arr[1]
                    minor = arr[2]
                    if (major < 2 || (major == 2 && minor <= 17)) {
                        gsub("@@", "@", i)
                        print i
                    }
                }
            }
        }
    '
}

# Download python-build-standalone to rpmbuild SOURCES
download_python_standalone()
{
    local src=$1
    local script_dir=$(cd "$(dirname "$0")" && pwd)
    local pyver="${PYTHON_VERSION:-3.12}"

    # Run script, all output goes directly to terminal
    (cd "$src" && "$script_dir/download-python-standalone.sh" ${PYTHON_VERSION:+$PYTHON_VERSION}) 1>&2
    # Return the latest matching file
    ls -t "$src"/cpython-${pyver}.*-$(uname -m)-*install_only_stripped.tar.gz 2>/dev/null | head -1 | xargs basename
}

src=$(rpmbuild --eval '%{_sourcedir}')
extra_defines=""

if [ "$compat" -eq 1 ]; then
    # Standalone python
    python_tarball=$(download_python_standalone "$src")
    extra_defines="--define 'python_tarball $python_tarball'"

    # glibc 2.17 compatibility (only glibc 2.18~2.28 needs patching)
    glibc_217=$(getconf GNU_LIBC_VERSION | awk '{match($2, "([0-9]+).([0-9]+)", arr);
                                                 if (arr[2]>17 && arr[2]<=28) print "1"}')
    if [ -n "$glibc_217" ]; then
        cp glibc_2.17.patch $src
        fmemopen_ver=$(sym_ver_le_217 fmemopen)
        fcntl_ver=$(sym_ver_le_217 fcntl)
        sed -i -e "s/fmemopen@GLIBC_/$fmemopen_ver/" -e "s/fcntl@GLIBC_/$fcntl_ver/" $src/glibc_2.17.patch
        extra_defines="$extra_defines --define 'glibc_217 1'"
    fi
fi

eval rpmbuild -bb perf-prof.spec \
    --define "'version $version'" --define "'tag $tag'" \
    $extra_defines
