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
#
# Package selection:
#   - Version: PYTHON_VERSION env var, default 3.12 (stable, widely compatible)
#   - Architecture: auto-detected via uname -m (x86_64, aarch64)
#   - Variant: install_only_stripped — minimal runtime without debug symbols,
#     pre-installed layout (bin/ lib/ include/), ready to use directly
#   - Stability: alpha/beta/rc versions are filtered out, highest patch version selected
#
# Source: https://github.com/astral-sh/python-build-standalone
# Asset naming: cpython-{ver}+{tag}-{arch}-unknown-linux-gnu-install_only_stripped.tar.gz
download_python_standalone()
{
    local pyver="${PYTHON_VERSION:-3.12}"
    local variant="$(uname -m)-unknown-linux-gnu-install_only_stripped"
    local src=$1

    echo "Fetching latest python-build-standalone release info..." 1>&2
    local release_json=$(curl -sfL https://raw.githubusercontent.com/astral-sh/python-build-standalone/latest-release/latest-release.json)
    local pbs_tag=$(echo "$release_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag'])")
    local prefix=$(echo "$release_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['asset_url_prefix'])")

    echo "Latest release tag: $pbs_tag" 1>&2

    local asset_name=$(curl -sf "https://api.github.com/repos/astral-sh/python-build-standalone/releases/tags/${pbs_tag}" \
      | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
pattern = re.compile(r'^cpython-${pyver}\.\d+(\+|\-).*${variant}\.tar\.gz\$')
matches = [a['name'] for a in data['assets'] if pattern.match(a['name'])]
stable = [m for m in matches if not re.search(r'(a|b|rc)\d+', m)]
if stable:
    matches = stable
if matches:
    matches.sort(key=lambda x: [int(n) for n in re.search(r'cpython-(\d+)\.(\d+)\.(\d+)', x).groups()], reverse=True)
    print(matches[0])
else:
    sys.exit(1)
")

    if [ -z "$asset_name" ]; then
        echo "ERROR: No matching python-build-standalone for cpython-${pyver}.x ${variant}" 1>&2
        exit 1
    fi

    # Check if already downloaded
    if [ -f "$src/$asset_name" ]; then
        echo "Python standalone already exists: $asset_name" 1>&2
    else
        echo "Downloading: $asset_name" 1>&2
        curl -fL --progress-bar -o "$src/$asset_name" "${prefix}/${asset_name}"
    fi

    echo "$asset_name"
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
