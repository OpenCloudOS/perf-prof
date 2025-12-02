#!/bin/sh

tag=$1

if [ -z "$tag" ]
then
  echo "Usage: $0 <package tag>" 1>&2
  exit 0
fi

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

# Only glibc 2.28 is compatible with glibc 2.17
glibc_217=$(getconf GNU_LIBC_VERSION | awk '{match($2, "([0-9]+).([0-9]+)", arr);
                                             if (arr[2]>17 && arr[2]<=28) print "1"}')
if [ -n "$glibc_217" ]; then
    src=$(rpmbuild --eval '%{_sourcedir}')
    cp glibc_2.17.patch $src
    fmemopen_ver=$(sym_ver_le_217 fmemopen)
    fcntl_ver=$(sym_ver_le_217 fcntl)
    sed -i -e "s/fmemopen@GLIBC_/$fmemopen_ver/" -e "s/fcntl@GLIBC_/$fcntl_ver/" $src/glibc_2.17.patch
    rpmbuild -bb perf-prof.spec \
        --define "version $version" --define "tag $tag" --define "glibc_217 1" \
        --define "EXTRA_CFLAGS -DSQLITE_COMPAT"
else
    rpmbuild -bb perf-prof.spec \
        --define "version $version" --define "tag $tag"
fi
