%define standalone %{?python_tarball:1}%{!?python_tarball:0}

%if %{standalone}
%define release 1.virt
%else
%define release 1%{?dist}
%endif

%define LIB_DIR /usr/lib64/%{name}
%define TRACEEVENT_DIR %{LIB_DIR}/traceevent
%define PLUGINS_DIR %{TRACEEVENT_DIR}/plugins
%define TOOLS_DIR /usr/share/%{name}/tools
%define has_btf %(test -f /sys/kernel/btf/vmlinux && echo 1 || echo 0)
%define has_tcmalloc %(test -f /usr/include/gperftools/tcmalloc.h && echo 1 || echo 0)

%undefine _disable_source_fetch
%define debug_package %{nil}

%if %{standalone}
%define PYTHON_DIR %{LIB_DIR}/python
# python-build-standalone is built with LLVM, use llvm-strip to handle its binaries correctly
%global __strip /usr/bin/llvm-strip
# Use standalone python3 to byte-compile .py files instead of system python
%global __brp_python_bytecompile %{_rpmconfigdir}/brp-python-bytecompile "%{_builddir}/python/bin/python3" 0 1
# Skip shebang mangling for the bundled python stdlib and the perf-prof tools:
# the tools use `#!/usr/bin/env -S perf-prof python ...` shebangs, which
# brp-mangle-shebangs would corrupt (it strips `env`, leaving `-S` as the interpreter).
%global __brp_mangle_shebangs_exclude_from (%{PYTHON_DIR}|%{TOOLS_DIR})
%else
# Skip shebang mangling for the perf-prof tools (env -S shebang would be corrupted).
%global __brp_mangle_shebangs_exclude_from %{TOOLS_DIR}
%endif


Name:           perf-prof
Version:        %{version}
Release:        %{release}
License:        GPL2
Group:          Unspecified
Summary:        Profiling based on perf_event
Distribution:   OpenCloudOS
Vendor:         Tencent
URL:            https://github.com/OpenCloudOS
BuildArch:      x86_64 aarch64
ExclusiveArch:  x86_64 aarch64

Requires:       elfutils-libelf
Requires:       glibc
Requires:       xz-libs
Requires:       libunwind
%if %{has_tcmalloc}
Requires:       gperftools-libs
%endif
%if ! %{standalone}
Requires:       python3-libs
%endif

BuildRequires:  elfutils-libelf-devel
BuildRequires:  xz-devel
BuildRequires:  libunwind-devel
%if %{standalone}
BuildRequires:  patchelf, llvm
%else
BuildRequires:  python3-devel
%endif
%if %{has_btf}
BuildRequires:  llvm, clang
BuildRequires:  bpftool
%endif

# source files
# Use {tag} which is auto-detected by rpm.sh to support both old (1.5.5) and new (v1.6.0) tag formats
Source:         https://github.com/OpenCloudOS/perf-prof/archive/refs/tags/%{tag}.tar.gz
%if %{standalone}
Source1:        %{python_tarball}
%endif
Patch0: glibc_2.17.patch

%description
Kernel profiler based on perf_event and ebpf

%prep
# GitHub strips 'v' prefix from directory name: v1.6.0 -> perf-prof-1.6.0
%setup -q -n %{name}-%{version}
%if %{defined glibc_217}
%patch0 -p1
%endif
%if %{standalone}
# Extract python-build-standalone into BUILD directory
rm -rf %{_builddir}/python
tar xzf %{SOURCE1} -C %{_builddir}
%endif

%build
%if %{standalone}
make PYTHON=%{_builddir}/python/bin/python3 PYTHON_HOME=%{PYTHON_DIR}
%else
make
%endif
strip -g %{name}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin/ %{buildroot}%{PLUGINS_DIR} %{buildroot}/etc/bash_completion.d/ %{buildroot}/usr/share/doc/%{name}
install -m 0755 -o root -g root %{name} %{buildroot}/usr/bin/
install -m 0755 -o root -g root flamegraph.pl %{buildroot}/usr/bin/
install -m 0755 -o root -g root trace2heatmap.pl %{buildroot}/usr/bin/
install -m 0755 -o root -g root lib/traceevent/plugins/*.so %{buildroot}%{PLUGINS_DIR}
cp packages/%{name} %{buildroot}/etc/bash_completion.d/
cp 'docs/perf-prof User Guide.pdf' %{buildroot}/usr/share/doc/%{name}

# Install the standalone analysis tools (see tools/). The release tarball only
# contains git-tracked files, so install everything under tools/ except the
# design docs (*.md). Executable bits are preserved from git: analysis scripts
# are 0755 with a `#!/usr/bin/env -S perf-prof python ...` shebang (exempted
# from brp-mangle-shebangs above), while modules loaded by those scripts
# (e.g. func_latency.py, imported by func_latency.sh from the same dir) are 0644.
mkdir -p %{buildroot}%{TOOLS_DIR}
find tools -maxdepth 1 -type f ! -name '*.md' -exec cp -a {} %{buildroot}%{TOOLS_DIR}/ \;

%if %{standalone}
# Install python-build-standalone runtime
mkdir -p %{buildroot}%{PYTHON_DIR}
cp -a %{_builddir}/python/* %{buildroot}%{PYTHON_DIR}/
# Remove unnecessary files to reduce package size
rm -rf %{buildroot}%{PYTHON_DIR}/include
find %{buildroot}%{PYTHON_DIR} -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
find %{buildroot}%{PYTHON_DIR} -name '*.pyc' -delete 2>/dev/null || true

# Fix rpath to point to installed python lib directory
patchelf --set-rpath %{PYTHON_DIR}/lib %{buildroot}/usr/bin/%{name}
%endif

%files
/usr/bin/%{name}
/usr/bin/flamegraph.pl
/usr/bin/trace2heatmap.pl
%{PLUGINS_DIR}
%{TOOLS_DIR}
%if %{standalone}
%{PYTHON_DIR}
%endif
/etc/bash_completion.d/%{name}
/usr/share/doc/%{name}


%changelog
