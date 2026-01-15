%define release 1.virt
%define TRACEEVENT_DIR /usr/lib64/%{name}-traceevent
%define PLUGINS_DIR %{TRACEEVENT_DIR}/plugins
%define has_btf %(test -f /sys/kernel/btf/vmlinux && echo 1 || echo 0)
%define has_tcmalloc %(test -f /usr/include/gperftools/tcmalloc.h && echo 1 || echo 0)

%undefine _disable_source_fetch
%define debug_package %{nil}


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
%if %{has_tcmalloc}
Requires:       gperftools-libs
%endif

BuildRequires:  elfutils-libelf-devel
BuildRequires:  xz-devel
%if %{has_btf}
BuildRequires:  llvm, clang
BuildRequires:  bpftool
%endif

# source files
# Use %{tag} which is auto-detected by rpm.sh to support both old (1.5.5) and new (v1.6.0) tag formats
Source:         https://github.com/OpenCloudOS/perf-prof/archive/refs/tags/%{tag}.tar.gz
Patch0: glibc_2.17.patch

%description
Kernel profiler based on perf_event and ebpf

%prep
# GitHub strips 'v' prefix from directory name: v1.6.0 -> perf-prof-1.6.0
%setup -q -n %{name}-%{version}
%if %{defined glibc_217}
%patch0 -p1
%endif

%build
make
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

%files
/usr/bin/%{name}
/usr/bin/flamegraph.pl
/usr/bin/trace2heatmap.pl
%{TRACEEVENT_DIR}
%{PLUGINS_DIR}
/etc/bash_completion.d/%{name}
/usr/share/doc/%{name}


%changelog
