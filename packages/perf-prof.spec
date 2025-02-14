%define release 1%{?dist}
%define TRACEEVENT_DIR /usr/lib64/%{name}-traceevent
%define PLUGINS_DIR %{TRACEEVENT_DIR}/plugins
%define has_btf %(test -f /sys/kernel/btf/vmlinux && echo 1 || echo 0)

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
BuildArch:      x86_64
ExclusiveArch:  x86_64

Requires:       elfutils-libelf
Requires:       glibc
Requires:       xz-libs

BuildRequires:  elfutils-libelf-devel
BuildRequires:  xz-devel
%if %{has_btf}
BuildRequires:  llvm
BuildRequires:  bpftool
%endif

# source files
Source:         https://github.com/OpenCloudOS/perf-prof/archive/refs/tags/%{version}.tar.gz


%description
Kernel profiler based on perf_event and ebpf

%prep
%setup -q

%build
if [ -f /sys/kernel/btf/vmlinux ]; then
    make CONFIG_LIBBPF=y
else
    make
fi
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
