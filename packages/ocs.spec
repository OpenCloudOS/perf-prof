%define TRACEEVENT_DIR /usr/lib64/%{name}-traceevent
%define PLUGINS_DIR %{TRACEEVENT_DIR}/plugins
%define has_btf %(test -f /sys/kernel/btf/vmlinux && echo 1 || echo 0)
%undefine _disable_source_fetch
%define debug_package %{nil}

Name:           perf-prof
Version:        1.4.4
Release:        1%{?dist}
License:        GPL2
Group:          Unspecified
Summary:        Profiling based on perf_event
Distribution:   OpenCloudOS
Vendor:         Tencent
URL:            https://github.com/OpenCloudOS
ExclusiveArch:  x86_64

Requires:       elfutils-libelf,glibc,xz-libs
BuildRequires:  elfutils-libelf-devel,xz-devel,gcc

%if %{has_btf}
BuildRequires:  clang,llvm,bpftool
%endif

Source0:        %{name}-%{version}.tar.gz

%description
Profiling based on perf_event: split-lock, irq-off, profile,
task-state, watchdog, kmemleak, kvm-exit, mpdelay.

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
# basic dirs
rm -rf %{buildroot}
mkdir -p -m755 %{buildroot}/usr/bin/ %{buildroot}%{PLUGINS_DIR} %{buildroot}/etc/bash_completion.d/

# binary
install -m 0755  %{name} %{buildroot}/usr/bin/
install -m 0755  flamegraph.pl %{buildroot}/usr/bin/
install -m 0755  trace2heatmap.pl %{buildroot}/usr/bin/
install -m 0755  lib/traceevent/plugins/*.so %{buildroot}%{PLUGINS_DIR}
cp packages/%{name} %{buildroot}/etc/bash_completion.d/

# doc
mkdir -p %{buildroot}/usr/share/doc/%{name}
cp 'docs/perf-prof User Guide.pdf' %{buildroot}/usr/share/doc/%{name}

%files
/usr/bin/%{name}
/usr/bin/flamegraph.pl
/usr/bin/trace2heatmap.pl
%{PLUGINS_DIR}
/etc/bash_completion.d/%{name}
/usr/share/doc/%{name}

%changelog
* Tue Feb 18 2025 Joshua Hu <joshuahu@tencent.com> - 1.4.4-1
- [Type] other
- [DESC] fix build error

* Fri Feb 14 2025 Joshua Hu <joshuahu@tencent.com> - 1.4.2-1
- [Type] other
- [DESC] fix make error & add support for ebpf

* Thu Feb 13 2025 Joshua Hu <joshuahu@tencent.com> - 1.4.1-1
- init in ocs

* Sun Feb  6 2022 Duanery <corcpp@foxmail.com>
- Supports multiple types of stack processing and flame graph.

* Sun Jan 23 2022 Builder <corcpp@foxmail.com>
- first version
- split-lock, irq-off, profile, task-state, watchdog, kmemleak, kvm-exit, mpdelay.
- Kernel stack support, user stack support
