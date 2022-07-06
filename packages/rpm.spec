%define release 1%{?dist}
%define TRACEEVENT_DIR /usr/lib64/%{name}-traceevent
%define PLUGINS_DIR %{TRACEEVENT_DIR}/plugins

%undefine _disable_source_fetch
%define debug_package %{nil}


Name:           %{name}
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

# source files
Source:         https://github.com/OpenCloudOS/perf-prof/archive/refs/tags/%{version}.tar.gz


%description
Profiling based on perf_event: split-lock, irq-off, profile,
task-state, watchdog, kmemleak, kvm-exit, mpdelay.


%prep
%setup -q

%build
make
strip -g %{name}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin/ %{buildroot}%{PLUGINS_DIR}
install -m 0755 -o root -g root %{name} %{buildroot}/usr/bin/
install -m 0755 -o root -g root flamegraph.pl %{buildroot}/usr/bin/
install -m 0755 -o root -g root trace2heatmap.pl %{buildroot}/usr/bin/
install -m 0755 -o root -g root lib/traceevent/plugins/*.so %{buildroot}%{PLUGINS_DIR}


%files
/usr/bin/%{name}
/usr/bin/flamegraph.pl
/usr/bin/trace2heatmap.pl
%{TRACEEVENT_DIR}
%{PLUGINS_DIR}


%changelog
* Sun Feb  6 2022 Duanery <corcpp@foxmail.com>
- Supports multiple types of stack processing and flame graph.

* Sun Jan 23 2022 Builder <corcpp@foxmail.com>
- first version
- split-lock, irq-off, profile, task-state, watchdog, kmemleak, kvm-exit, mpdelay.
- Kernel stack support, user stack support
