#%define name    perf-monitor
#%define version 0.1.0
%define release 1
%undefine _disable_source_fetch
%define debug_package %{nil}


Name:           %{name}
Version:        %{version}
Release:        %{release}
License:        MulanPSL2
Group:          Unspecified
Summary:        Monitor based on perf_event
Distribution:   OpenCloudOS
Vendor:         Tencent
URL:            https://github.com/OpenCloudOS
BuildArch:      x86_64
ExclusiveArch:  x86_64

Requires:       elfutils-libelf
Requires:       glibc

# source files
Source:         https://github.com/OpenCloudOS/perf-monitor/archive/refs/tags/%{version}.tar.gz


%description
Monitor based on perf_event: split-lock, irq-off, profile,
task-state, watchdog, kmemleak, kvm-exit, mpdelay.


%prep
%setup -q

%build
make
strip -g %{name}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin/
install -m 0755 -o root -g root %{name} %{buildroot}/usr/bin/


%files
/usr/bin/%{name}


%changelog
* Sun Jan 23 2022 Builder <corcpp@foxmail.com>
- first version
- split-lock, irq-off, profile, task-state, watchdog, kmemleak, kvm-exit, mpdelay.
- Kernel stack support, user stack support
