Name:		lsw
Version:	1.0.0
Release:	1%{?dist}
Summary:	Linux Subsystem for Windows - run Windows 11 apps on Linux
License:	GPLv3+
URL:		https://github.com/lsw-project/lsw
Source0:	%{url}/archive/refs/tags/v%{version}.tar.gz
BuildRequires:	gcc
BuildRequires:	make
%if 0%{?fedora}
Requires:	gcc, make
%endif

%description
LSW (Linux Subsystem for Windows) brings Windows 11 to Linux very much
the same way WSL brought Linux to Windows. It includes its own NTLL
(NT Layer Library) compatibility runtime - a PE32+ loader, NT syscall
translation layer and Win32 API implementation - with zero dependency on
Wine.

%prep
%setup -q -n lsw-%{version}

%build
make PREFIX=%{_prefix}

%install
make PREFIX=%{_prefix} DESTDIR=%{buildroot} install

%files
%{_bindir}/lsw
%{_bindir}/lswd
%{_bindir}/lsw-runtime
%{_bindir}/lsw-init
%{_libdir}/lsw/*
%{_datadir}/lsw/*
%{_datadir}/bash-completion/completions/lsw
%{_sysconfdir}/lsw/*
%dir /var/lib/lsw

%post
# Ensure the runtime data directories exist
mkdir -p /var/lib/lsw/distros
mkdir -p /var/lib/lsw/pids
mkdir -p /var/lib/lsw/registry
mkdir -p /var/lib/lsw/root
exit 0

%preun
if [ "$1" = "0" ]; then
    # Stop daemon on remove
    pkill -f "lswd" 2>/dev/null || true
fi
exit 0

%changelog
* Mon Sep 14 2026 LSW Contributors <dev@lsw.dev> - 1.0.0
- Initial release: Windows 11 support with NTLL runtime