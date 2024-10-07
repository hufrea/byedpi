%global origname        byedpi
%global commit          0a20d69537018baa8dd8c00c1ff6bbecdf623c93
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           byedpi
Version:        0.14.0
Release:        1%{?dist}
Summary:        Implementation of some DPI bypass methods.

License:        MIT
URL:            https://github.com/hufrea/byedpi
Source0:        https://github.com/hufrea/byedpi/%{name}.tar.gz
Patch0:		000-Makefile-environment.patch

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  systemd-rpm-macros

%description
Implementation of some DPI bypass methods. 
The program is a local SOCKS proxy server.

%prep
%setup -q -n %{name}
%patch0
sed -i 's@ciadpi@byedpi@g' dist/linux/byedpi.service

%build
make %{?_smp_mflags} INSTALL_DIR="%{_bindir}" TARGET="%{name}" CFLAGS="%{optflags}"

%install
install -p -D -m 0755 %{name}  %{buildroot}%{_bindir}/%{name}
install -p -D -m 0644 dist/linux/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%files
%license LICENSE
%doc *.md 
%{_bindir}/*
%{_unitdir}/*

%changelog
* Sun Sep 15 2024 Andrew Clark <andrewclarkii@gmail.com> - 0.14.0-1
- initial build

