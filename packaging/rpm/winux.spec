Name:           winux
Version:        1.0.1
Release:        1%{?dist}
Summary:        Windows PE executor for Linux — no Wine, no QEMU

License:        MIT
URL:            https://github.com/devfrp/winux
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc, make, libseccomp-devel
Requires:       glibc, libseccomp

%description
Run native Windows PE32+ (x86_64) executables directly on Linux
through a lightweight translation layer. Zero dependencies at
runtime beyond glibc and libseccomp.

Features:
 - PE32+ loader with IAT resolution and on-address mapping
 - 17 NT API stubs → Linux syscalls
 - ~45 kernel32 functions (CreateFile, threads, heap, I/O)
 - Synthetic TEB/PEB with GS segment register
 - Seccomp BPF sandbox (~50 syscall whitelist)
 - Full /proc transparency (ps, strace, lsof)
 - Signal passthrough (SIGTERM, SIGSEGV crash dump)
 - Path translation C:\ → Linux filesystem

%prep
%setup -q

%build
make clean
make

%install
make install DESTDIR=%{buildroot} PREFIX=/usr

%files
/usr/bin/winexec
/usr/share/doc/winux/README.md
/usr/share/doc/winux/CHANGELOG.md
/usr/share/doc/winux/LICENSE

%changelog
* Sat Jun 20 2025 winux contributors
- v1.0.1: Registry HKCU, TLS callbacks, imports by ordinal, dlopen DLL fallback, SEH
* Mon Jun 17 2025 winux contributors
- Initial release v1.0.0
