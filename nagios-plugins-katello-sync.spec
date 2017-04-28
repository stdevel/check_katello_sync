Name:           nagios-plugins-katello-sync
Version:        0.5.0
Release:        1%{?dist}
Summary:        A Nagios / Icinga plugin for checking product synchronization within Katello/Red Hat Satellite 6.x

Group:          Applications/System
License:        GPL
URL:            https://github.com/stdevel/check_katello_sync
Source0:        nagios-plugins-katello-sync-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires:
Requires:       Python(requests) Python(simplejson)

%description
This package contains a Nagios / Icinga plugin for checking patch sync of hosts managed by Katello, Red Hat Satellite 5.x or SUSE Manager.

Check out the GitHub page for further information: https://github.com/stdevel/check_katello_sync

%prep
%setup -q

%build
#change /usr/lib64 to /usr/lib if we're on i686
%ifarch i686
sed -i -e "s/usr\/lib64/usr\/lib/" check_katello_sync.cfg
%endif

%install
install -m 0755 -d %{buildroot}%{_libdir}/nagios/plugins/
install -m 0755 check_katello_sync.py %{buildroot}%{_libdir}/nagios/plugins/check_katello_sync
%if 0%{?el7}
        install -m 0755 -d %{buildroot}%{_sysconfdir}/nrpe.d/
        install -m 0755 check_katello_sync.cfg  %{buildroot}%{_sysconfdir}/nrpe.d/check_katello_sync.cfg
%else
        install -m 0755 -d %{buildroot}%{_sysconfdir}/nagios/plugins.d/
        install -m 0755 check_katello_sync.cfg  %{buildroot}%{_sysconfdir}/nagios/plugins.d/check_katello_sync.cfg
%endif



%clean
rm -rf $RPM_BUILD_ROOT

%files
%if 0%{?el7}
        %config %{_sysconfdir}/nrpe.d/check_katello_sync.cfg
%else
        %config %{_sysconfdir}/nagios/plugins.d/check_katello_sync.cfg
%endif
%{_libdir}/nagios/plugins/check_katello_sync


%changelog
* Fri Apr 28 2017 Christian Stankowic <info@stankowic-development.net> - 0.5.0-1
- First release
