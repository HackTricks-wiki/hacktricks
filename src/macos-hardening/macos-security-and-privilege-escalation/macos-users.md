# macOS-Benutzer & Externe Konten

{{#include ../../banners/hacktricks-training.md}}

## Gemeinsame Benutzer

- **Daemon**: Benutzer, der für System-Daemons reserviert ist. Die Standardnamen der Daemon-Konten beginnen normalerweise mit einem "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gast**: Konto für Gäste mit sehr strengen Berechtigungen
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Niemand**: Prozesse werden mit diesem Benutzer ausgeführt, wenn minimale Berechtigungen erforderlich sind
- **Root**

## Benutzerberechtigungen

- **Standardbenutzer:** Der grundlegendste Benutzer. Dieser Benutzer benötigt Berechtigungen, die von einem Administrator gewährt werden, wenn er versucht, Software zu installieren oder andere fortgeschrittene Aufgaben auszuführen. Er kann dies nicht selbst tun.
- **Administratorbenutzer**: Ein Benutzer, der die meiste Zeit als Standardbenutzer arbeitet, aber auch berechtigt ist, Root-Aktionen wie die Installation von Software und andere administrative Aufgaben auszuführen. Alle Benutzer, die zur Administratorgruppe gehören, **erhalten Zugriff auf Root über die sudoers-Datei**.
- **Root**: Root ist ein Benutzer, der fast jede Aktion ausführen darf (es gibt Einschränkungen, die durch Schutzmaßnahmen wie den System Integrity Protection auferlegt werden).
- Zum Beispiel kann Root keine Datei in `/System` ablegen.

## Externe Konten

MacOS unterstützt auch die Anmeldung über externe Identitätsanbieter wie FaceBook, Google... Der Hauptdaemon, der diese Aufgabe ausführt, ist `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) und es ist möglich, Plugins für die externe Authentifizierung im Ordner `/System/Library/Accounts/Authentication/` zu finden.\
Darüber hinaus erhält `accountsd` die Liste der Kontotypen aus `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
