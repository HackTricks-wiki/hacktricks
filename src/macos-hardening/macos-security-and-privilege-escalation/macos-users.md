# macOS-Benutzer & externe Konten

{{#include ../../banners/hacktricks-training.md}}

## Häufige Benutzer

- **Daemon**: Benutzer, der für System-Daemons reserviert ist. Die Standardnamen von Daemon-Accounts beginnen normalerweise mit einem "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gast**: Account für Gäste mit sehr strengen Berechtigungen
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Prozesse werden mit diesem Benutzer ausgeführt, wenn minimale Berechtigungen erforderlich sind
- **Root**

## Benutzerberechtigungen

- **Standard User:** Der grundlegendste Benutzertyp. Dieser Benutzer benötigt von einem Admin User erteilte Berechtigungen, wenn er versucht, Software zu installieren oder andere fortgeschrittene Aufgaben auszuführen. Er kann dies nicht eigenständig tun.
- **Admin User**: Ein Benutzer, der die meiste Zeit als Standard User arbeitet, aber auch Root-Aktionen wie die Installation von Software und andere administrative Aufgaben durchführen darf. Alle Benutzer, die der Admin-Gruppe angehören, **erhalten über die sudoers file Zugriff auf Root**.
- **Root**: Root ist ein Benutzer, der nahezu jede Aktion durchführen darf (es gibt Einschränkungen durch Schutzmechanismen wie System Integrity Protection).
- Beispielsweise kann Root keine Datei innerhalb von `/System` ablegen.

## Externe Konten

macOS unterstützt auch die Anmeldung über externe Identity Provider wie FaceBook, Google ... Der wichtigste Daemon, der diese Aufgabe übernimmt, ist `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), und Plugins für die externe Authentifizierung befinden sich im Ordner `/System/Library/Accounts/Authentication/`.\
Außerdem ruft `accountsd` die Liste der Kontotypen aus `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` ab.

{{#include ../../banners/hacktricks-training.md}}
