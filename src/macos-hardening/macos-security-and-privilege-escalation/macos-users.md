# macOS-Benutzer & externe Accounts

{{#include ../../banners/hacktricks-training.md}}

## Gängige Benutzer

- **Daemon-Accounts**: Für System-Daemons reserviert. Ihre Kurznamen beginnen häufig mit einem Unterstrich (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Gast**: Ein eingeschränktes, temporäres Konto, dessen Verfügbarkeit lokal oder über eine MDM-Accounts-Payload gesteuert werden kann.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Eine bewusst unprivilegierte Identität, die von Diensten verwendet wird, die minimale Dateisystemberechtigungen benötigen.
- **Root**: Der Superuser. Die interaktive Root-Anmeldung ist standardmäßig deaktiviert, Administratoren können jedoch über Autorisierung und `sudo` privilegierte Vorgänge ausführen.<sup>[[2]](#references)</sup>

Material zur Überprüfung lokaler Kontopasswörter und dessen Extraktions-Workflow werden unter [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords) behandelt.

## Benutzerberechtigungen

- **Standardbenutzer:** Der normale Kontotyp ohne Administratorrechte. Änderungen, die Administratorrechte erfordern, müssen von einem Administrator autorisiert werden.
- **Admin-Benutzer**: Ein Mitglied der lokalen Gruppe `admin`. Admin-Benutzer führen gewöhnliche Prozesse weiterhin mit ihrer Benutzeridentität aus, können aber privilegierte Vorgänge autorisieren. Gehe nicht davon aus, dass die Mitgliedschaft allein jeden Befehl als Root ausführt; `sudo`, Authorization Services, Richtlinien und anwendungsspezifische Prüfungen gelten weiterhin.<sup>[[2]](#references)</sup>
- **Root**: Root ist ein Benutzer, der nahezu jede Aktion ausführen darf (es gibt Einschränkungen durch Schutzmechanismen wie System Integrity Protection).
  - Beispielsweise verhindern System Integrity Protection und das signierte Systemvolume, dass selbst Root während des normalen Betriebs geschützte Inhalte in `/System` dauerhaft ändern kann.

## Externe Konten

macOS unterstützt auch Anwendungskonten externer Anbieter. Der Daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) vermittelt den Zugriff auf Daten des Accounts-Frameworks. Authentifizierungs-Plug-ins befinden sich unter `/System/Library/Accounts/Authentication/`. Dies sind Anwendungs-/Dienstkonten, also nicht unbedingt Identitäten, mit denen man sich am macOS-Anmeldefenster anmelden kann. `accountsd` liest außerdem die bekannten Kontotypen aus `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload für die Geräteverwaltung von Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD-Berechtigungen und Eigentümerschaft: Administrations- und Root-Konten](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
