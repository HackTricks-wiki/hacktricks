# macOS-Benutzer & externe Konten

{{#include ../../banners/hacktricks-training.md}}

## Häufige Benutzer

- **Daemon-Konten**: Für System-Daemons reserviert. Ihre Kurznamen beginnen üblicherweise mit einem Unterstrich (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gast**: Ein eingeschränktes, temporäres Konto, dessen Verfügbarkeit lokal oder durch ein MDM Accounts payload gesteuert werden kann.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Eine absichtlich nicht privilegierte Identität, die von Diensten verwendet wird, die minimale Dateisystemberechtigungen benötigen.
- **Root**: Der Superuser. Die interaktive Root-Anmeldung ist standardmäßig deaktiviert, obwohl Administratoren privilegierte Vorgänge über Autorisierung und `sudo` ausführen können.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** Der normale, nicht administrative Kontotyp. Administrative Änderungen erfordern die Autorisierung durch einen Administrator.
- **Admin user**: Ein Mitglied der lokalen Gruppe `admin`. Admin users führen gewöhnliche Prozesse weiterhin mit ihrer Benutzeridentität aus, können jedoch privilegierte Vorgänge autorisieren. Gehe nicht davon aus, dass allein die Mitgliedschaft dafür sorgt, dass jeder Befehl als root ausgeführt wird; `sudo`, Authorization Services, Richtlinien und anwendungsspezifische Prüfungen gelten weiterhin.<sup>[[2]](#references)</sup>
- **Root**: Root ist ein Benutzer, der nahezu jede Aktion ausführen darf (es gibt Einschränkungen durch Schutzmechanismen wie System Integrity Protection).
- Beispielsweise verhindern System Integrity Protection und das signierte Systemvolume, dass selbst root während des normalen Betriebs geschützte Inhalte unter `/System` dauerhaft ändert.

## External Accounts

macOS unterstützt auch application accounts von externen Anbietern. Der `accountsd` daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) vermittelt Daten des Accounts framework, und Authentication plug-ins befinden sich unter `/System/Library/Accounts/Authentication/`. Dies sind application/service accounts und nicht unbedingt Identitäten, die sich am macOS-Anmeldefenster anmelden können. `accountsd` liest die bekannten account types außerdem aus `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
