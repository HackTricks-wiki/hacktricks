# macOS-gebruikers en eksterne rekeninge

{{#include ../../banners/hacktricks-training.md}}

## Algemene gebruikers

- **Daemon-rekeninge**: Gereserveer vir stelsel-daemons. Hul kort name begin gewoonlik met ’n onderstreep (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: ’n Beperkte, tydelike rekening waarvan die beskikbaarheid plaaslik of deur ’n MDM Accounts payload beheer kan word.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: ’n Doelbewus onbevoorregte identiteit wat deur dienste gebruik word wat minimale lêerstelseltoestemmings benodig.
- **Root**: Die superuser. Interaktiewe root-aanmelding is by verstek gedeaktiveer, hoewel administrateurs bevoorregte bewerkings deur authorization en `sudo` kan uitvoer.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** Die normale, nie-administratiewe rekeningtipe. Administratiewe veranderinge vereis authorization van ’n administrateur.
- **Admin user**: ’n Lid van die plaaslike `admin`-groep. Admin-gebruikers voer steeds gewone prosesse met hul gebruikersidentiteit uit, maar kan authorization vir bevoorregte bewerkings verleen. Moenie aanvaar dat lidmaatskap alleen elke command as root laat loop nie; `sudo`, Authorization Services, policy en toepassingspesifieke kontroles is steeds van toepassing.<sup>[[2]](#references)</sup>
- **Root**: Root is ’n gebruiker wat toegelaat word om byna enige aksie uit te voer (daar is beperkings wat deur beskermings soos System Integrity Protection opgelê word).
- System Integrity Protection en die signed system volume voorkom byvoorbeeld dat selfs root beskermde `/System`-inhoud tydens normale werking permanent wysig.

## External Accounts

macOS ondersteun ook application accounts van external providers. Die `accountsd`-daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) tree as ’n tussenganger vir Accounts-framework-data op, en authentication plug-ins kan onder `/System/Library/Accounts/Authentication/` gevind word. Dit is application/service accounts, nie noodwendig identiteite wat by die macOS-aanmeldvenster kan aanmeld nie. `accountsd` lees ook die bekende account types uit `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
