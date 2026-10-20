# macOS-gebruikers en eksterne rekeninge

{{#include ../../banners/hacktricks-training.md}}

## Algemene gebruikers

- **Daemon-rekeninge**: Gereserveer vir stelseldaemons. Hul kort name begin gewoonlik met ’n onderstreep (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Gast**: ’n Beperkte, tydelike rekening waarvan die beskikbaarheid plaaslik of deur ’n MDM Accounts-payload beheer kan word.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: ’n Doelbewus onbevoorregte identiteit wat deur dienste gebruik word wat minimale lêerstelseltoestemmings vereis.
- **Root**: Die supergebruiker. Interaktiewe root-aanmelding is by verstek gedeaktiveer, hoewel administrateurs bevoorregte bewerkings deur magtiging en `sudo` kan uitvoer.<sup>[[2]](#references)</sup>

Plaaslike rekeningwagwoordverifikasiemateriaal en die onttrekkingswerkvloei word onder [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords) behandel.

## Gebruikersregte

- **Standaardgebruiker:** Die gewone, nie-administratiewe rekeningtipe. Administratiewe veranderinge vereis magtiging van ’n administrateur.
- **Admin-gebruiker**: ’n Lid van die plaaslike `admin`-groep. Admin-gebruikers voer steeds gewone prosesse met hul eie gebruikersidentiteit uit, maar kan bevoorregte bewerkings magtig. Moenie aanvaar dat lidmaatskap alleen elke opdrag as root laat loop nie; `sudo`, Authorization Services, beleid en toepassingspesifieke kontroles is steeds van toepassing.<sup>[[2]](#references)</sup>
- **Root**: Root is ’n gebruiker wat byna enige handeling mag uitvoer (daar is beperkings wat deur beskermingsmaatreëls soos System Integrity Protection opgelê word).
  - System Integrity Protection en die ondertekende stelselvolume verhoed byvoorbeeld dat selfs root beskermde `/System`-inhoud tydens normale werking permanent verander.

## Eksterne rekeninge

macOS ondersteun ook toepassingrekeninge van eksterne verskaffers. Die `accountsd`-daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) tree op as ’n tussenganger vir Accounts-raamwerkdata, en verifikasie-inproppe kan gevind word onder `/System/Library/Accounts/Authentication/`. Dit is toepassing-/diensrekeninge, nie noodwendig identiteite wat by die macOS-aanmeldvenster kan aanmeld nie. `accountsd` lees ook die bekende rekeningsoorte vanaf `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Rekeninge se toestelbestuurlas](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD-toestemmings en eienaarskap: administratiewe en root-rekeninge](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
