# macOS-gebruikers & eksterne rekeninge

{{#include ../../banners/hacktricks-training.md}}

## Algemene gebruikers

- **Daemon**: Gebruiker gereserveer vir stelseldaemons. Die verstek-daemonrekeningname begin gewoonlik met ’n "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Rekening vir gaste met baie streng toestemmings
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Prosesse word met hierdie gebruiker uitgevoer wanneer minimale toestemmings vereis word
- **Root**

## Gebruikersvoorregte

- **Standard User:** Die mees basiese tipe gebruiker. Hierdie gebruiker benodig toestemmings wat deur ’n admin user verleen word wanneer sagteware geïnstalleer of ander gevorderde take uitgevoer word. Hulle kan dit nie op hul eie doen nie.
- **Admin User**: ’n Gebruiker wat meestal as ’n standard user werk, maar ook toegelaat word om root-aksies uit te voer, soos om sagteware te installeer en ander administratiewe take uit te voer. Alle gebruikers wat aan die admin-groep behoort, **kry toegang tot root via die sudoers file**.
- **Root**: Root is ’n gebruiker wat toegelaat word om byna enige aksie uit te voer (daar is beperkings wat deur beskermingsmaatreëls soos System Integrity Protection opgelê word).
- Byvoorbeeld, root sal nie ’n lêer binne `/System` kan plaas nie

## Eksterne Rekeninge

MacOS ondersteun ook aanmelding via eksterne identity providers soos FaceBook, Google... Die hoofdaemon wat hierdie taak uitvoer, is `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), en dit is moontlik om plugins wat vir eksterne authentication gebruik word binne die vouer `/System/Library/Accounts/Authentication/` te vind.\
Boonop kry `accountsd` die lys van rekeningtipes vanaf `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
