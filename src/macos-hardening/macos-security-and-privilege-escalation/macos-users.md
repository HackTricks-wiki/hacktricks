# watumiaji wa macOS & Akaunti za Nje

{{#include ../../banners/hacktricks-training.md}}

## Watumiaji Wanaofahamika

- **Daemon**: Mtumiaji aliyehifadhiwa kwa ajili ya daemons za mfumo. Majina ya akaunti ya daemon ya kawaida huanza kwa "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Akaunti ya wageni yenye ruhusa kali sana
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Mchakato unatekelezwa na mtumiaji huyu wakati ruhusa ndogo zinahitajika
- **Root**

## User Privileges

- **Standard User:** Mtumiaji wa msingi zaidi. Mtumiaji huyu anahitaji ruhusa zinazotolewa na mtumiaji wa admin anapojaribu kufunga programu au kufanya kazi nyingine za juu. Hawawezi kufanya hivyo peke yao.
- **Admin User**: Mtumiaji ambaye anafanya kazi mara nyingi kama mtumiaji wa kawaida lakini pia anaruhusiwa kufanya vitendo vya root kama vile kufunga programu na kazi nyingine za kiutawala. Watumiaji wote wanaotegemea kundi la admin **wanapewa ufikiaji wa root kupitia faili ya sudoers**.
- **Root**: Root ni mtumiaji anayeruhusiwa kufanya karibu kila kitendo (kuna vizuizi vinavyowekwa na ulinzi kama vile System Integrity Protection).
- Kwa mfano root hataweza kuweka faili ndani ya `/System`

## External Accounts

MacOS pia inasaidia kuingia kupitia watoa huduma za kitambulisho za nje kama FaceBook, Google... Daemon kuu inayofanya kazi hii ni `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) na inawezekana kupata plugins zinazotumika kwa uthibitishaji wa nje ndani ya folda `/System/Library/Accounts/Authentication/`.\
Zaidi ya hayo, `accountsd` inapata orodha ya aina za akaunti kutoka `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
