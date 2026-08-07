# Watumiaji wa macOS na Akaunti za Nje

{{#include ../../banners/hacktricks-training.md}}

## Watumiaji wa Kawaida

- **Daemon**: Mtumiaji aliyetengwa kwa ajili ya daemons za mfumo. Majina ya akaunti za daemon kwa kawaida huanza na "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Akaunti ya wageni iliyo na ruhusa zilizowekewa vizuizi vikali
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Michakato huendeshwa kwa kutumia mtumiaji huyu wakati ruhusa ndogo zaidi zinahitajika
- **Root**

## Ruhusa za Mtumiaji

- **Mtumiaji wa Kawaida:** Mtumiaji wa msingi zaidi. Mtumiaji huyu anahitaji kupewa ruhusa na mtumiaji wa admin anapojaribu kusakinisha software au kutekeleza kazi nyingine za hali ya juu. Hawezi kufanya hivyo mwenyewe.
- **Mtumiaji wa Admin**: Mtumiaji anayefanya kazi mara nyingi kama mtumiaji wa kawaida, lakini pia anaruhusiwa kutekeleza vitendo vya root kama vile kusakinisha software na kufanya kazi nyingine za kiutawala. Watumiaji wote walio katika admin group **hupewa ufikiaji wa root kupitia sudoers file**.
- **Root**: Root ni mtumiaji anayeruhusiwa kutekeleza karibu kitendo chochote (kuna vikwazo vinavyowekwa na protections kama System Integrity Protection).
- Kwa mfano, root hataweza kuweka file ndani ya `/System`

## Akaunti za Nje

MacOS pia inasaidia kuingia kupitia external identity providers kama vile FaceBook, Google... daemon kuu inayotekeleza kazi hii ni `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) na inawezekana kupata plugins zinazotumiwa kwa external authentication ndani ya folder `/System/Library/Accounts/Authentication/`.\
Zaidi ya hayo, `accountsd` hupata orodha ya account types kutoka `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
