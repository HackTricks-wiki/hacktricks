# macOS Korisnici i Eksterni Računi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni Korisnici

- **Daemon**: Korisnik rezervisan za sistemske demone. Podrazumevana imena naloga demona obično počinju sa "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Račun za goste sa veoma strogim dozvolama
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Procesi se izvršavaju sa ovim korisnikom kada su potrebne minimalne dozvole
- **Root**

## Korisničke privilegije

- **Standardni korisnik:** Najosnovniji korisnik. Ovaj korisnik treba dozvole koje dodeljuje admin korisnik kada pokušava da instalira softver ili izvrši druge napredne zadatke. Ne može to da uradi sam.
- **Admin korisnik**: Korisnik koji većinu vremena radi kao standardni korisnik, ali mu je takođe dozvoljeno da izvršava root akcije kao što su instalacija softvera i drugi administrativni zadaci. Svi korisnici koji pripadaju admin grupi su **dodeljeni pristup root-u putem sudoers datoteke**.
- **Root**: Root je korisnik kojem je dozvoljeno da izvrši gotovo svaku akciju (postoje ograničenja koja nameću zaštite poput System Integrity Protection).
- Na primer, root neće moći da postavi datoteku unutar `/System`

## Eksterni nalozi

MacOS takođe podržava prijavljivanje putem eksternih provajdera identiteta kao što su FaceBook, Google... Glavni demon koji obavlja ovaj posao je `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) i moguće je pronaći dodatke koji se koriste za eksternu autentifikaciju unutar fascikle `/System/Library/Accounts/Authentication/`.\
Pored toga, `accountsd` dobija listu tipova naloga iz `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
