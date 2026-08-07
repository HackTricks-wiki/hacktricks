# macOS korisnici i eksterni nalozi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni korisnici

- **Daemon**: Korisnik rezervisan za system daemons. Podrazumevana imena daemon naloga obično počinju znakom "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gost**: Nalog za goste sa veoma strogim dozvolama
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Procesi se izvršavaju sa ovim korisnikom kada su potrebne minimalne dozvole
- **Root**

## Privilegije korisnika

- **Standardni korisnik:** Najosnovniji tip korisnika. Ovom korisniku su potrebne dozvole koje dodeljuje admin korisnik kada pokušava da instalira software ili obavlja druge napredne zadatke. Ne može to da uradi samostalno.
- **Admin korisnik**: Korisnik koji većinu vremena radi kao standardni korisnik, ali takođe može da obavlja root radnje, kao što su instalacija software-a i drugi administrativni zadaci. Svim korisnicima koji pripadaju admin grupi **omogućen je pristup root-u putem sudoers file-a**.
- **Root**: Root je korisnik kome je dozvoljeno da obavlja gotovo svaku radnju (postoje ograničenja koja nameću zaštite kao što je System Integrity Protection).
- Na primer, root neće moći da smesti file unutar `/System`

## Spoljni nalozi

MacOS takođe podržava prijavljivanje putem eksternih identity provider-a kao što su FaceBook, Google... Glavni daemon koji obavlja ovaj zadatak je `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), a plugin-ove koji se koriste za eksternu authentication moguće je pronaći u folderu `/System/Library/Accounts/Authentication/`.\
Pored toga, `accountsd` dobija listu tipova naloga iz `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
