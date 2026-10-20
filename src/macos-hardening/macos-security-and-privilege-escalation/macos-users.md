# macOS korisnici i eksterni nalozi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni korisnici

- **Daemon nalozi**: Rezervisani su za sistemske daemon-e. Njihova kratka imena obično počinju donjom crtom (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Gost**: Ograničen, privremeni nalog čija se dostupnost može kontrolisati lokalno ili pomoću MDM Accounts payload-a.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Namerno neprivilegovani identitet koji koriste servisi kojima su potrebne minimalne dozvole za sistem datoteka.
- **Root**: Superkorisnik. Interaktivno prijavljivanje kao root podrazumevano je onemogućeno, mada administratori mogu da obavljaju privilegovane operacije putem autorizacije i `sudo`.<sup>[[2]](#references)</sup>

Materijal za proveru lozinki lokalnih naloga i postupak njegovog izdvajanja obrađeni su u odeljku [Lozinke u shadow fajlu](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Korisničke privilegije

- **Standardni korisnik:** Uobičajen tip naloga bez administrativnih privilegija. Za administrativne izmene potrebna je autorizacija administratora.
- **Admin korisnik**: Član lokalne grupe `admin`. Admin korisnici i dalje pokreću uobičajene procese pod svojim korisničkim identitetom, ali mogu da autorizuju privilegovane operacije. Nemojte pretpostaviti da samo članstvo u grupi znači da se svaka komanda izvršava kao root; i dalje se primenjuju `sudo`, Authorization Services, pravila i provere specifične za aplikaciju.<sup>[[2]](#references)</sup>
- **Root**: Root je korisnik kome je dozvoljeno da obavlja gotovo svaku radnju (postoje ograničenja koja nameću zaštite kao što je System Integrity Protection).
  - Na primer, System Integrity Protection i potpisani sistemski volumen sprečavaju čak i root korisnika da tokom uobičajenog rada trajno menja zaštićeni sadržaj direktorijuma `/System`.

## Spoljni nalozi

macOS podržava i naloge aplikacija kod spoljnih provajdera. Daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) posreduje u radu sa podacima Accounts frameworka, a dodaci za autentifikaciju mogu se pronaći u direktorijumu `/System/Library/Accounts/Authentication/`. To su nalozi aplikacija/usluga, a ne nužno identiteti koji mogu da se prijave na macOS prozoru za prijavljivanje. `accountsd` takođe čita poznate tipove naloga iz fajla `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — korisni teret za upravljanje uređajem Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD dozvole i vlasništvo: administratorski i root nalozi](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
