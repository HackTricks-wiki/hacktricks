# macOS korisnici i eksterni nalozi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni korisnici

- **Daemon nalozi**: Rezervisani za sistemske daemon-e. Njihova kratka imena obično počinju donjom crtom (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Ograničeni, privremeni nalog čija se dostupnost može kontrolisati lokalno ili pomoću MDM Accounts payload-a.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Namerno neprivilegovani identitet koji koriste servisi kojima su potrebne minimalne dozvole nad filesystemom.
- **Root**: Superuser. Interaktivno root prijavljivanje je podrazumevano onemogućeno, iako administratori mogu da izvršavaju privilegovane operacije putem autorizacije i `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Standardni korisnik:** Uobičajeni nalog koji nije administrativan. Administrativne promene zahtevaju autorizaciju administratora.
- **Admin user**: Član lokalne `admin` grupe. Admin korisnici i dalje izvršavaju obične procese sa svojim korisničkim identitetom, ali mogu da autorizuju privilegovane operacije. Nemojte pretpostaviti da samo članstvo znači da će se svaka komanda izvršavati kao root; `sudo`, Authorization Services, policy i provere specifične za aplikaciju i dalje se primenjuju.<sup>[[2]](#references)</sup>
- **Root**: Root je korisnik kome je dozvoljeno da izvrši gotovo svaku radnju (postoje ograničenja koja nameću zaštite kao što je System Integrity Protection).
- Na primer, System Integrity Protection i signed system volume sprečavaju čak i root da trajno menja zaštićeni sadržaj direktorijuma `/System` tokom uobičajenog rada.

## External Accounts

macOS takođe podržava application naloge eksternih provajdera. `accountsd` daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) posreduje u radu sa podacima Accounts frameworka, a authentication plug-ins se mogu pronaći u direktorijumu `/System/Library/Accounts/Authentication/`. Ovo su application/service nalozi, a ne nužno identiteti koji mogu da se prijave u macOS login window. `accountsd` takođe čita poznate tipove naloga iz `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — payload za upravljanje Accounts uređajima](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD dozvole i vlasništvo: administrativni i root nalozi](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
