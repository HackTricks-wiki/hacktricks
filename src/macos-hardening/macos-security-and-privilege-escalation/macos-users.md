# Użytkownicy macOS i konta zewnętrzne

{{#include ../../banners/hacktricks-training.md}}

## Typowi użytkownicy

- **Konta daemon**: Zarezerwowane dla systemowych daemonów. Ich krótkie nazwy zwykle zaczynają się od podkreślenia (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gość**: Ograniczone, tymczasowe konto, którego dostępność można kontrolować lokalnie lub za pomocą payloadu Accounts w MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Celowo nieuprzywilejowana tożsamość używana przez usługi wymagające minimalnych uprawnień systemu plików.
- **Root**: Superuser. Interaktywne logowanie jako root jest domyślnie wyłączone, chociaż administratorzy mogą wykonywać uprzywilejowane operacje za pośrednictwem autoryzacji i `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Użytkownik standardowy:** Zwykły typ konta, bez uprawnień administracyjnych. Zmiany administracyjne wymagają autoryzacji administratora.
- **Użytkownik administracyjny**: Członek lokalnej grupy `admin`. Użytkownicy administracyjni nadal uruchamiają zwykłe procesy z własną tożsamością użytkownika, ale mogą autoryzować uprzywilejowane operacje. Nie zakładaj, że sama przynależność do grupy powoduje uruchamianie każdego polecenia jako root; nadal obowiązują `sudo`, Authorization Services, zasady i kontrole właściwe dla danej aplikacji.<sup>[[2]](#references)</sup>
- **Root**: Root to użytkownik, który może wykonywać niemal dowolne działania (istnieją ograniczenia nakładane przez mechanizmy ochrony, takie jak System Integrity Protection).
- Na przykład System Integrity Protection i signed system volume uniemożliwiają nawet rootowi trwałe modyfikowanie chronionej zawartości `/System` podczas normalnego działania.

## External Accounts

macOS obsługuje również konta aplikacji pochodzące od zewnętrznych dostawców. Demon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) pośredniczy w obsłudze danych Accounts-framework, a plug-ins uwierzytelniania można znaleźć w `/System/Library/Accounts/Authentication/`. Są to konta aplikacji/usług, a niekoniecznie tożsamości, które mogą logować się w oknie logowania macOS. `accountsd` odczytuje również znane typy kont z `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload zarządzania kontami urządzenia](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Uprawnienia BSD i własność: konta administracyjne i root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
