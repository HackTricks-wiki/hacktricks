# Użytkownicy macOS i konta zewnętrzne

{{#include ../../banners/hacktricks-training.md}}

## Wspólni użytkownicy

- **Daemon**: Użytkownik zarezerwowany dla demonów systemowych. Domyślne nazwy kont demonów zazwyczaj zaczynają się od "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Gość**: Konto dla gości z bardzo restrykcyjnymi uprawnieniami
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nikt**: Procesy są wykonywane z tym użytkownikiem, gdy wymagane są minimalne uprawnienia
- **Root**

## Uprawnienia użytkowników

- **Użytkownik standardowy:** Najbardziej podstawowy użytkownik. Ten użytkownik potrzebuje uprawnień przyznanych przez użytkownika admina, gdy próbuje zainstalować oprogramowanie lub wykonać inne zaawansowane zadania. Nie jest w stanie zrobić tego samodzielnie.
- **Użytkownik admina**: Użytkownik, który działa przez większość czasu jako użytkownik standardowy, ale ma również prawo do wykonywania działań root, takich jak instalacja oprogramowania i inne zadania administracyjne. Wszyscy użytkownicy należący do grupy admin mają **dostęp do roota za pośrednictwem pliku sudoers**.
- **Root**: Root to użytkownik, któremu zezwala się na wykonywanie prawie każdej akcji (istnieją ograniczenia nałożone przez zabezpieczenia, takie jak System Integrity Protection).
- Na przykład root nie będzie w stanie umieścić pliku w `/System`

## Konta zewnętrzne

MacOS obsługuje również logowanie za pośrednictwem zewnętrznych dostawców tożsamości, takich jak FaceBook, Google... Główny demon wykonujący tę pracę to `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) i możliwe jest znalezienie wtyczek używanych do zewnętrznej autoryzacji w folderze `/System/Library/Accounts/Authentication/`.\
Ponadto `accountsd` pobiera listę typów kont z `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
