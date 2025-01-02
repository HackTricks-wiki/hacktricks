# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## Common Users

- **Daemon**: Utente riservato per i demoni di sistema. I nomi degli account daemon predefiniti di solito iniziano con un "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Account per ospiti con permessi molto restrittivi
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nessuno**: I processi vengono eseguiti con questo utente quando sono richieste autorizzazioni minime
- **Root**

## Privilegi Utente

- **Utente Standard:** Il tipo più basilare di utente. Questo utente ha bisogno di autorizzazioni concesse da un utente admin quando tenta di installare software o eseguire altre operazioni avanzate. Non è in grado di farlo da solo.
- **Utente Admin**: Un utente che opera per la maggior parte del tempo come un utente standard ma è anche autorizzato a eseguire azioni di root come installare software e altre operazioni amministrative. Tutti gli utenti appartenenti al gruppo admin **hanno accesso a root tramite il file sudoers**.
- **Root**: Root è un utente autorizzato a eseguire quasi qualsiasi azione (ci sono limitazioni imposte da protezioni come System Integrity Protection).
- Ad esempio, root non sarà in grado di posizionare un file all'interno di `/System`

## Account Esterni

MacOS supporta anche l'accesso tramite fornitori di identità esterni come FaceBook, Google... Il principale demone che esegue questo lavoro è `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) ed è possibile trovare plugin utilizzati per l'autenticazione esterna all'interno della cartella `/System/Library/Accounts/Authentication/`.\
Inoltre, `accountsd` ottiene l'elenco dei tipi di account da `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
