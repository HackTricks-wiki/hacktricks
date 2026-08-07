# Utenti macOS e Account esterni

{{#include ../../banners/hacktricks-training.md}}

## Utenti comuni

- **Daemon**: User riservato ai daemon di sistema. I nomi degli account daemon predefiniti iniziano solitamente con "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Ospite**: Account per gli ospiti con permessi molto restrittivi
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nessuno**: I processi vengono eseguiti con questo utente quando sono necessarie autorizzazioni minime
- **Root**

## Privilegi utente

- **Utente standard:** Il tipo di utente più basilare. Questo utente necessita delle autorizzazioni concesse da un utente admin quando tenta di installare software o eseguire altre attività avanzate. Non può farlo autonomamente.
- **Utente admin**: Un utente che opera per la maggior parte del tempo come utente standard, ma che può anche eseguire azioni da root, come installare software e svolgere altre attività amministrative. A tutti gli utenti appartenenti al gruppo admin **viene concesso l'accesso a root tramite il file sudoers**.
- **Root**: Root è un utente autorizzato a eseguire quasi qualsiasi azione (esistono limitazioni imposte da protezioni come System Integrity Protection).
- Ad esempio, root non potrà inserire un file all'interno di `/System`

## Account esterni

MacOS supporta anche l'accesso tramite identity provider esterni come FaceBook, Google... Il demone principale che esegue questo compito è `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) ed è possibile trovare i plugin utilizzati per l'autenticazione esterna nella cartella `/System/Library/Accounts/Authentication/`.\
Inoltre, `accountsd` ottiene l'elenco dei tipi di account da `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
