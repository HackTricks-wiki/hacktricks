# Utenti macOS e account esterni

{{#include ../../banners/hacktricks-training.md}}

## Utenti comuni

- **Account daemon**: Riservati ai daemon di sistema. I loro short name iniziano comunemente con un underscore (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Un account limitato e temporaneo, la cui disponibilità può essere controllata localmente o tramite un Accounts payload di MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Un’identità deliberatamente priva di privilegi, utilizzata dai servizi che richiedono autorizzazioni minime sul filesystem.
- **Root**: Il superuser. L’accesso interattivo come root è disabilitato per impostazione predefinita, sebbene gli amministratori possano eseguire operazioni con privilegi tramite l’autorizzazione e `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Utente standard:** Il normale tipo di account non amministrativo. Le modifiche amministrative richiedono l’autorizzazione di un amministratore.
- **Utente admin**: Un membro del gruppo locale `admin`. Gli utenti admin eseguono comunque i processi ordinari con la propria identità utente, ma possono autorizzare operazioni con privilegi. Non presumere che la sola appartenenza al gruppo faccia eseguire ogni comando come root; `sudo`, Authorization Services, le policy e i controlli specifici delle applicazioni restano applicabili.<sup>[[2]](#references)</sup>
- **Root**: Root è un utente autorizzato a eseguire quasi qualsiasi azione (esistono limitazioni imposte da protezioni come System Integrity Protection).
- Ad esempio, System Integrity Protection e il signed system volume impediscono persino a root di modificare permanentemente i contenuti protetti di `/System` durante il normale funzionamento.

## External Accounts

macOS supporta anche account delle applicazioni provenienti da provider esterni. Il daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) gestisce i dati dell’Accounts framework, mentre i plug-in di autenticazione possono trovarsi in `/System/Library/Accounts/Authentication/`. Si tratta di account di applicazioni/servizi, non necessariamente di identità che possono accedere dalla finestra di login di macOS. `accountsd` legge inoltre i tipi di account conosciuti da `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload di gestione dei dispositivi Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permessi e ownership BSD: account amministrativi e root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
