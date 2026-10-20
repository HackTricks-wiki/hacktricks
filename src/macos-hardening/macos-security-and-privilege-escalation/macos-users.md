# Utenti macOS e account esterni

{{#include ../../banners/hacktricks-training.md}}

## Utenti comuni

- **Account daemon**: riservati ai daemon di sistema. I loro nomi brevi iniziano comunemente con un trattino basso (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Ospite**: Un account temporaneo con restrizioni, la cui disponibilità può essere controllata localmente o tramite un payload Accounts di MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nessuno**: Un'identità deliberatamente priva di privilegi, usata dai servizi che richiedono autorizzazioni minime sul filesystem.
- **Root**: Il superutente. L'accesso interattivo come root è disabilitato per impostazione predefinita, anche se gli amministratori possono eseguire operazioni con privilegi tramite l'autorizzazione e `sudo`.<sup>[[2]](#references)</sup>

I dati locali per la verifica delle password degli account e il relativo processo di estrazione sono trattati in [Password shadow](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Privilegi degli utenti

- **Utente standard:** Il normale tipo di account non amministrativo. Per apportare modifiche amministrative è necessaria l'autorizzazione di un amministratore.
- **Utente admin**: Un membro del gruppo locale `admin`. Gli utenti admin continuano a eseguire i processi ordinari con la propria identità utente, ma possono autorizzare operazioni con privilegi. Non presumere che la sola appartenenza al gruppo faccia eseguire ogni comando come root: si applicano comunque `sudo`, Authorization Services, le policy e i controlli specifici delle applicazioni.<sup>[[2]](#references)</sup>
- **Root**: Root è un utente autorizzato a eseguire quasi qualsiasi operazione (con alcune limitazioni imposte da protezioni come System Integrity Protection).
  - Ad esempio, System Integrity Protection e il volume di sistema firmato impediscono persino a root di modificare in modo persistente i contenuti protetti di `/System` durante il normale funzionamento.

## Account esterni

macOS supporta anche account delle applicazioni forniti da provider esterni. Il daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) gestisce i dati del framework Accounts, mentre i plug-in di autenticazione si trovano in `/System/Library/Accounts/Authentication/`. Si tratta di account di applicazioni o servizi, non necessariamente di identità che possono accedere dalla finestra di login di macOS. `accountsd` legge anche i tipi di account noti da `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload di gestione dei dispositivi Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permessi e proprietà BSD: account amministrativi e root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
