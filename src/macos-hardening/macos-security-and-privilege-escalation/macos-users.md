# Utilisateurs macOS et comptes externes

{{#include ../../banners/hacktricks-training.md}}

## Utilisateurs courants

- **Comptes de daemon** : réservés aux daemons système. Leurs noms courts commencent généralement par un trait de soulignement (`_`) :

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Invité** : un compte restreint et temporaire dont la disponibilité peut être contrôlée localement ou par un payload Accounts MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody** : Une identité délibérément dépourvue de privilèges, utilisée par les services nécessitant des permissions minimales sur le système de fichiers.
- **Root** : Le superutilisateur. La connexion interactive en tant que root est désactivée par défaut, bien que les administrateurs puissent effectuer des opérations privilégiées via l’autorisation et `sudo`.<sup>[[2]](#references)</sup>

## Privilèges utilisateur

- **Utilisateur standard :** Le type de compte normal et non administratif. Les modifications administratives nécessitent l’autorisation d’un administrateur.
- **Utilisateur admin** : Membre du groupe local `admin`. Les utilisateurs admin exécutent toujours les processus ordinaires avec leur identité utilisateur, mais peuvent autoriser des opérations privilégiées. Ne supposez pas que l’appartenance à ce groupe suffit à faire exécuter chaque commande en tant que root ; `sudo`, Authorization Services, les politiques et les vérifications spécifiques aux applications s’appliquent toujours.<sup>[[2]](#references)</sup>
- **Root** : Root est un utilisateur autorisé à effectuer presque toute action (certaines limitations sont imposées par des protections comme System Integrity Protection).
- Par exemple, System Integrity Protection et le signed system volume empêchent même root de modifier durablement le contenu protégé de `/System` pendant le fonctionnement normal.

## Comptes externes

macOS prend également en charge les comptes d’applications provenant de fournisseurs externes. Le daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) sert d’intermédiaire pour les données du framework Accounts, et les plug-ins d’authentification se trouvent sous `/System/Library/Accounts/Authentication/`. Il s’agit de comptes d’applications/services, et non nécessairement d’identités pouvant se connecter à la fenêtre de connexion de macOS. `accountsd` lit également les types de comptes connus dans `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload de gestion des comptes des appareils](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permissions et propriété BSD : comptes administratifs et root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
