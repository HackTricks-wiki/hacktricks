# Utilisateurs macOS et comptes externes

{{#include ../../banners/hacktricks-training.md}}

## Utilisateurs courants

- **Comptes daemon** : réservés aux daemons système. Leurs noms courts commencent généralement par un trait de soulignement (`_`) :

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Invité** : Un compte temporaire à accès restreint, dont la disponibilité peut être contrôlée localement ou par une charge utile Accounts MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody** : une identité volontairement dépourvue de privilèges, utilisée par les services qui nécessitent des permissions minimales sur le système de fichiers.
- **Root** : le superutilisateur. La connexion interactive en tant que root est désactivée par défaut, mais les administrateurs peuvent effectuer des opérations privilégiées via l’autorisation et `sudo`.<sup>[[2]](#references)</sup>

Les éléments locaux de vérification des mots de passe des comptes et leur procédure d’extraction sont présentés dans [Mots de passe shadow](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Privilèges utilisateur

- **Utilisateur standard :** le type de compte normal, non administratif. Les modifications administratives nécessitent l’autorisation d’un administrateur.
- **Utilisateur admin** : membre du groupe local `admin`. Les utilisateurs admin exécutent toujours les processus ordinaires sous leur identité d’utilisateur, mais peuvent autoriser des opérations privilégiées. Ne supposez pas que cette appartenance suffit à exécuter chaque commande en tant que root ; `sudo`, Authorization Services, les politiques et les vérifications propres aux applications s’appliquent toujours.<sup>[[2]](#references)</sup>
- **Root** : root est un utilisateur autorisé à effectuer presque toutes les actions (des protections comme System Integrity Protection imposent certaines limites).
  - Par exemple, System Integrity Protection et le volume système signé empêchent même root de modifier durablement le contenu protégé de `/System` en fonctionnement normal.

## Comptes externes

macOS prend également en charge les comptes d’applications provenant de fournisseurs externes. Le daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) sert d’intermédiaire pour les données du framework Accounts, et les modules d’authentification se trouvent sous `/System/Library/Accounts/Authentication/`. Il s’agit de comptes d’applications/services, qui ne correspondent pas nécessairement à des identités pouvant ouvrir une session dans la fenêtre de connexion macOS. `accountsd` lit également les types de comptes connus dans `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Charge utile de gestion des comptes d’un appareil](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permissions et propriété BSD : comptes administrateur et root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
