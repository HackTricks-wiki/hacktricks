# Utilisateurs macOS et comptes externes

{{#include ../../banners/hacktricks-training.md}}

## Utilisateurs courants

- **Daemon** : Utilisateur réservé aux daemons système. Les noms de comptes daemon par défaut commencent généralement par un "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest** : Compte destiné aux invités, avec des permissions très strictes
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody** : Les processus sont exécutés avec cet utilisateur lorsque des permissions minimales sont requises
- **Root**

## Privilèges utilisateur

- **Utilisateur standard :** Le type d'utilisateur le plus basique. Cet utilisateur doit obtenir des permissions accordées par un utilisateur admin lorsqu'il tente d'installer des logiciels ou d'effectuer d'autres tâches avancées. Il ne peut pas le faire seul.
- **Utilisateur admin** : Utilisateur qui fonctionne la plupart du temps comme un utilisateur standard, mais qui est également autorisé à effectuer des actions root, comme installer des logiciels et effectuer d'autres tâches administratives. Tous les utilisateurs appartenant au groupe admin **obtiennent un accès à root via le fichier sudoers**.
- **Root** : Root est un utilisateur autorisé à effectuer presque toutes les actions (des limitations sont imposées par des protections comme System Integrity Protection).
- Par exemple, root ne pourra pas placer un fichier dans `/System`

## Comptes externes

MacOS prend également en charge la connexion via des fournisseurs d'identité externes tels que FaceBook, Google... Le daemon principal qui effectue cette tâche est `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) et il est possible de trouver les plugins utilisés pour l'authentification externe dans le dossier `/System/Library/Accounts/Authentication/`.\
De plus, `accountsd` récupère la liste des types de comptes depuis `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
