# Usuarios de macOS y Cuentas Externas

{{#include ../../banners/hacktricks-training.md}}

## Usuarios Comunes

- **Daemon**: Usuario reservado para demonios del sistema. Los nombres de cuenta de demonio predeterminados suelen comenzar con un "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Cuenta para invitados con permisos muy estrictos.
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nadie**: Los procesos se ejecutan con este usuario cuando se requieren permisos mínimos.
- **Root**

## Privilegios de Usuario

- **Usuario Estándar:** El más básico de los usuarios. Este usuario necesita permisos otorgados por un usuario administrador al intentar instalar software o realizar otras tareas avanzadas. No puede hacerlo por su cuenta.
- **Usuario Administrador**: Un usuario que opera la mayor parte del tiempo como un usuario estándar, pero que también tiene permitido realizar acciones de root, como instalar software y otras tareas administrativas. Todos los usuarios que pertenecen al grupo de administradores **tienen acceso a root a través del archivo sudoers**.
- **Root**: Root es un usuario que puede realizar casi cualquier acción (hay limitaciones impuestas por protecciones como la Protección de Integridad del Sistema).
- Por ejemplo, root no podrá colocar un archivo dentro de `/System`.

## Cuentas Externas

MacOS también admite iniciar sesión a través de proveedores de identidad externos como FaceBook, Google... El principal daemon que realiza este trabajo es `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) y es posible encontrar plugins utilizados para la autenticación externa dentro de la carpeta `/System/Library/Accounts/Authentication/`.\
Además, `accountsd` obtiene la lista de tipos de cuentas de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
