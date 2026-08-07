# Usuarios de macOS y cuentas externas

{{#include ../../banners/hacktricks-training.md}}

## Usuarios comunes

- **Daemon**: Usuario reservado para los daemons del sistema. Los nombres de las cuentas daemon predeterminadas suelen comenzar con "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Cuenta para invitados con permisos muy estrictos
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Los procesos se ejecutan con este usuario cuando se requieren permisos mínimos
- **Root**

## Privilegios de usuario

- **Usuario estándar:** El tipo de usuario más básico. Este usuario necesita permisos otorgados por un usuario administrador cuando intenta instalar software o realizar otras tareas avanzadas. No puede hacerlo por su cuenta.
- **Usuario administrador**: Un usuario que opera la mayor parte del tiempo como usuario estándar, pero que también puede realizar acciones de root, como instalar software y otras tareas administrativas. Todos los usuarios pertenecientes al grupo de administradores tienen **acceso a root mediante el archivo sudoers**.
- **Root**: Root es un usuario autorizado a realizar prácticamente cualquier acción (existen limitaciones impuestas por protecciones como System Integrity Protection).
- Por ejemplo, root no podrá colocar un archivo dentro de `/System`

## Cuentas externas

MacOS también permite iniciar sesión mediante proveedores de identidad externos como FaceBook, Google... El daemon principal que realiza esta tarea es `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) y es posible encontrar los plugins utilizados para la autenticación externa dentro de la carpeta `/System/Library/Accounts/Authentication/`.\
Además, `accountsd` obtiene la lista de tipos de cuenta de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
