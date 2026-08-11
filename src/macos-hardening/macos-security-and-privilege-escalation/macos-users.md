# Usuarios de macOS y cuentas externas

{{#include ../../banners/hacktricks-training.md}}

## Usuarios comunes

- **Cuentas de daemon**: Reservadas para los daemons del sistema. Sus nombres cortos suelen comenzar con un guion bajo (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Una cuenta restringida y temporal cuya disponibilidad puede controlarse localmente o mediante un payload de Accounts de MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Una identidad deliberadamente sin privilegios utilizada por servicios que requieren permisos mínimos en el sistema de archivos.
- **Root**: El superusuario. El inicio de sesión interactivo como root está deshabilitado de forma predeterminada, aunque los administradores pueden realizar operaciones privilegiadas mediante autorización y `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Usuario estándar:** El tipo de cuenta normal y no administrativa. Los cambios administrativos requieren la autorización de un administrador.
- **Usuario administrador**: Miembro del grupo local `admin`. Los usuarios administradores siguen ejecutando los procesos ordinarios con su identidad de usuario, pero pueden autorizar operaciones privilegiadas. No asumas que la pertenencia por sí sola hace que cada comando se ejecute como root; `sudo`, Authorization Services, las políticas y las comprobaciones específicas de las aplicaciones siguen siendo aplicables.<sup>[[2]](#references)</sup>
- **Root**: Root es un usuario autorizado a realizar prácticamente cualquier acción (existen limitaciones impuestas por protecciones como System Integrity Protection).
- Por ejemplo, System Integrity Protection y el volumen del sistema firmado impiden incluso a root modificar de forma persistente el contenido protegido de `/System` durante el funcionamiento normal.

## External Accounts

macOS también admite cuentas de aplicaciones de proveedores externos. El daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) gestiona los datos del Accounts framework, y los plug-ins de autenticación se pueden encontrar en `/System/Library/Accounts/Authentication/`. Estas son cuentas de aplicaciones/servicios, no necesariamente identidades que puedan iniciar sesión en la ventana de inicio de sesión de macOS. `accountsd` también lee los tipos de cuenta conocidos de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permisos y propiedad BSD: cuentas administrativas y root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
