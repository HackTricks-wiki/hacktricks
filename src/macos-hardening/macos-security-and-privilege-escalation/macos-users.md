# Usuarios de macOS y cuentas externas

{{#include ../../banners/hacktricks-training.md}}

## Usuarios comunes

- **Cuentas de daemon**: Reservadas para los daemons del sistema. Sus nombres cortos suelen empezar con un guion bajo (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Invitado**: Una cuenta temporal restringida cuya disponibilidad se puede controlar localmente o mediante una carga útil de Accounts de MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Una identidad deliberadamente sin privilegios, utilizada por servicios que requieren permisos mínimos en el sistema de archivos.
- **Root**: El superusuario. El inicio de sesión interactivo como root está desactivado de forma predeterminada, aunque los administradores pueden realizar operaciones privilegiadas mediante autorización y `sudo`.<sup>[[2]](#references)</sup>

El material de verificación de contraseñas de cuentas locales y el flujo de trabajo para extraerlo se describen en [Contraseñas shadow](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Privilegios de usuario

- **Usuario estándar:** El tipo de cuenta normal, sin privilegios administrativos. Los cambios administrativos requieren la autorización de un administrador.
- **Usuario admin**: Miembro del grupo local `admin`. Los usuarios admin siguen ejecutando los procesos ordinarios con su identidad de usuario, pero pueden autorizar operaciones privilegiadas. No asumas que pertenecer al grupo basta para que todos los comandos se ejecuten como root; `sudo`, Authorization Services, las políticas y las comprobaciones específicas de cada aplicación siguen aplicándose.<sup>[[2]](#references)</sup>
- **Root**: Root es un usuario que puede realizar casi cualquier acción (hay limitaciones impuestas por protecciones como System Integrity Protection).
  - Por ejemplo, System Integrity Protection y el volumen del sistema firmado impiden que incluso root modifique de forma persistente el contenido protegido de `/System` durante el funcionamiento normal.

## Cuentas externas

macOS también admite cuentas de aplicaciones de proveedores externos. El daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) gestiona los datos del framework Accounts, y se pueden encontrar plug-ins de autenticación en `/System/Library/Accounts/Authentication/`. Estas son cuentas de aplicaciones/servicios y no necesariamente identidades que puedan iniciar sesión en la ventana de inicio de sesión de macOS. `accountsd` también lee los tipos de cuenta conocidos desde `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Carga de administración de dispositivos Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permisos y propiedad de BSD: cuentas administrativas y root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
