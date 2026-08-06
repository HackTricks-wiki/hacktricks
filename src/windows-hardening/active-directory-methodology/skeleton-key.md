# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

El **Skeleton Key attack** es una técnica que permite a los atacantes **evitar la autenticación de Active Directory** mediante la **inyección de una contraseña maestra** en el proceso LSASS de cada controlador de dominio. Después de la inyección, la contraseña maestra (por defecto, **`mimikatz`**) puede utilizarse para autenticarse como **cualquier usuario del dominio**, mientras sus contraseñas reales siguen funcionando.<sup>[[1]](#references)[[2]](#references)</sup>

Datos clave:

- Requiere **Domain Admin/SYSTEM + SeDebugPrivilege** en cada DC y debe **reaplicarse después de cada reinicio**.<sup>[[2]](#references)</sup>
- Parchea las rutas de validación de **NTLM** y **Kerberos RC4 (etype 0x17)**; los realms que solo utilizan AES o las cuentas que exigen AES **no aceptarán el skeleton key**.<sup>[[2]](#references)</sup>
- Puede entrar en conflicto con paquetes de autenticación LSA de terceros o con proveedores adicionales de smart-card / MFA.<sup>[[2]](#references)</sup>
- El módulo de Mimikatz acepta el switch opcional `/letaes` para evitar modificar los hooks de Kerberos/AES en caso de problemas de compatibilidad.<sup>[[3]](#references)</sup>

### Execution

LSASS clásico, no protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS se ejecuta como PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), se necesita un controlador de kernel para eliminar la protección antes de aplicar parches a LSASS:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Después de la inyección, autentícate con cualquier cuenta del dominio, pero usa la contraseña `mimikatz` (o el valor establecido por el operador). Recuerda repetirlo en **todos los DCs** en entornos con varios DCs.

## Mitigaciones

- **Supervisión de logs**
- **Event ID 7045** del sistema (instalación de servicio/driver) para drivers sin firma, como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (carga de driver) para `mimidrv.sys`; Event ID 10 para accesos sospechosos a `lsass.exe` desde procesos que no sean del sistema.
- **Event ID 4673/4611** de Security para usos de privilegios sensibles o anomalías en el registro de paquetes de autenticación de LSA; correlaciona con logons 4624 inesperados que usen RC4 (etype 0x17) desde DCs.
- **Hardening de LSASS**
- Mantén **RunAsPPL/Credential Guard/Secure LSASS** habilitado en los DCs para obligar a los atacantes a desplegar drivers en modo kernel (más telemetría y explotación más difícil).
- Deshabilita **RC4** cuando sea posible; los tickets de Kerberos limitados a AES impiden el path de hook de RC4 utilizado por skeleton key.<sup>[[2]](#references)</sup>
- Búsquedas rápidas con PowerShell:
- Detectar instalaciones de drivers kernel sin firma: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Buscar el driver de Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validar que PPL se aplica después del reinicio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para obtener orientación adicional sobre el hardening de credenciales, consulta [protecciones de credenciales de Windows](../stealing-credentials/credentials-protections.md).

## Referencias

- [1] [Netwrix – ataque Skeleton Key en Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – módulo misc::skeleton de Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
