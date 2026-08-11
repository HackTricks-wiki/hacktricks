# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

El **ataque Skeleton Key** es una técnica que permite a los atacantes **eludir la autenticación de Active Directory** mediante la **inyección de una contraseña maestra** en el proceso LSASS de cada controlador de dominio. Tras la inyección, la contraseña maestra (por defecto, **`mimikatz`**) puede utilizarse para autenticarse como **cualquier usuario del dominio**, mientras sus contraseñas reales siguen funcionando.<sup>[[1]](#references)[[2]](#references)</sup>

Datos clave:

- Requiere **Domain Admin/SYSTEM + SeDebugPrivilege** en cada DC y debe **volver a aplicarse después de cada reinicio**.<sup>[[2]](#references)</sup>
- La implementación clásica de Mimikatz modifica las rutas de validación de **NTLM** y **Kerberos RC4 (etype 0x17)**; la autenticación que solo utiliza AES **no acepta esa contraseña skeleton mediante el hook de RC4**.<sup>[[2]](#references)</sup>
- Puede entrar en conflicto con paquetes de autenticación LSA de terceros o con proveedores adicionales de tarjetas inteligentes / MFA.<sup>[[2]](#references)</sup>
- El módulo de Mimikatz acepta el switch opcional `/letaes` para evitar modificar los hooks de Kerberos/AES en caso de problemas de compatibilidad.<sup>[[3]](#references)</sup>

### Ejecución

LSASS clásico, no protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS se ejecuta como un proceso protegido ligero (PPL)**, el acceso de depuración en modo usuario está bloqueado. El procedimiento histórico de Mimikatz que se muestra a continuación carga su controlador del kernel y elimina la protección antes de aplicar parches a LSASS. Credential Guard es un control de aislamiento independiente y no debe utilizarse como sinónimo de PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Después de la inyección, autentícate con cualquier cuenta del dominio, pero usa la contraseña `mimikatz` (o el valor establecido por el operador). Recuerda repetirlo en **todos los DCs** en entornos con varios DCs.

## Mitigaciones

- **Monitorización de logs**
- **Event ID 7045** del sistema (instalación de servicio/controlador) para controladores sin firmar como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (carga de controladores) para `mimidrv.sys`; Event ID 10 para accesos sospechosos a `lsass.exe` desde procesos que no sean del sistema.
- **Event ID 4673/4611** de Security para uso de privilegios confidenciales o anomalías en el registro de paquetes de autenticación de LSA; correlaciona con logons 4624 inesperados que utilicen RC4 (etype 0x17) desde DCs.
- **Hardening de LSASS**
- Mantén **RunAsPPL** y **Credential Guard** habilitados cuando sean compatibles. Proporcionan protecciones diferentes y, juntos, aumentan el coste y la telemetría de los intentos de modificar o extraer secretos de LSASS.<sup>[[4]](#references)</sup>
- Deshabilita **RC4** cuando sea posible; los tickets de Kerberos limitados a AES impiden el hook path de RC4 utilizado por skeleton key.<sup>[[2]](#references)</sup>
- Búsquedas rápidas con PowerShell:
- Detectar instalaciones de controladores kernel sin firmar: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Buscar el controlador de Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validar que PPL se aplica después del reinicio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para obtener orientación adicional sobre el hardening de credenciales, consulta [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Ataque Skeleton Key en Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Módulo misc::skeleton de Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configurar protección LSA adicional](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
