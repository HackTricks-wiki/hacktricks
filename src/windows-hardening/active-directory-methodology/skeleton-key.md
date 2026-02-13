# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

El **Skeleton Key attack** es una técnica que permite a los atacantes **omitir la autenticación de Active Directory** mediante **la inyección de una contraseña maestra** en el proceso LSASS de cada controlador de dominio. Tras la inyección, la contraseña maestra (por defecto **`mimikatz`**) puede usarse para autenticarse como **cualquier usuario del dominio** mientras sus contraseñas reales siguen funcionando.

Puntos clave:

- Requiere **Domain Admin/SYSTEM + SeDebugPrivilege** en cada DC y debe **reaplicarse después de cada reinicio**.
- Modifica las rutas de validación de **NTLM** y **Kerberos RC4 (etype 0x17)**; los dominios solo con AES o las cuentas que requieren AES **no aceptarán el skeleton key**.
- Puede entrar en conflicto con paquetes de autenticación LSA de terceros o con proveedores adicionales de smart‑card / MFA.
- El módulo Mimikatz acepta el switch opcional `/letaes` para evitar tocar los hooks de Kerberos/AES en caso de problemas de compatibilidad.

### Ejecución

LSASS clásico no protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS se está ejecutando como PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), se necesita un kernel driver para eliminar la protección antes de parchear LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Después de la inyección, autentíquese con cualquier cuenta del dominio pero use la contraseña `mimikatz` (o el valor establecido por el operador). Recuerde repetir en **todos los DCs** en entornos con múltiples DCs.

## Mitigaciones

- **Monitoreo de logs**
- System **Event ID 7045** (instalación de servicio/controlador) para controladores no firmados como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) para `mimidrv.sys`; Event ID 10 para accesos sospechosos a `lsass.exe` desde procesos no del sistema.
- Security **Event ID 4673/4611** por uso de privilegios sensibles o anomalías en el registro de paquetes de autenticación LSA; correlacione con inicios de sesión 4624 inesperados usando RC4 (etype 0x17) desde DCs.
- **Endurecimiento de LSASS**
- Mantenga **RunAsPPL/Credential Guard/Secure LSASS** habilitados en los DCs para forzar a los atacantes a desplegar drivers en modo kernel (más telemetría, explotación más difícil).
- Desactive RC4 legado donde sea posible; limitar los tickets Kerberos a AES previene la vía de hook RC4 usada por el skeleton key.
- Búsquedas rápidas con PowerShell:
- Detecte instalaciones de drivers de kernel no firmados: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`  
- Busque el driver de Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`  
- Valide que PPL esté aplicado después del reinicio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para orientación adicional sobre endurecimiento de credenciales consulte [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
