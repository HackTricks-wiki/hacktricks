# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Ataque de Skeleton Key

El **ataque de Skeleton Key** es una técnica sofisticada que permite a los atacantes **eludir la autenticación de Active Directory** al **inyectar una contraseña maestra** en el controlador de dominio. Esto permite al atacante **autenticarse como cualquier usuario** sin su contraseña, otorgándoles **acceso sin restricciones** al dominio.

Se puede realizar utilizando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Para llevar a cabo este ataque, **se requieren derechos de Administrador de Dominio**, y el atacante debe dirigirse a cada controlador de dominio para asegurar una violación completa. Sin embargo, el efecto del ataque es temporal, ya que **reiniciar el controlador de dominio erradica el malware**, lo que requiere una reimplementación para un acceso sostenido.

**Ejecutar el ataque** requiere un solo comando: `misc::skeleton`.

## Mitigaciones

Las estrategias de mitigación contra tales ataques incluyen la monitorización de IDs de eventos específicos que indican la instalación de servicios o el uso de privilegios sensibles. Específicamente, buscar el ID de Evento del Sistema 7045 o el ID de Evento de Seguridad 4673 puede revelar actividades sospechosas. Además, ejecutar `lsass.exe` como un proceso protegido puede dificultar significativamente los esfuerzos de los atacantes, ya que esto requiere que empleen un controlador en modo kernel, aumentando la complejidad del ataque.

Aquí están los comandos de PowerShell para mejorar las medidas de seguridad:

- Para detectar la instalación de servicios sospechosos, use: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Específicamente, para detectar el controlador de Mimikatz, se puede utilizar el siguiente comando: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Para fortalecer `lsass.exe`, se recomienda habilitarlo como un proceso protegido: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La verificación después de un reinicio del sistema es crucial para asegurar que las medidas de protección se hayan aplicado con éxito. Esto se puede lograr a través de: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referencias

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
