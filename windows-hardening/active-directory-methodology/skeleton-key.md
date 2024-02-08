# Ataque Skeleton Key

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Ataque Skeleton Key

El **ataque Skeleton Key** es una técnica sofisticada que permite a los atacantes **burlar la autenticación de Active Directory** al **inyectar una contraseña maestra** en el controlador de dominio. Esto permite al atacante **autenticarse como cualquier usuario** sin necesidad de su contraseña, otorgándoles efectivamente **acceso ilimitado** al dominio.

Puede llevarse a cabo utilizando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Para realizar este ataque, **se requieren derechos de Administrador de Dominio**, y el atacante debe apuntar a cada controlador de dominio para asegurar una brecha completa. Sin embargo, el efecto del ataque es temporal, ya que **reiniciar el controlador de dominio erradica el malware**, lo que requiere una reimplantación para un acceso sostenido.

La **ejecución del ataque** requiere un solo comando: `misc::skeleton`.

## Mitigaciones

Las estrategias de mitigación contra tales ataques incluyen monitorear eventos específicos que indican la instalación de servicios o el uso de privilegios sensibles. Específicamente, buscar el Evento de Sistema ID 7045 o el Evento de Seguridad ID 4673 puede revelar actividades sospechosas. Además, ejecutar `lsass.exe` como un proceso protegido puede obstaculizar significativamente los esfuerzos de los atacantes, ya que esto requiere que utilicen un controlador de modo kernel, aumentando la complejidad del ataque.

Aquí están los comandos de PowerShell para mejorar las medidas de seguridad:

- Para detectar la instalación de servicios sospechosos, usa: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Específicamente, para detectar el controlador de Mimikatz, se puede utilizar el siguiente comando: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Para fortalecer `lsass.exe`, se recomienda habilitarlo como un proceso protegido: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Es crucial verificar después de reiniciar el sistema que las medidas de protección se hayan aplicado con éxito. Esto se logra a través de: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referencias
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
