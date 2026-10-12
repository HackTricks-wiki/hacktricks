# Techniques anti-forensiques

{{#include ../../banners/hacktricks-training.md}}

## Horodatages

Un attaquant peut vouloir **modifier les horodatages des fichiers** pour éviter d’être détecté.\
Il est possible de trouver les horodatages dans la MFT, dans les attributs `$STANDARD_INFORMATION` \_\_ et \_\_ `$FILE_NAME`.

Les deux attributs comportent 4 horodatages : **modification**, **accès**, **création** et **modification du registre MFT** (MACE ou MACB).

**L’Explorateur Windows** et d’autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

### TimeStomp - Outil anti-forensique

Cet outil **modifie** les informations d’horodatage dans **`$STANDARD_INFORMATION`**, **mais pas** celles de **`$FILE_NAME`**. Il est donc possible d’**identifier** une **activité** **suspecte**.

### Usnjrnl

Le **journal USN** (Update Sequence Number Journal) est une fonctionnalité de NTFS (système de fichiers Windows NT) qui suit les modifications apportées au volume. L’outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d’examiner ces modifications.

![TimeStomp - Outil anti-forensique - Usnjrnl : le journal USN (Update Sequence Number Journal) est une fonctionnalité de NTFS (système de fichiers Windows NT) qui suit les modifications apportées au volume. L...](<../../images/image (801).png>)

L’image précédente montre la **sortie** de l’**outil**, où l’on peut constater que des **modifications ont été effectuées** sur le fichier.

### $LogFile

**Toutes les modifications des métadonnées d’un système de fichiers sont consignées** selon un processus appelé [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées consignées sont conservées dans un fichier nommé `**$LogFile**`, situé dans le répertoire racine d’un système de fichiers NTFS. Des outils comme [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent servir à analyser ce fichier et à identifier les modifications.

![Usnjrnl - $LogFile : toutes les modifications des métadonnées d’un système de fichiers sont consignées selon un processus appelé write-ahead logging. Les métadonnées consignées sont conservées dans un fichier nommé $LogFile , situé dans le répertoire racine...](<../../images/image (137).png>)

Là encore, la sortie de l’outil permet de voir que **des modifications ont été effectuées**.

Avec le même outil, il est possible d’identifier **à quelle date et heure les horodatages ont été modifiés** :

![Usnjrnl - $LogFile : avec le même outil, il est possible d’identifier à quelle date et heure les horodatages ont été modifiés](<../../images/image (1089).png>)

- CTIME : heure de création du fichier
- ATIME : heure de modification du fichier
- MTIME : modification du registre MFT du fichier
- RTIME : heure d’accès au fichier

### Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre façon d’identifier les fichiers modifiés de manière suspecte consiste à comparer les heures des deux attributs pour repérer les **écarts**.

### Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Il est donc très suspect de trouver des fichiers dont les horodatages ressemblent à 2010-10-10 10:10:**00.000:0000**.

### SetMace - Outil anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, à partir de Windows Vista, un OS en cours d’exécution est nécessaire pour modifier ces informations.

## Masquage de données

NFTS utilise des clusters et une taille minimale d’information. Cela signifie que si un fichier occupe un cluster et demi, **la moitié restante ne sera jamais utilisée** tant que le fichier n’est pas supprimé. Il est donc possible de **masquer des données dans cet espace inutilisé**.

Des outils comme slacker permettent de masquer des données dans cet espace « caché ». Cependant, l’analyse de `$logfile` et `$usnjrnl` peut révéler que des données ont été ajoutées :

![SetMace - Outil anti-forensique - Masquage de données : des outils comme slacker permettent de masquer des données dans cet espace « caché ». Cependant, l’analyse de $logfile et $usnjrnl peut révéler que...](<../../images/image (1060).png>)

Il est alors possible de récupérer l’espace inutilisé à l’aide d’outils comme FTK Imager. Notez que ce type d’outil peut enregistrer le contenu de manière obfusquée, voire chiffrée.

## UsbKill

Cet outil **éteint l’ordinateur si une modification des ports USB** est détectée.\
Pour le découvrir, on peut inspecter les processus en cours d’exécution et **examiner chaque script Python actif**.

## Distributions Linux en mode live

Ces distributions sont **exécutées dans la mémoire RAM**. Le seul moyen de les détecter est **si le système de fichiers NTFS est monté avec des autorisations d’écriture**. S’il est monté uniquement avec des autorisations de lecture, il sera impossible de détecter l’intrusion.

## Suppression sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Auto-suppression différée sous Windows

Une image Windows en cours d’exécution peut être verrouillée tant que son processus est actif. Un processus peut déléguer la suppression à un processus enfant `cmd.exe`, utiliser `choice` comme temporisateur, puis se terminer avant que le shell n’exécute `del`. Le délai permet au processus d’origine de libérer son handle d’image ; il faut mettre le chemin complet entre guillemets s’il contient des espaces.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Lorsque cette chaîne est fournie directement comme argument à `cmd.exe` plutôt que saisie depuis une autre invite `cmd` interactive, utilisez `&` au lieu de `^&` et `>nul` au lieu de `^>nul`. Cela supprime l’entrée de répertoire ; ce n’est **pas un effacement sécurisé** et cela ne supprime pas les traces d’exécution, de tâches, de journal du système de fichiers ni les autres traces forensiques. Recherchez les processus enfants `cmd.exe` de courte durée dont la ligne de commande combine `choice /T`, `Del` et le chemin de l’image du processus parent.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configuration de Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows afin de compliquer considérablement l’investigation forensique.

### Désactiver les horodatages - UserAssist

Cette clé de registre conserve les dates et les heures auxquelles chaque exécutable a été lancé par l’utilisateur.

La désactivation de UserAssist nécessite deux étapes :

1. Définissez à zéro les deux clés de registre `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` afin d’indiquer que nous voulons désactiver UserAssist.
2. Effacez les sous-arborescences du registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Désactiver les horodatages - Prefetch

Cette fonctionnalité enregistre des informations sur les applications exécutées afin d’améliorer les performances de Windows. Ces informations peuvent toutefois aussi être utiles aux pratiques forensiques.

- Exécutez `regedit`
- Sélectionnez le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Faites un clic droit sur `EnablePrefetcher` et `EnableSuperfetch`
- Sélectionnez Modifier pour chacun afin de remplacer la valeur 1 (ou 3) par 0
- Redémarrez

### Désactiver les horodatages - Heure du dernier accès

Lorsqu’un dossier est ouvert depuis un volume NTFS sur un serveur Windows NT, le système met à jour un champ d’horodatage de chaque dossier répertorié, appelé heure du dernier accès. Sur un volume NTFS très utilisé, cela peut affecter les performances.

1. Ouvrez l’Éditeur du Registre (Regedit.exe).
2. Accédez à `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Recherchez `NtfsDisableLastAccessUpdate`. Si cette entrée n’existe pas, ajoutez cette valeur DWORD et définissez-la sur 1 pour désactiver le processus.
4. Fermez l’Éditeur du Registre et redémarrez le serveur.

### Supprimer l’historique USB

Toutes les **entrées de périphériques USB** sont stockées dans le Registre Windows, sous la clé de registre **USBSTOR**, qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB à votre PC ou ordinateur portable. Vous trouverez cette clé ici H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **La supprimer** effacera l’historique USB.\
Vous pouvez également utiliser l’outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vérifier que vous les avez supprimées (et les supprimer).

Un autre fichier qui enregistre des informations sur les périphériques USB est `setupapi.dev.log`, situé dans `C:\Windows\INF`. Il faut également le supprimer.

### Désactiver les clichés instantanés

**Listez** les clichés instantanés avec `vssadmin list shadowstorage`\
**Supprimez-les** en exécutant `vssadmin delete shadow`

Vous pouvez aussi les supprimer via l’interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les clichés instantanés [étapes indiquées ici](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) :

1. Ouvrez le programme Services en saisissant « services » dans la zone de recherche de texte après avoir cliqué sur le bouton Démarrer de Windows.
2. Dans la liste, recherchez « Volume Shadow Copy », sélectionnez-le, puis accédez à Propriétés en faisant un clic droit.
3. Choisissez Désactivé dans le menu déroulant « Type de démarrage », puis confirmez la modification en cliquant sur Appliquer et sur OK.

Il est également possible de modifier dans le registre la configuration des fichiers qui seront copiés dans le cliché instantané : `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Écraser les fichiers supprimés

- Vous pouvez utiliser un **outil Windows** : `cipher /w:C`. Cela indique à cipher de supprimer toutes les données de l’espace disque disponible et inutilisé du lecteur C.
- Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

### Supprimer les journaux d’événements Windows

- Windows + R --> eventvwr.msc --> Développez « Journaux Windows » --> Faites un clic droit sur chaque catégorie et sélectionnez « Effacer le journal »
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Désactiver les journaux d’événements Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dans la section Services, désactivez le service « Windows Event Log »
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Désactiver $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Falsification avancée des journaux et des traces (2023-2025)

### Journalisation PowerShell ScriptBlock/Module

Les versions récentes de Windows 10/11 et Windows Server conservent de **nombreux artefacts forensiques PowerShell** dans
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

Les défenseurs devraient surveiller les modifications de ces clés de registre et la suppression en grand volume d’événements PowerShell.

### Patch ETW (Event Tracing for Windows)

Les produits de sécurité des endpoints s’appuient fortement sur ETW. Une méthode d’évasion répandue en 2024 consiste à patcher en mémoire `ntdll!EtwEventWrite`/`EtwEventWriteFull` afin que chaque appel ETW renvoie `STATUS_SUCCESS` sans émettre l’événement :<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Les PoCs publics (p. ex. `EtwTiSwallow`) implémentent la même primitive en PowerShell ou en C++.  
Comme le patch est **local au processus**, les EDR exécutés dans d’autres processus peuvent ne pas le détecter.<sup>[[5]](#references)</sup>
Détection : comparer `ntdll` en mémoire avec celui sur le disque, ou installer un hook avant le passage en mode utilisateur.

### Résurgence des Alternate Data Streams (ADS)

Des campagnes de malware en 2023 (p. ex. les loaders **FIN12**) ont été observées en train de déposer des binaires de seconde étape dans des ADS afin d’échapper aux scanners traditionnels :

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Énumérez les flux avec `dir /R`, `Get-Item -Stream *` ou Sysinternals `streams64.exe`.
Copier le fichier hôte sur FAT/exFAT ou via SMB supprimera le flux caché et peut permettre
aux enquêteurs de récupérer la charge utile.

### BYOVD & « AuKill » (2023)

Bring-Your-Own-Vulnerable-Driver est désormais couramment utilisé à des fins d’**anti-forensics** lors d’intrusions par ransomware.  
L’outil open source **AuKill** charge un pilote signé mais vulnérable (`procexp152.sys`) pour suspendre ou arrêter les capteurs EDR et forensic **avant le chiffrement et la destruction des journaux** :<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Le pilote est ensuite supprimé, ne laissant que des traces minimales.<sup>[[1]](#references)</sup>  
Mesures d’atténuation : activer la liste de blocage des pilotes vulnérables de Microsoft (HVCI/SAC) et déclencher une alerte lors de la création d’un service kernel depuis un chemin accessible en écriture par l’utilisateur.

---

## Anti-forensique Linux : auto-correction et C2 cloud (2023–2025)

### Auto-correction des services compromis pour réduire la détection (Linux)
Les adversaires « corrigent eux-mêmes » de plus en plus un service juste après l’avoir exploité, à la fois pour empêcher une nouvelle exploitation et pour neutraliser les détections fondées sur les vulnérabilités. L’idée consiste à remplacer les composants vulnérables par les derniers binaires/JAR légitimes en amont, afin que les scanners signalent l’hôte comme corrigé, tandis que la persistance et le C2 restent en place.<sup>[[3]](#references)</sup>

Exemple : RCE OpenWire d’Apache ActiveMQ (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Après l’exploitation, les attaquants ont récupéré des JAR légitimes depuis Maven Central (repo1.maven.org), supprimé les JAR vulnérables de l’installation d’ActiveMQ, puis redémarré le broker.
- Cela a neutralisé la RCE initiale tout en conservant d’autres points d’appui (cron, modifications de la configuration SSH, implants C2 distincts).

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

Conseils d’investigation forensique et de threat hunting
- Examinez les répertoires de services à la recherche de remplacements non planifiés de binaires/JAR :
  - Debian/Ubuntu : `dpkg -V activemq` et comparez les hashes/chemins des fichiers avec ceux des miroirs du dépôt.
  - RHEL/CentOS : `rpm -Va 'activemq*'`
  - Recherchez les versions de JAR présentes sur le disque qui ne sont pas gérées par le gestionnaire de paquets, ou les liens symboliques modifiés hors processus.
- Chronologie : `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` pour corréler ctime/mtime avec la période de compromission.
- Historique du shell/télémétrie des processus : recherchez des traces de `curl`/`wget` vers `repo1.maven.org` ou d’autres CDN d’artefacts juste après l’exploitation initiale.
- Gestion des changements : vérifiez qui a appliqué le « patch » et pourquoi, et pas seulement qu’une version corrigée est présente.

### C2 via un service cloud avec des tokens bearer et des stagers anti-analyse
Les tradecraft observés combinaient plusieurs voies C2 persistantes et un empaquetage anti-analyse :<sup>[[3]](#references)</sup>
- Chargeurs ELF PyInstaller protégés par mot de passe pour compliquer le sandboxing et l’analyse statique (par exemple, PYZ chiffré, extraction temporaire sous `/_MEI*`).
  - Indicateurs : résultats de `strings` tels que `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefacts à l’exécution : extraction vers `/tmp/_MEI*` ou des chemins personnalisés `--runtime-tmpdir`.
- C2 adossé à Dropbox utilisant des tokens OAuth Bearer codés en dur
  - Indicateurs réseau : `api.dropboxapi.com` / `content.dropboxapi.com` avec `Authorization: Bearer <token>`.
  - Recherchez dans les données proxy/NetFlow/Zeek/Suricata les connexions HTTPS sortantes vers les domaines Dropbox depuis des charges de travail serveur qui ne synchronisent normalement pas de fichiers.
- C2 parallèle/de secours via tunneling (par exemple, Cloudflare Tunnel `cloudflared`), pour conserver le contrôle si un canal est bloqué.
  - IOC sur l’hôte : processus/unités `cloudflared`, configuration dans `~/.cloudflared/*.json`, connexions sortantes sur le port 443 vers les nœuds edge de Cloudflare.

### Persistance et « rollback du hardening » pour maintenir l’accès (exemples Linux)
Les attaquants associent fréquemment l’auto-patching à des mécanismes d’accès persistants :<sup>[[3]](#references)</sup>
- Cron/Anacron : modifications du stub `0anacron` dans chaque répertoire `/etc/cron.*/` pour exécution périodique.
  - Recherchez :
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Annulation du durcissement de la configuration SSH : activation des connexions root et modification des shells par défaut des comptes à faibles privilèges.
  - Rechercher l’activation des connexions root :
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Rechercher des shells interactifs suspects sur les comptes système (p. ex., `games`) :
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefacts beacon aléatoires au nom court (8 caractères alphabétiques), déposés sur le disque et communiquant également avec un C2 cloud :
  - Rechercher :
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Les défenseurs devraient corréler ces artefacts avec l’exposition externe et les événements de mise à jour des services afin de découvrir les mécanismes d’auto-remédiation anti-forensique utilisés pour dissimuler l’exploitation initiale.

## References

- [1] [Sophos X-Ops – AuKill : un pilote vulnérable militarisé pour désactiver l’EDR (mars 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite pour la furtivité : détection et chasse (juin 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching pour la persistance : comment le malware Linux DripDropper se déplace dans le cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Dissimuler votre .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Découverte d’une variante de SectopRAT intégrée à un logiciel légitime](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – commande choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – commande del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
