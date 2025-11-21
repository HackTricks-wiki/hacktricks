# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe BIOS et sécurité du système

**Réinitialiser le BIOS** peut être réalisé de plusieurs manières. La plupart des cartes mères incluent une **pile** qui, lorsqu'elle est retirée pendant environ **30 minutes**, réinitialise les paramètres du BIOS, y compris le mot de passe. Alternativement, un **cavalier sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en connectant des broches spécifiques.

Pour les situations où des ajustements matériels ne sont pas possibles ou pratiques, des **outils logiciels** offrent une solution. Démarrer un système depuis un **Live CD/USB** avec des distributions comme **Kali Linux** donne accès à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe BIOS.

Dans les cas où le mot de passe BIOS est inconnu, le saisir incorrectement **trois fois** provoque généralement un code d'erreur. Ce code peut être utilisé sur des sites web comme [https://bios-pw.org](https://bios-pw.org) pour éventuellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation de **Secure Boot**. Cela peut être réalisé avec la commande suivante :
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analyse de la RAM et Cold Boot Attacks

La RAM conserve les données brièvement après la coupure de l'alimentation, généralement pour **1 to 2 minutes**. Cette persistance peut être étendue à **10 minutes** en appliquant des substances froides, comme de l'azote liquide. Pendant cette période prolongée, un **memory dump** peut être créé à l'aide d'outils tels que **dd.exe** et **volatility** pour analyse.

---

## Attaques Direct Memory Access (DMA)

**INCEPTION** est un outil conçu pour la **manipulation physique de la mémoire** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en patchant la mémoire pour accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

---

## Live CD/USB pour l'accès au système

Remplacer des binaires système comme **_sethc.exe_** ou **_Utilman.exe_** par une copie de **_cmd.exe_** peut fournir une invite de commandes avec des privilèges système. Des outils tels que **chntpw** peuvent être utilisés pour éditer le fichier **SAM** d'une installation Windows, permettant de modifier les mots de passe.

**Kon-Boot** est un outil qui facilite la connexion aux systèmes Windows sans connaître le mot de passe en modifiant temporairement le Windows kernel ou UEFI. Plus d'informations sur [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Gestion des fonctionnalités de sécurité Windows

### Raccourcis de démarrage et Recovery

- **Supr** : Accéder aux paramètres du BIOS.
- **F8** : Entrer en Recovery mode.
- Appuyer sur **Shift** après la bannière Windows peut contourner l'autologon.

### BAD USB Devices

Des dispositifs comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des **bad USB** devices, capables d'exécuter des payloads prédéfinis lorsqu'ils sont connectés à un ordinateur cible.

### Volume Shadow Copy

Les privilèges administrateur permettent de créer des copies de fichiers sensibles, y compris le fichier **SAM**, via **PowerShell**.

---

## Contournement du chiffrement BitLocker

Le chiffrement **BitLocker** peut potentiellement être contourné si le recovery password se trouve dans un fichier memory dump (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cet effet.

---

## Ingénierie sociale pour l'ajout d'une clé de récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée via des tactiques d'ingénierie sociale, en convainquant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

---

## Exploitation des interrupteurs Chassis Intrusion / Maintenance pour réinitialiser le BIOS aux paramètres d'usine

De nombreux laptops modernes et desktops small-form-factor intègrent un **chassis-intrusion switch** qui est surveillé par l'Embedded Controller (EC) et le firmware BIOS/UEFI. Alors que le but principal du switch est de déclencher une alerte lorsqu'un appareil est ouvert, les fournisseurs implémentent parfois un **raccourci de récupération non documenté** qui est déclenché lorsque le switch est basculé selon un schéma spécifique.

### Comment l'attaque fonctionne

1. Le switch est câblé sur une **GPIO interrupt** de l'EC.
2. Le firmware exécuté sur l'EC garde la trace du **timing et du nombre de pressions**.
3. Lorsqu'un pattern codé en dur est reconnu, l'EC invoque une routine *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS** du système.
4. Au démarrage suivant, le BIOS charge les valeurs par défaut – **le mot de passe superviseur, les clés Secure Boot et toute configuration personnalisée sont effacés**.

> Une fois Secure Boot désactivé et le mot de passe du firmware supprimé, l'attaquant peut simplement démarrer n'importe quelle image OS externe et obtenir un accès illimité aux disques internes.

### Exemple réel – Framework 13 Laptop

Le raccourci de récupération pour le Framework 13 (11th/12th/13th-gen) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l'EC définit un drapeau qui ordonne au BIOS d'effacer la NVRAM au prochain redémarrage. Toute la procédure prend ~40 s et ne nécessite **rien d'autre qu'un tournevis**.

### Generic Exploitation Procedure

1. Mettre sous tension ou effectuer un suspend-resume sur la cible pour que l'EC soit en fonctionnement.
2. Retirer la coque inférieure pour exposer l'interrupteur d'intrusion/maintenance.
3. Reproduire le motif de basculement spécifique au fabricant (consulter la documentation, les forums, ou reverse-engineer le firmware de l'EC).
4. Remonter et redémarrer – les protections du firmware devraient être désactivées.
5. Démarrer depuis un live USB (e.g. Kali Linux) et effectuer la post-exploitation habituelle (credential dumping, exfiltration de données, implantation de binaires EFI malveillants, etc.).

### Detection & Mitigation

* Enregistrer les événements d'intrusion du châssis dans la console de gestion de l'OS et les corréler avec des réinitialisations BIOS inattendues.
* Utiliser des **scellés anti-manipulation** sur les vis/couvercles pour détecter les ouvertures.
* Garder les appareils dans des **zones physiquement contrôlées** ; supposer que l'accès physique équivaut à une compromission totale.
* Lorsque disponible, désactiver la fonctionnalité “maintenance switch reset” du fournisseur ou exiger une autorisation cryptographique supplémentaire pour les réinitialisations NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Les capteurs « wave-to-exit » grand public associent un émetteur LED proche-IR à un récepteur de type télécommande TV qui ne signale un niveau logique haut qu'après avoir vu plusieurs impulsions (~4–10) du porteur correct (≈30 kHz).
- Un cache en plastique empêche l'émetteur et le récepteur de se regarder directement, donc le contrôleur suppose qu'un porteur validé provient d'une réflexion à proximité et actionne un relais qui ouvre la gâche de la porte.
- Une fois que le contrôleur estime qu'une cible est présente, il change souvent l'enveloppe de modulation sortante, mais le récepteur continue d'accepter toute rafale correspondant au porteur filtré.

### Attack Workflow
1. **Capture the emission profile** – brancher un analyseur logique sur les broches du contrôleur pour enregistrer les formes d'onde pré-détection et post-détection qui pilotent la LED IR interne.
2. **Replay only the “post-detection” waveform** – retirer/ignorer l'émetteur d'origine et piloter une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne considère que le nombre/la fréquence d'impulsions, il interprète le porteur usurpé comme une réflexion authentique et active la ligne de relais.
3. **Gate the transmission** – transmettre le porteur en rafales réglées (p.ex. dizaines de millisecondes actif, durée similaire inactif) pour délivrer le nombre minimal d'impulsions sans saturer l'AGC du récepteur ni la logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de se déclencher.

### Long-Range Reflective Injection
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et des optiques de focalisation permet de déclencher de manière fiable depuis ~6 m.
- L'attaquant n'a pas besoin d'une ligne de mire vers l'ouverture du récepteur ; viser le faisceau sur des murs intérieurs, des étagères ou des cadres de porte visibles à travers du verre permet à l'énergie réfléchie d'entrer dans le champ de vision d'environ 30° et imite un mouvement de main à courte portée.
- Comme les récepteurs s'attendent à des réflexions faibles, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces et rester au-dessus du seuil de détection.

### Weaponised Attack Torch
- Intégrer le driver à l'intérieur d'une lampe de poche commerciale masque l'outil à la vue de tous. Remplacer la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajouter un ATtiny412 (ou équivalent) pour générer les rafales ≈30 kHz, et utiliser un MOSFET pour commuter le courant de la LED.
- Un objectif zoom télescopique resserre le faisceau pour la portée/la précision, tandis qu'un moteur à vibration sous contrôle MCU fournit une confirmation haptique que la modulation est active sans émettre de lumière visible.
- Parcourir plusieurs motifs de modulation stockés (fréquences porteuses et enveloppes légèrement différentes) augmente la compatibilité entre familles de capteurs rebrandées, permettant à l'opérateur de balayer les surfaces réfléchissantes jusqu'à ce que le relais claque et que la porte se libère.

---

## Références

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)

{{#include ../banners/hacktricks-training.md}}
