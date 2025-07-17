# Attaques Physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération de Mot de Passe BIOS et Sécurité Système

**Réinitialiser le BIOS** peut être réalisé de plusieurs manières. La plupart des cartes mères incluent une **batterie** qui, lorsqu'elle est retirée pendant environ **30 minutes**, réinitialisera les paramètres du BIOS, y compris le mot de passe. Alternativement, un **jumper sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en connectant des broches spécifiques.

Pour les situations où les ajustements matériels ne sont pas possibles ou pratiques, des **outils logiciels** offrent une solution. Exécuter un système à partir d'un **Live CD/USB** avec des distributions comme **Kali Linux** permet d'accéder à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe BIOS.

Dans les cas où le mot de passe BIOS est inconnu, entrer incorrectement le mot de passe **trois fois** entraînera généralement un code d'erreur. Ce code peut être utilisé sur des sites comme [https://bios-pw.org](https://bios-pw.org) pour potentiellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation de **Secure Boot**. Cela peut être accompli avec la commande suivante :
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analyse de la RAM et Attaques par Cold Boot

La RAM conserve des données brièvement après la coupure de l'alimentation, généralement pendant **1 à 2 minutes**. Cette persistance peut être prolongée jusqu'à **10 minutes** en appliquant des substances froides, comme de l'azote liquide. Pendant cette période prolongée, un **memory dump** peut être créé à l'aide d'outils comme **dd.exe** et **volatility** pour analyse.

---

## Attaques par Accès Direct à la Mémoire (DMA)

**INCEPTION** est un outil conçu pour la **manipulation de la mémoire physique** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en patchant la mémoire pour accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

---

## Live CD/USB pour Accès Système

Changer des binaires système comme **_sethc.exe_** ou **_Utilman.exe_** avec une copie de **_cmd.exe_** peut fournir un invite de commande avec des privilèges système. Des outils comme **chntpw** peuvent être utilisés pour éditer le fichier **SAM** d'une installation Windows, permettant des changements de mot de passe.

**Kon-Boot** est un outil qui facilite la connexion aux systèmes Windows sans connaître le mot de passe en modifiant temporairement le noyau Windows ou UEFI. Plus d'informations peuvent être trouvées sur [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Gestion des Fonctionnalités de Sécurité de Windows

### Raccourcis de Démarrage et de Récupération

- **Supr** : Accéder aux paramètres du BIOS.
- **F8** : Entrer en mode de récupération.
- Appuyer sur **Shift** après la bannière Windows peut contourner l'autologon.

### Périphériques BAD USB

Des dispositifs comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des dispositifs **bad USB**, capables d'exécuter des charges utiles prédéfinies lorsqu'ils sont connectés à un ordinateur cible.

### Volume Shadow Copy

Des privilèges d'administrateur permettent de créer des copies de fichiers sensibles, y compris le fichier **SAM**, via PowerShell.

---

## Contournement du Chiffrement BitLocker

Le chiffrement BitLocker peut potentiellement être contourné si le **mot de passe de récupération** est trouvé dans un fichier de memory dump (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

---

## Ingénierie Sociale pour l'Ajout de Clé de Récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée par des tactiques d'ingénierie sociale, convainquant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

---

## Exploitation des Interrupteurs d'Intrusion de Châssis / de Maintenance pour Réinitialiser le BIOS

De nombreux ordinateurs portables modernes et desktops de petite taille incluent un **interrupteur d'intrusion de châssis** qui est surveillé par le Contrôleur Intégré (EC) et le firmware BIOS/UEFI. Bien que le but principal de l'interrupteur soit de déclencher une alerte lorsque l'appareil est ouvert, les fournisseurs mettent parfois en œuvre un **raccourci de récupération non documenté** qui est déclenché lorsque l'interrupteur est basculé dans un motif spécifique.

### Comment l'Attaque Fonctionne

1. L'interrupteur est câblé à un **GPIO interrupt** sur l'EC.
2. Le firmware exécuté sur l'EC suit le **timing et le nombre de pressions**.
3. Lorsqu'un motif codé en dur est reconnu, l'EC invoque une routine de *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS système**.
4. Au prochain démarrage, le BIOS charge des valeurs par défaut – **le mot de passe superviseur, les clés de Secure Boot, et toute configuration personnalisée sont effacés**.

> Une fois que Secure Boot est désactivé et que le mot de passe du firmware est supprimé, l'attaquant peut simplement démarrer n'importe quelle image OS externe et obtenir un accès illimité aux disques internes.

### Exemple du Monde Réel – Ordinateur Portable Framework 13

Le raccourci de récupération pour le Framework 13 (11e/12e/13e génération) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l'EC définit un drapeau qui instructe le BIOS d'effacer la NVRAM au prochain redémarrage. L'ensemble de la procédure prend environ 40 secondes et nécessite **rien d'autre qu'un tournevis**.

### Procédure d'Exploitation Générique

1. Allumez ou réveillez la cible afin que l'EC soit en fonctionnement.
2. Retirez le couvercle inférieur pour exposer l'interrupteur d'intrusion/de maintenance.
3. Reproduisez le motif de basculement spécifique au fournisseur (consultez la documentation, les forums ou reverse-engineer le firmware de l'EC).
4. Remontez et redémarrez – les protections du firmware devraient être désactivées.
5. Démarrez un USB live (par exemple, Kali Linux) et effectuez les opérations post-exploitation habituelles (extraction de credentials, exfiltration de données, implantation de binaires EFI malveillants, etc.).

### Détection & Atténuation

* Enregistrez les événements d'intrusion de châssis dans la console de gestion de l'OS et corrélez-les avec des réinitialisations inattendues du BIOS.
* Employez des **sceaux anti-manipulation** sur les vis/couvercles pour détecter l'ouverture.
* Gardez les appareils dans des **zones physiquement contrôlées** ; supposez que l'accès physique équivaut à une compromission totale.
* Lorsque cela est possible, désactivez la fonction de réinitialisation de l'interrupteur de maintenance du fournisseur ou exigez une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Références

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
