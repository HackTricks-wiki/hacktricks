# Outils de carving de fichiers/données et de récupération

{{#include ../../../banners/hacktricks-training.md}}

## Outils de carving et de récupération

Effectuez toujours le carving sur une **copie vérifiée**, jamais sur l’appareil d’origine. Consultez [Acquisition d’image et montage](../image-acquisition-and-mount.md) pour les procédures d’acquisition en lecture seule et de hachage.

Plus d’outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

L’outil le plus couramment utilisé en criminalistique pour extraire des fichiers à partir d’images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui analyser le fichier pour trouver les fichiers « cachés ». Notez qu’Autopsy est conçu pour prendre en charge les images disque et d’autres types d’images, mais pas les fichiers simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil d’analyse de fichiers binaires permettant de trouver du contenu intégré. **Binwalk v3** est une réécriture en Rust qui propose l’extraction automatique (`-e`), le carving brut d’objets connus et inconnus (`-c`), l’analyse récursive (Matryoshka) (`-M`) et des threads de travail configurables. Le projet recommande son image Docker lorsque tous les extracteurs externes sont nécessaires ; `cargo install binwalk` installe l’interface en ligne de commande Rust, mais pas ces dépendances externes.<sup>[[11]](#references)</sup>

**Commandes v3 utiles**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

La recette héritée v2 `--dd='.*'` n’est **pas** l’équivalent v3 de `-c` ; vérifiez d’abord `binwalk --version` lorsque vous suivez d’anciennes commandes de CTF ou de write-up.<sup>[[11]](#references)</sup>

⚠️  **Note de sécurité** – Les versions **2.1.2b à 2.3.3** sont affectées par une vulnérabilité de **Path Traversal** (CVE-2022-4510) ; l’avis ne répertorie aucune version corrigée sur pip. Évitez d’extraire des échantillons non fiables avec les versions concernées, ou isolez l’outil dans un conteneur/sous un UID non privilégié.<sup>[[4]](#references)</sup>

### Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous trouverez le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez rechercher des fichiers spécifiques, décommentez les lignes correspondantes. Si vous ne décommentez aucune ligne, foremost recherchera les types de fichiers configurés par défaut.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** est un autre outil qui permet de trouver et d’extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Carving fragmenté avec Scalpel3

Lorsque la récupération priorisant les métadonnées et les outils de carving contigu laissent des fichiers fragmentés incomplets, **Scalpel3** peut réassembler les formats pris en charge à l’aide de validateurs de fichiers/blocs. Son code est différent de celui de l’ancienne commande `scalpel` ci-dessus. Créez d’abord le blockmap requis avec la **même taille de bloc** que celle utilisée pour le carving ; utilisez la taille des clusters du système de fichiers indiquée par `fsstat` si elle est connue, ou déterminez une valeur défendable avant d’analyser une image de partition. Exécutez l’outil uniquement sur une copie vérifiée et placez les résultats sur un volume distinct.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Remplacez `4096` par la taille de bloc sélectionnée. `-w` conserve les candidats **PROMISING** ainsi que ceux qui ont été validés, et `-b` écrit des blockvectors pour aider à vérifier les dispositions reconstruites. Un fichier marqué PROMISING, ou doté d’une extension familière, ne prouve pas que la récupération est complète ; vérifiez le contenu avant de l’utiliser.<sup>[[13]](#references)[[14]](#references)</sup> Pour localiser les partitions supprimées ou les espaces avant le carving, consultez [Finding data outside listed partitions](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Cet outil est inclus dans Kali, mais vous pouvez le trouver ici : <https://github.com/simsong/bulk_extractor>

Bulk Extractor peut analyser une image de preuve et extraire des **fragments pcap**, des **artefacts réseau (URL, domaines, adresses IP, adresses MAC, e-mails)** et de nombreux autres objets **en parallèle à l’aide de plusieurs scanners**.

La version 2.1.1 documente une compilation avec Autotools et le paramètre `-S jpeg_carve_mode=2` pour extraire toutes les images JPEG contiguës.<sup>[[2]](#references)</sup>

```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```

Le `bulk_diff.py` fourni compare deux exécutions de bulk_extractor, tandis que `bulk_extractor_reader.py` lit les fichiers de rapports et de caractéristiques.<sup>[[3]](#references)</sup>

### PhotoRec

Vous le trouverez sur <https://www.cgsecurity.org/wiki/TestDisk_Download>

Il existe en versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que PhotoRec doit rechercher.

![Exécutez tous les scanners, récupérez agressivement les JPEG et générez un bodyfile - PhotoRec : Il existe en versions GUI et CLI. Vous pouvez sélectionner les types de fichiers que PhotoRec doit rechercher](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (métadonnées d’abord)

Avant de procéder à une récupération par signature brute, essayez une récupération prenant en compte le système de fichiers lorsque les métadonnées du volume sont encore analysables. Par défaut, `tsk_recover` exporte uniquement les fichiers non alloués ; `-a` sélectionne les fichiers alloués et `-e` exporte les deux. Pour une image de disque entier, transmettez à `-o` le **secteur de départ** de la partition indiqué par `mmls` (ne le convertissez pas en octets). Si l’entrée est déjà une image de partition, omettez `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Cette passe peut préserver les noms et chemins issus du système de fichiers, contrairement au carving d’en-tête/pied de page ; lancez ensuite Foremost, Scalpel ou PhotoRec pour les entrées dont les métadonnées sont absentes ou inutilisables.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (création d’image de disques défaillants)

Lorsqu’un disque physique est instable, il est recommandé de **créer d’abord une image disque** et de n’exécuter les outils de carving que sur cette image. `ddrescue` (projet GNU) se concentre sur la copie fiable des disques défectueux tout en conservant un journal des secteurs illisibles.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

L’option **`--cluster-size`** contrôle le nombre de secteurs copiés à la fois ; des valeurs plus faibles peuvent aider avec les disques lents.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (récupération de fichiers supprimés EXT 3/4)

Si le système de fichiers source est basé sur Linux EXT, vous pourrez peut-être récupérer les fichiers récemment supprimés **sans carving complet** ; ces outils basés sur le journal fonctionnent sur un système de fichiers démonté ou une image en lecture seule.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Note de compatibilité** – ext4magic est abandonné ; la page du projet indique que les systèmes de fichiers actuels ne sont plus compatibles avec cet outil.<sup>[[10]](#references)</sup>

> 🛈 Si le système de fichiers a été monté après la suppression, les blocs de données ont peut-être déjà été réutilisés – dans ce cas, un carving approprié (Foremost/Scalpel) reste nécessaire.

### binvis

Consultez le [code](https://code.google.com/archive/p/binvis/) et l'[outil de la page Web](https://binvis.io/#/).

#### Fonctionnalités de BinVis

- **Visualiseur de structure** visuel et interactif
- Plusieurs graphiques pour différents points d'intérêt
- Focalisation sur des portions d'un échantillon
- **Visualisation des chaînes et des ressources**, par exemple dans les exécutables PE ou ELF
- Obtention de **motifs** pour la cryptanalyse de fichiers
- **Détection** des algorithmes de packer ou d'encodage
- **Identification** de la stéganographie par ses motifs
- **Diff binaire** visuel

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de black-boxing.

## Outils spécifiques de carving de données

### FindAES

Recherche des clés AES en repérant leurs key schedules. Peut trouver des clés de 128, 192 et 256 bits, comme celles utilisées par TrueCrypt et BitLocker.

Téléchargez-le [ici](https://sourceforge.net/projects/findaes/).

### YARA-X (triage des artefacts récupérés par carving)

[YARA-X](https://github.com/VirusTotal/yara-x) est une réécriture de YARA en Rust, introduite en 2024 ; VirusTotal indique que certaines règles utilisant des expressions régulières et des boucles complexes peuvent s'exécuter beaucoup plus rapidement.<sup>[[5]](#references)</sup> Son interface en ligne de commande s'appelle `yr`, et la commande `scan` prend en charge les analyses récursives, le nombre de threads et la sortie de métadonnées.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu)pour afficher des images depuis le terminal.  \
Vous pouvez utiliser l’outil en ligne de commande Linux **pdftotext** pour convertir un PDF en texte et le lire.







## References

- [1] [Notes de version d’Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [Fichier README de bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [Fichier README des outils Python de bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Traversée de répertoires dans binwalk (CVE-2022-4510) - Base de données des avis GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA est mort, vive YARA-X - Blog de VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Commandes CLI de YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manuel de GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manuel d’ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [État du projet ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Fichier README de Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit : manuel de tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Fichier README de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Manuel de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Flux de travail de test de Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
