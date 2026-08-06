# Outils de carving et de récupération de fichiers/données

{{#include ../../../banners/hacktricks-training.md}}

## Outils de carving et de récupération

Plus d’outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

L’outil le plus couramment utilisé en forensic pour extraire des fichiers à partir d’images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui ingérer le fichier afin de trouver les fichiers « cachés ». Notez qu’Autopsy est conçu pour prendre en charge les images disque et d’autres types d’images, mais pas les fichiers simples.

> **Mise à jour 2024-2025** – La version **4.21** (sortie en février 2025) a ajouté un **module de carving basé sur SleuthKit v4.13** entièrement remanié, qui est sensiblement plus rapide avec les images de plusieurs téraoctets et prend en charge l’extraction parallèle sur les systèmes multi-cœurs. Un petit wrapper CLI (`autopsycli ingest <case> <image>`) a également été introduit, ce qui permet de scripter le carving dans les environnements CI/CD ou les laboratoires à grande échelle.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil d’analyse de fichiers binaires permettant de trouver du contenu incorporé. Il peut être installé via `apt` et son code source est disponible sur [GitHub](https://github.com/ReFirmLabs/binwalk).

**Commandes utiles** :
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Note de sécurité** – Les versions **≤2.3.3** sont affectées par une vulnérabilité de **Path Traversal** (CVE-2022-4510). Mettez à niveau (ou isolez avec un conteneur/UID non privilégié) avant de récupérer des échantillons non fiables.<sup>[[2]](#references)</sup>

### Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez rechercher uniquement certains fichiers, décommentez-les. Si vous ne décommentez rien, foremost recherchera les types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** est un autre outil pouvant être utilisé pour rechercher et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Cet outil est inclus dans Kali, mais vous pouvez le trouver ici : <https://github.com/simsong/bulk_extractor>

Bulk Extractor peut analyser une image de preuve et extraire des **fragments pcap**, des **artefacts réseau (URL, domaines, IP, adresses MAC, e-mails)** ainsi que de nombreux autres objets **en parallèle à l'aide de plusieurs scanners**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Les scripts utiles de post-traitement (`bulk_diff`, `bulk_extractor_reader.py`) peuvent dédupliquer les artefacts entre deux images ou convertir les résultats au format JSON pour leur ingestion dans un SIEM.

### PhotoRec

Vous pouvez le trouver sur <https://www.cgsecurity.org/wiki/TestDisk_Download>

Il est fourni avec des versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que PhotoRec doit rechercher.

![Exécuter tous les scanners, effectuer un carving agressif des fichiers JPEG et générer un bodyfile - PhotoRec : il est fourni avec des versions GUI et CLI. Vous pouvez sélectionner les types de fichiers que PhotoRec doit rechercher](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imagerie des disques défaillants)

Lorsqu'un disque physique est instable, il est recommandé de **créer d'abord une image** et de n'exécuter les outils de carving que sur cette image. `ddrescue` (projet GNU) se concentre sur la copie fiable des disques endommagés tout en conservant un journal des secteurs illisibles.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
La version **1.28** (décembre 2024) a introduit **`--cluster-size`**, qui peut accélérer l’imagerie des SSD haute capacité lorsque les tailles de secteur traditionnelles ne s’alignent plus sur les blocs flash.

### Extundelete / Ext4magic (undelete EXT 3/4)

Si le système de fichiers source est basé sur Linux EXT, vous pourrez peut-être récupérer les fichiers récemment supprimés **sans effectuer de carving complet**. Les deux outils fonctionnent directement sur une image en lecture seule :
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Si le système de fichiers a été monté après la suppression, les blocs de données ont peut-être déjà été réutilisés – dans ce cas, un carving approprié (Foremost/Scalpel) reste nécessaire.

### binvis

Consultez le [code](https://code.google.com/archive/p/binvis/) et l'[outil de la page web](https://binvis.io/#/).

#### Fonctionnalités de BinVis

- **Visualisation de la structure** visuelle et active
- Plusieurs graphiques pour différents points d'intérêt
- Focalisation sur certaines portions d'un échantillon
- **Visualisation des chaînes et des ressources**, dans les exécutables PE ou ELF, par exemple
- Obtention de **patterns** pour la cryptanalyse de fichiers
- **Détection** des algorithmes de packer ou d'encodage
- **Identification** de la stéganographie par patterns
- **Diff binaire** visuel

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de black-boxing.

## Outils spécifiques de Data Carving

### FindAES

Recherche des clés AES en recherchant leurs key schedules. Capable de trouver des clés de 128, 192 et 256 bits, comme celles utilisées par TrueCrypt et BitLocker.

Téléchargement [ici](https://sourceforge.net/projects/findaes/).

### YARA-X (triage des artefacts issus du carving)

[YARA-X](https://github.com/VirusTotal/yara-x) est une réécriture de YARA en Rust publiée en 2024. Il est **10 à 30× plus rapide** que YARA classique et peut être utilisé pour classifier très rapidement des milliers d'objets issus du carving :<sup>[[3]](#references)</sup>.
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
L'accélération rend réaliste l'**étiquetage automatique** de tous les fichiers récupérés lors d'investigations à grande échelle.

## Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu)pour voir des images depuis le terminal.  \
Vous pouvez utiliser l'outil de ligne de commande Linux **pdftotext** pour transformer un PDF en texte et le lire.



## Références

- [1] [Notes de version d'Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal dans binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA est morte, vive YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
