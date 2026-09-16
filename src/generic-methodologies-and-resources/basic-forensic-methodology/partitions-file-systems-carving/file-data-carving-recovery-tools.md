# Outils de carving et de récupération de fichiers/données

{{#include ../../../banners/hacktricks-training.md}}

## Outils de carving et de récupération

Effectuez toujours le carving sur une **copie vérifiée**, jamais sur le périphérique d’origine. Consultez [Image Acquisition & Mount](../image-acquisition-and-mount.md) pour les workflows d’acquisition en lecture seule et de hachage.

Plus d’outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

L’outil le plus couramment utilisé en forensics pour extraire des fichiers à partir d’images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui ingérer le fichier afin de trouver les fichiers « cachés ». Notez qu’Autopsy est conçu pour prendre en charge les images disque et d’autres types d’images, mais pas les fichiers simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil d’analyse des fichiers binaires permettant de trouver du contenu intégré. **Binwalk v3** est une réécriture en Rust avec extraction automatique (`-e`), carving brut d’objets connus et inconnus (`-c`), scan récursif/Matryoshka (`-M`) et threads workers configurables. Le projet recommande son build Docker lorsque tous les extractors externes sont requis ; `cargo install binwalk` installe la CLI Rust, mais pas ces dépendances externes.<sup>[[11]](#references)</sup>

**Commandes v3 utiles**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
La recette legacy v2 `--dd='.*'` n'est **pas** l'équivalent v3 de `-c` ; vérifiez d'abord `binwalk --version` lorsque vous suivez d'anciennes commandes de CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Note de sécurité** – Les versions **2.1.2b à 2.3.3** sont affectées par une vulnérabilité de **Path Traversal** (CVE-2022-4510) ; l'advisory ne liste aucune version pip corrigée. Évitez d'extraire des échantillons non fiables avec les versions affectées, ou isolez l'outil avec un conteneur/un UID non privilégié.<sup>[[4]](#references)</sup>

### Foremost

Un autre outil courant pour rechercher des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez uniquement rechercher certains fichiers, décommentez-les. Si vous ne décommentez rien, foremost recherchera les types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour rechercher et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Cet outil est inclus dans kali, mais vous pouvez le trouver ici : <https://github.com/simsong/bulk_extractor>

Bulk Extractor peut analyser une image disque et extraire des **fragments pcap**, des **artefacts réseau (URL, domaines, adresses IP, adresses MAC, e-mails)** ainsi que de nombreux autres objets **en parallèle à l’aide de plusieurs scanners**.

La version v2.1.1 documente une compilation Autotools et le paramètre `-S jpeg_carve_mode=2` pour extraire tous les fichiers JPEG contigus.<sup>[[2]](#references)</sup>
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
Le fichier `bulk_diff.py` fourni compare deux exécutions de bulk_extractor, tandis que `bulk_extractor_reader.py` lit le rapport et les fichiers de fonctionnalités.<sup>[[3]](#references)</sup>

### PhotoRec

Vous pouvez le trouver sur <https://www.cgsecurity.org/wiki/TestDisk_Download>

Il est fourni avec des versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que PhotoRec doit rechercher.

![Exécuter chaque scanner, récupérer agressivement les fichiers JPEG et générer un bodyfile - PhotoRec : il est fourni avec des versions GUI et CLI. Vous pouvez sélectionner les types de fichiers que PhotoRec doit rechercher](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Avant la récupération par signatures brutes, essayez une récupération tenant compte du système de fichiers lorsque les métadonnées du volume sont encore analysables. Par défaut, `tsk_recover` exporte uniquement les fichiers non alloués ; `-a` sélectionne les fichiers alloués et `-e` exporte les deux. Pour une image disque complète, transmettez à `-o` le **secteur de début** de la partition obtenu avec `mmls` (ne le convertissez pas en octets). Si l’entrée est déjà une image de partition, omettez `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Cette passe peut préserver les noms et chemins dérivés du système de fichiers, ce que le carving basé sur les en-têtes et pieds de page ne permet pas ; exécutez ensuite Foremost, Scalpel ou PhotoRec pour les entrées dont les métadonnées sont absentes ou inutilisables.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (imagerie de disques défaillants)

Lorsqu’un disque physique est instable, il est recommandé de **créer d’abord une image** et de n’exécuter les outils de carving que sur cette image. `ddrescue` (projet GNU) se concentre sur la copie fiable des disques endommagés tout en conservant un journal des secteurs illisibles.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
L’option **`--cluster-size`** contrôle le nombre de secteurs copiés à la fois ; des valeurs plus faibles peuvent être utiles avec les disques lents.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (undelete EXT 3/4)

Si le système de fichiers source est basé sur Linux EXT, vous pourrez peut-être récupérer les fichiers récemment supprimés **sans effectuer un carving complet** ; ces outils basés sur le journal fonctionnent sur un système de fichiers démonté ou une image en lecture seule.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Note de compatibilité** – ext4magic est abandonné ; la page de son projet avertit que les systèmes de fichiers actuels ne sont plus compatibles avec lui.<sup>[[10]](#references)</sup>

> 🛈 Si le système de fichiers a été monté après la suppression, les blocs de données ont peut-être déjà été réutilisés – dans ce cas, un carving approprié (Foremost/Scalpel) reste nécessaire.

### binvis

Consultez le [code](https://code.google.com/archive/p/binvis/) et l’[outil de la page web](https://binvis.io/#/).

#### Fonctionnalités de BinVis

- **Visualisation de la structure** active
- Plusieurs graphiques pour différents points d’intérêt
- Focalisation sur certaines portions d’un échantillon
- **Visualisation des strings et des ressources**, par exemple dans les exécutables PE ou ELF
- Obtention de **patterns** pour la cryptanalyse de fichiers
- **Détection** des algorithmes de packer ou d’encodage
- **Identification** de la stéganographie par patterns
- **Diff binaire** visuel

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de black-boxing.

## Outils spécifiques de Data Carving

### FindAES

Recherche des clés AES en recherchant leurs key schedules. Capable de trouver des clés de 128, 192 et 256 bits, telles que celles utilisées par TrueCrypt et BitLocker.

Téléchargez-le [ici](https://sourceforge.net/projects/findaes/).

### YARA-X (triage des artefacts issus du carving)

[YARA-X](https://github.com/VirusTotal/yara-x) est une réécriture de YARA en Rust introduite en 2024 ; VirusTotal indique que certaines règles d’expressions régulières et de boucles complexes peuvent s’exécuter beaucoup plus rapidement.<sup>[[5]](#references)</sup> Son CLI s’appelle `yr`, et la commande `scan` prend en charge les scans récursifs, le nombre de threads et la sortie des métadonnées.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu)pour voir des images depuis le terminal.  \
Vous pouvez utiliser l'outil en ligne de commande Linux **pdftotext** pour transformer un fichier PDF en texte et le lire.





## References

- [1] [Notes de version d'Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README de bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README des outils Python de bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal dans binwalk (CVE-2022-4510) - Base de données des avis GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA est mort, vive YARA-X - Blog de VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Commandes CLI de YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manuel de GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manuel d'ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [État du projet ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README de Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit : manuel de tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
