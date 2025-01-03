# Outils de Carving & de Récupération de Fichiers/Données

{{#include ../../../banners/hacktricks-training.md}}

## Outils de Carving & de Récupération

Plus d'outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

L'outil le plus couramment utilisé en criminalistique pour extraire des fichiers d'images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui ingérer le fichier pour trouver des fichiers "cachés". Notez qu'Autopsy est conçu pour prendre en charge les images disque et d'autres types d'images, mais pas les fichiers simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil pour analyser des fichiers binaires afin de trouver du contenu intégré. Il est installable via `apt` et sa source est sur [GitHub](https://github.com/ReFirmLabs/binwalk).

**Commandes utiles** :
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez simplement rechercher des fichiers spécifiques, décommentez-les. Si vous ne décommentez rien, foremost recherchera ses types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire **des fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Cet outil est inclus dans Kali mais vous pouvez le trouver ici : [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Cet outil peut analyser une image et **extraire des pcaps** à l'intérieur, **des informations réseau (URLs, domaines, IPs, MACs, mails)** et plus **de fichiers**. Vous n'avez qu'à faire :
```
bulk_extractor memory.img -o out_folder
```
Naviguez à travers **toutes les informations** que l'outil a rassemblées (mots de passe ?), **analysez** les **paquets** (lisez[ **Analyse des Pcaps**](../pcap-inspection/)), recherchez des **domaines étranges** (domaines liés à **malware** ou **inexistants**).

### PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Il est disponible en versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](<../../../images/image (242).png>)

### binvis

Vérifiez le [code](https://code.google.com/archive/p/binvis/) et la [page web de l'outil](https://binvis.io/#/).

#### Fonctionnalités de BinVis

- Visualiseur de **structure** visuel et actif
- Plusieurs graphiques pour différents points de focalisation
- Focalisation sur des portions d'un échantillon
- **Voir les chaînes et ressources**, dans des exécutables PE ou ELF par exemple
- Obtenir des **modèles** pour la cryptanalyse sur des fichiers
- **Repérer** des algorithmes de packer ou d'encodeur
- **Identifier** la stéganographie par des motifs
- **Différenciation** binaire visuelle

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de black-boxing.

## Outils de Carving de Données Spécifiques

### FindAES

Recherche des clés AES en cherchant leurs plannings de clés. Capable de trouver des clés de 128, 192 et 256 bits, telles que celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

## Outils Complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu) pour voir des images depuis le terminal.\
Vous pouvez utiliser l'outil en ligne de commande linux **pdftotext** pour transformer un pdf en texte et le lire.

{{#include ../../../banners/hacktricks-training.md}}
