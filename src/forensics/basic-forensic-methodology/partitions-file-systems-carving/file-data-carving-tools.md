{{#include ../../../banners/hacktricks-training.md}}

# Outils de carving

## Autopsy

L'outil le plus couramment utilisé en criminalistique pour extraire des fichiers d'images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui ingérer le fichier pour trouver des fichiers "cachés". Notez qu'Autopsy est conçu pour prendre en charge les images disque et d'autres types d'images, mais pas les fichiers simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** est un outil pour rechercher des fichiers binaires comme des images et des fichiers audio à la recherche de fichiers et de données intégrés.  
Il peut être installé avec `apt`, cependant la [source](https://github.com/ReFirmLabs/binwalk) peut être trouvée sur github.  
**Commandes utiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez simplement rechercher des fichiers spécifiques, décommentez-les. Si vous ne décommentez rien, foremost recherchera ses types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire **des fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration \(_/etc/scalpel/scalpel.conf_\) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Cet outil est inclus dans Kali, mais vous pouvez le trouver ici : [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Cet outil peut analyser une image et **extraire des pcaps** à l'intérieur, **des informations réseau (URLs, domaines, IPs, MACs, mails)** et plus **de fichiers**. Vous n'avez qu'à faire :
```text
bulk_extractor memory.img -o out_folder
```
Naviguez à travers **toutes les informations** que l'outil a rassemblées \(mots de passe ?\), **analysez** les **paquets** \(lisez [ **Analyse des Pcaps**](../pcap-inspection/index.html)\), recherchez des **domaines étranges** \(domaines liés à **des logiciels malveillants** ou **inexistants**\).

## PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Il est disponible en version GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](../../../images/image%20%28524%29.png)

# Outils de Carving de Données Spécifiques

## FindAES

Recherche des clés AES en cherchant leurs plannings de clés. Capable de trouver des clés de 128, 192 et 256 bits, telles que celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

# Outils Complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu) pour voir des images depuis le terminal.  
Vous pouvez utiliser l'outil en ligne de commande linux **pdftotext** pour transformer un pdf en texte et le lire.

{{#include ../../../banners/hacktricks-training.md}}
