# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et le logiciel avec lequel les utilisateurs interagissent. Il est stocké dans une mémoire permanente, garantissant que l'appareil peut accéder à des instructions vitales dès qu'il est allumé, ce qui conduit au lancement du système d'exploitation. L'examen et la modification potentielle du firmware sont une étape cruciale pour identifier les vulnérabilités de sécurité.

## **Collecte d'informations**

**La collecte d'informations** est une étape initiale critique pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus implique la collecte de données sur :

- L'architecture CPU et le système d'exploitation qu'il utilise
- Les spécificités du bootloader
- La disposition matérielle et les fiches techniques
- Les métriques de code et les emplacements source
- Les bibliothèques externes et les types de licences
- Les historiques de mise à jour et les certifications réglementaires
- Les diagrammes architecturaux et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cette fin, les outils de **renseignement open-source (OSINT)** sont inestimables, tout comme l'analyse de tout composant logiciel open-source disponible par le biais de processus de révision manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut être exploitée pour trouver des problèmes potentiels.

## **Acquisition du firmware**

L'obtention du firmware peut être abordée par divers moyens, chacun ayant son propre niveau de complexité :

- **Directement** à partir de la source (développeurs, fabricants)
- **En le construisant** à partir des instructions fournies
- **En le téléchargeant** depuis des sites de support officiels
- En utilisant des requêtes **Google dork** pour trouver des fichiers de firmware hébergés
- En accédant directement au **stockage cloud**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- En interceptant les **mises à jour** via des techniques de l'homme du milieu
- **En extrayant** de l'appareil par des connexions comme **UART**, **JTAG** ou **PICit**
- **En reniflant** les demandes de mise à jour dans la communication de l'appareil
- En identifiant et en utilisant des **points de terminaison de mise à jour codés en dur**
- **En dumpant** depuis le bootloader ou le réseau
- **En retirant et en lisant** la puce de stockage, lorsque tout le reste échoue, en utilisant des outils matériels appropriés

## Analyser le firmware

Maintenant que vous **avez le firmware**, vous devez extraire des informations à son sujet pour savoir comment le traiter. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropie** de l'image avec `binwalk -E <bin>`, si l'entropie est faible, il est peu probable qu'elle soit chiffrée. Si l'entropie est élevée, il est probable qu'elle soit chiffrée (ou compressée d'une certaine manière).

De plus, vous pouvez utiliser ces outils pour extraire des **fichiers intégrés dans le firmware** :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Récupération du Système de Fichiers

Avec les outils précédemment commentés comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk extrait généralement cela dans un **dossier nommé selon le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction Manuelle du Système de Fichiers

Parfois, binwalk **n'aura pas le byte magique du système de fichiers dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver l'offset du système de fichiers et extraire le système de fichiers compressé** du binaire et **extraire manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.
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
Alternativement, la commande suivante pourrait également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers seront dans le répertoire "`squashfs-root`" par la suite.

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs avec NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse du Firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données précieuses de l'image du firmware.

### Outils d'Analyse Initiale

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (appelé `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire des chaînes, analyser des données binaires et comprendre les détails de la partition et du système de fichiers :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l'état de l'encryption de l'image, l'**entropie** est vérifiée avec `binwalk -E <bin>`. Une faible entropie suggère un manque d'encryption, tandis qu'une haute entropie indique une possible encryption ou compression.

Pour extraire des **fichiers intégrés**, des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l'inspection des fichiers sont recommandés.

### Extraction du Système de Fichiers

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d'après le type de système de fichiers (par exemple, squashfs, ubifs). Cependant, lorsque **binwalk** ne parvient pas à reconnaître le type de système de fichiers en raison de l'absence de bytes magiques, une extraction manuelle est nécessaire. Cela implique d'utiliser `binwalk` pour localiser l'offset du système de fichiers, suivi de la commande `dd` pour extraire le système de fichiers :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ensuite, en fonction du type de système de fichiers (par exemple, squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du Système de Fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. Une attention particulière est portée aux démons réseau non sécurisés, aux identifiants codés en dur, aux points de terminaison API, aux fonctionnalités des serveurs de mise à jour, au code non compilé, aux scripts de démarrage et aux binaires compilés pour une analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** et **etc/passwd** pour les identifiants des utilisateurs
- Certificats SSL et clés dans **etc/ssl**
- Fichiers de configuration et scripts pour d'éventuelles vulnérabilités
- Binaires intégrés pour une analyse plus approfondie
- Serveurs web et binaires courants des appareils IoT

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités au sein du système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour une analyse statique et dynamique

### Vérifications de Sécurité sur les Binaires Compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être scrutés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Émulation de Firmware pour Analyse Dynamique

Le processus d'émulation de firmware permet une **analyse dynamique** soit du fonctionnement d'un appareil, soit d'un programme individuel. Cette approche peut rencontrer des défis liés aux dépendances matérielles ou d'architecture, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil avec une architecture et un ordre d'octets correspondants, comme un Raspberry Pi, ou vers une machine virtuelle préconstruite, peut faciliter des tests supplémentaires.

### Émulation de Binaires Individuels

Pour examiner des programmes uniques, il est crucial d'identifier l'ordre d'octets et l'architecture CPU du programme.

#### Exemple avec l'Architecture MIPS

Pour émuler un binaire d'architecture MIPS, on peut utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` serait le choix.

#### Émulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire, avec l'émulateur `qemu-arm` utilisé pour l'émulation.

### Émulation de système complet

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres, facilitent l'émulation complète du firmware, automatisant le processus et aidant à l'analyse dynamique.

## Analyse dynamique en pratique

À ce stade, un environnement de dispositif réel ou émulé est utilisé pour l'analyse. Il est essentiel de maintenir un accès shell au système d'exploitation et au système de fichiers. L'émulation peut ne pas imiter parfaitement les interactions matérielles, nécessitant des redémarrages d'émulation occasionnels. L'analyse doit revisiter le système de fichiers, exploiter les pages web et services réseau exposés, et explorer les vulnérabilités du bootloader. Les tests d'intégrité du firmware sont critiques pour identifier les vulnérabilités potentielles de porte dérobée.

## Techniques d'analyse à l'exécution

L'analyse à l'exécution implique d'interagir avec un processus ou un binaire dans son environnement d'exploitation, en utilisant des outils comme gdb-multiarch, Frida, et Ghidra pour définir des points d'arrêt et identifier des vulnérabilités par le biais de fuzzing et d'autres techniques.

## Exploitation binaire et preuve de concept

Développer un PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l'architecture cible et de la programmation dans des langages de bas niveau. Les protections d'exécution binaire dans les systèmes embarqués sont rares, mais lorsqu'elles sont présentes, des techniques comme le Return Oriented Programming (ROP) peuvent être nécessaires.

## Systèmes d'exploitation préparés pour l'analyse de firmware

Des systèmes d'exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité du firmware, équipés des outils nécessaires.

## OS préparés pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution destinée à vous aider à effectuer une évaluation de sécurité et un test de pénétration des dispositifs Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires chargés.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : Système d'exploitation de test de sécurité embarqué basé sur Ubuntu 18.04 préchargé avec des outils de test de sécurité du firmware.

## Firmware vulnérable pour pratiquer

Pour pratiquer la découverte de vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

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

## Références

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Formation et Certificat

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
