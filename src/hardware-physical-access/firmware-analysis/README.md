# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Ressources associées


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et facilitant la communication entre les composants hardware et le software avec lequel les utilisateurs interagissent. Il est stocké en mémoire permanente, garantissant que l'appareil peut accéder aux instructions vitales dès sa mise sous tension, ce qui conduit au lancement du système d'exploitation. Examiner et potentiellement modifier le firmware est une étape critique pour identifier des vulnérabilités de sécurité.

## **Collecte d'informations**

La **collecte d'informations** est une étape initiale cruciale pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus implique la collecte de données sur :

- L'architecture CPU et le système d'exploitation qu'il exécute
- Les spécificités du bootloader
- La disposition hardware et les datasheets
- Les métriques de la codebase et les emplacements des sources
- Les bibliothèques externes et les types de licences
- Les historiques de mise à jour et les certifications réglementaires
- Les diagrammes d'architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

À cet effet, les outils d’**open-source intelligence (OSINT)** sont précieux, tout comme l'analyse des composants logiciels open-source disponibles via des revues manuelles et automatisées. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut être exploitée pour trouver des problèmes potentiels.

## **Acquisition du firmware**

Obtenir le firmware peut se faire par diverses méthodes, chacune avec son niveau de complexité :

- **Directement** depuis la source (développeurs, fabricants)
- **Le construire** à partir des instructions fournies
- **Le télécharger** depuis les sites de support officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers firmware hébergés
- Accéder directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **updates** via des techniques man-in-the-middle
- **Extraire** depuis l'appareil via des connexions comme **UART**, **JTAG**, ou **PICit**
- **Sniffer** les requêtes de mise à jour dans les communications de l'appareil
- Identifier et utiliser des **endpoints de mise à jour hardcodés**
- **Dumper** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, quand tout échoue, en utilisant des outils hardware appropriés

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez extraire des informations le concernant pour savoir comment l'aborder. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropie** de l'image avec `binwalk -E <bin>` ; si l'entropie est faible, il est peu probable qu'elle soit chiffrée. Si l'entropie est élevée, il est probable qu'elle soit chiffrée (ou compressée d'une manière ou d'une autre).

De plus, vous pouvez utiliser ces outils pour extraire les **fichiers embarqués dans le firmware** :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Récupération du système de fichiers

Avec les outils mentionnés précédemment comme `binwalk -ev <bin>` vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l'extrait généralement dans un **dossier nommé selon le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk ne détectera pas **l'octet magique du système de fichiers dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver l'offset du système de fichiers et carve le système de fichiers compressé** depuis le binaire et **extraire manuellement** le système de fichiers selon son type en utilisant les étapes ci-dessous.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Exécutez la **dd command** suivante pour extraire le système de fichiers Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire `squashfs-root`.

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs avec NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Once the firmware is obtained, it's essential to dissect it for understanding its structure and potential vulnerabilities. This process involves utilizing various tools to analyze and extract valuable data from the firmware image.

### Initial Analysis Tools

A set of commands is provided for initial inspection of the binary file (referred to as `<bin>`). These commands help in identifying file types, extracting strings, analyzing binary data, and understanding the partition and filesystem details:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer le statut de chiffrement de l'image, on vérifie l'**entropie** avec `binwalk -E <bin>`. Une entropie faible suggère l'absence de chiffrement, tandis qu'une entropie élevée indique un chiffrement ou une compression possible.

Pour extraire les **fichiers intégrés**, des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l'inspection de fichiers sont recommandés.

### Extraction du système de fichiers

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d'après le type de système de fichiers (par ex. squashfs, ubifs). Cependant, lorsque **binwalk** n'arrive pas à reconnaître le type de système de fichiers en raison de l'absence des magic bytes, une extraction manuelle est nécessaire. Cela implique d'utiliser `binwalk` pour localiser l'offset du système de fichiers, suivie de la commande `dd` pour extraire le système de fichiers :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ensuite, selon le type de système de fichiers (p. ex., squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On prête attention aux network daemons non sécurisés, aux hardcoded credentials, aux API endpoints, aux fonctionnalités du serveur de mise à jour, au uncompiled code, aux startup scripts et aux compiled binaries pour analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** and **etc/passwd** for user credentials
- Certificats et clés SSL dans **etc/ssl**
- Fichiers de configuration et scripts pour identifier des vulnérabilités potentielles
- Binaires embarqués pour une analyse plus approfondie
- Serveurs web courants d'appareils IoT et binaires

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour l'analyse statique et dynamique

### Vérifications de sécurité sur les binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Émulation du firmware pour l'analyse dynamique

Le processus d'émulation du firmware permet une **analyse dynamique** du fonctionnement d'un appareil ou d'un programme individuel. Cette approche peut rencontrer des difficultés liées au matériel ou aux dépendances d'architecture, mais transférer le root filesystem ou des binaires spécifiques vers un appareil ayant la même architecture et endianness, comme un Raspberry Pi, ou vers une machine virtuelle préconstruite, peut faciliter les tests supplémentaires.

### Émuler des binaires individuels

Pour examiner des programmes isolés, il est crucial d'identifier l'endianness et l'architecture CPU du programme.

#### Exemple avec l'architecture MIPS

Pour émuler un binaire d'architecture MIPS, on peut utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, `qemu-mipsel` est le choix.

#### Émulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire, l'émulation étant assurée par `qemu-arm`.

### Émulation système complète

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres, facilitent l'émulation complète du firmware, automatisent le processus et aident à l'analyse dynamique.

## Analyse dynamique en pratique

À ce stade, un environnement appareil réel ou émulé est utilisé pour l'analyse. Il est essentiel de conserver un accès shell à l'OS et au système de fichiers. L'émulation peut ne pas reproduire parfaitement les interactions matérielles, nécessitant des redémarrages d'émulation occasionnels. L'analyse doit revisiter le système de fichiers, exploiter les pages web et services réseau exposés, et examiner les vulnérabilités du bootloader. Des tests d'intégrité du firmware sont cruciaux pour identifier d'éventuelles portes dérobées.

## Techniques d'analyse à l'exécution

L'analyse à l'exécution consiste à interagir avec un process ou un binaire dans son environnement d'exécution, en utilisant des outils comme gdb-multiarch, Frida et Ghidra pour poser des breakpoints et identifier des vulnérabilités via le fuzzing et d'autres techniques.

## Exploitation binaire et preuve de concept

Développer un PoC pour des vulnérabilités identifiées requiert une connaissance approfondie de l'architecture cible et de la programmation en langages bas niveau. Les protections d'exécution binaire dans les systèmes embarqués sont rares, mais lorsqu'elles existent, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

## Systèmes d'exploitation préparés pour l'analyse de firmware

Des systèmes d'exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité des firmware, équipés des outils nécessaires.

## OSs préparés pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS est une distro destinée à vous aider à effectuer des security assessment et penetration testing des appareils Internet of Things (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement pré-configuré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Système d'exploitation pour les tests de sécurité embarquée basé sur Ubuntu 18.04, préchargé avec des outils de test de sécurité du firmware.

## Attaques de downgrade du firmware & mécanismes de mise à jour non sécurisés

Même lorsqu'un fournisseur implémente des vérifications de signature cryptographique pour les images firmware, **la protection contre le version rollback (downgrade) est fréquemment omise**. Lorsque le bootloader ou recovery-loader vérifie seulement la signature avec une clé publique embarquée mais ne compare pas la *version* (ou un compteur monotone) de l'image en cours de flash, un attaquant peut légitimement installer un **firmware plus ancien et vulnérable qui porte toujours une signature valide** et réintroduire ainsi des vulnérabilités corrigées.

Flux d'attaque typique :

1. **Obtain an older signed image**
* Récupérez-la depuis le portail de téléchargement public du fournisseur, un CDN ou le site de support.
* Extrayez-la d'applications mobiles/desktop accompagnantes (p. ex. à l'intérieur d'un APK Android sous `assets/firmware/`).
* Récupérez-la depuis des dépôts tiers tels que VirusTotal, des archives Internet, des forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *unauthenticated* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la récupération/la mise à jour.
3. Après le downgrade, exploitez une vulnérabilité qui avait été corrigée dans la version plus récente (par exemple un filtre de command-injection ajouté ultérieurement).
4. Optionnellement, reflashez l'image la plus récente ou désactivez les mises à jour pour éviter la détection une fois la persistance établie.

### Exemple : Command Injection après downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement dans une commande shell sans être assaini, permettant l'injection de commandes arbitraires (ici — activation d'un accès root par clé SSH). Les versions de firmware ultérieures ont introduit un filtrage basique des caractères, mais l'absence de protection contre le downgrade rend la correction caduque.

### Extraction du firmware depuis les applications mobiles

De nombreux fournisseurs embarquent des images firmware complètes dans leurs applications mobiles compagnon afin que l'application puisse mettre à jour l'appareil via Bluetooth/Wi-Fi. Ces paquets sont généralement stockés en clair dans l'APK/APEX sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra` ou même le simple `unzip` permettent d'extraire des images signées sans toucher au matériel physique.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Liste de contrôle pour évaluer la logique de mise à jour

* Le transport/l'authentification du *update endpoint* est-il suffisamment protégé (TLS + authentication) ?
* L'appareil compare-t-il **version numbers** ou un **monotonic anti-rollback counter** avant le flashing ?
* L'image est-elle vérifiée dans une secure boot chain (par ex. signatures vérifiées par du ROM code) ?
* Le userland code effectue-t-il des vérifications supplémentaires de sanity (par ex. allowed partition map, model number) ?
* Les flux de mise à jour *partial* ou *backup* réutilisent-ils la même validation logic ?

> 💡  Si un des points ci‑dessus manque, la plateforme est probablement vulnérable à des rollback attacks.

## Firmware vulnérable pour s'entraîner

Pour s'exercer à découvrir des vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

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
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Formation et certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
