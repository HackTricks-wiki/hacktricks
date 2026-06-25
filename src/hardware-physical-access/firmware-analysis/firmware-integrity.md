# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Les **firmware custom et/ou les binaires compilés peuvent être uploadés pour exploiter des failles d'intégrité ou de vérification de signature**. Les étapes suivantes peuvent être suivies pour la compilation d'un backdoor bind shell :

1. Le firmware peut être extrait à l'aide de firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un cross compiler peut être construit à l'aide de Buildroot ou d'autres méthodes adaptées à l'environnement.
4. Le backdoor peut être construit à l'aide du cross compiler.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé à l'aide de chroot et QEMU.
8. Le backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être recompilé en utilisant FMK.
11. Le firmware backdoored peut être testé en l'émulant avec firmware analysis toolkit (FAT) et en se connectant à l'IP et au port du backdoor cible à l'aide de netcat.

Si un root shell a déjà été obtenu par analyse dynamique, manipulation du bootloader ou tests de sécurité hardware, des binaires malveillants précompilés tels que des implants ou des reverse shells peuvent être exécutés. Des outils automatisés de payload/implant comme Metasploit framework et 'msfvenom' peuvent être exploités en suivant les étapes suivantes :

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier le payload cible, l'IP de l'hôte attaquant, le numéro du port d'écoute, le filetype, l'architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré vers l'appareil compromis et il faut s'assurer qu'il dispose des permissions d'exécution.
4. Metasploit peut être préparé pour gérer les requêtes entrantes en lançant msfconsole et en configurant les paramètres selon le payload.
5. Le meterpreter reverse shell peut être exécuté sur l'appareil compromis.

## Unauthenticated transport bridges to privileged update protocols

A common embedded design mistake is exposing the **same internal command protocol over several transports** but enforcing authentication on only one of them. For example, USB may require challenge-response while BLE simply forwards unauthenticated **GATT writes** into the same privileged firmware-update handler.

Typical offensive workflow:

1. Enumerate the BLE GATT database and identify writable characteristics used by the official mobile app.
2. Sniff app traffic and look for **magic bytes / opcodes** that match the wired protocol.
3. Replay privileged commands over BLE **without pairing** and verify whether sensitive operations still work.
4. If firmware upgrade, config write, debug, or factory-test opcodes are reachable, treat BLE as a **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Choses à vérifier lors du reverse :

- Est-ce que BLE nécessite un **pairing/bonding** ou juste une connexion simple ?
- Tous les transports sont-ils routés vers la même table de dispatch interne ?
- Les opcodes privilégiés sont-ils filtrés différemment sur USB / BLE / UART / Wi-Fi ?
- L’application mobile peut-elle déclencher à distance les handlers de firmware update, recovery ou diagnostic ?

## Les conteneurs de firmware basés uniquement sur un checksum restent du firmware contrôlé par l’attaquant

Un conteneur de firmware protégé uniquement par un **checksum non keyé** (CRC32, SHA-256, MD5, etc.) fournit une détection de corruption, **pas une authenticité**. Si l’attaquant peut atteindre la routine de mise à jour, il peut patcher l’image, recalculer le checksum et flasher du code arbitraire.

Signaux d’alerte pendant le RE :

- Le code de mise à jour valide seulement un blob de checksum final tel que `CHK2`, `CRC` ou `SHA256`.
- Aucune vérification de signature ni root of trust de secure-boot n’est présente.
- Aucun MAC lié à l’appareil / HMAC / chiffrement authentifié n’est utilisé.
- Le mode recovery accepte le même format d’image non authentifié.

Flux de validation pratique :

1. Extraire le conteneur de firmware et identifier le bootloader, le firmware principal et les métadonnées d’intégrité.
2. Modifier une chaîne ou une bannière inoffensive dans l’image.
3. Recalculer le checksum exactement comme l’updater l’attend.
4. Reflasher l’image via le chemin de mise à jour normal.
5. Confirmer le changement au boot pour prouver le remplacement arbitraire du firmware.

Si cela fonctionne via un transport atteignable à distance tel que BLE/Wi-Fi, le bug est en pratique un **remplacement de firmware OTA non authentifié**.

## Transformer un périphérique USB de confiance en BadUSB via le reflashing du firmware

Lorsque le périphérique cible est déjà considéré comme fiable par l’hôte via USB, un firmware malveillant n’a pas forcément besoin d’implémenter une pile USB complète. Un pivot beaucoup plus simple consiste souvent à **réutiliser le support HID existant**.

Pattern utile :

1. Vérifier si le périphérique s’énumère déjà comme une interface **HID Consumer Control** / media / vendor HID.
2. Localiser le **HID report descriptor** existant dans le firmware.
3. Ajouter ou remplacer des entrées de descripteur pour que le périphérique annonce aussi une capacité **keyboard**.
4. Réutiliser les routines de firmware existantes qui envoient déjà des rapports HID au lieu d’écrire une nouvelle implémentation de transport.
5. Injecter des rapports key press + key release pour taper des commandes sur l’hôte.

Cela transforme la compromission du firmware en **compromission de l’hôte** car le PC fera confiance au périphérique reflashe comme à un clavier légitime.

### Checklist minimale d’évaluation

- `dmesg`, Device Manager ou les descripteurs USB montrent-ils déjà une interface HID ?
- Y a-t-il de la place disponible près du report descriptor ou une table de descripteurs relocatable ?
- Les routines d’envoi de media-control existantes peuvent-elles être réutilisées pour des rapports keyboard ?
- L’hôte accepte-t-il automatiquement la nouvelle interface keyboard après le reflashing ?

## Exécution fiable d’un payload dans le firmware RTOS

Au lieu d’insérer des trampolines fragiles dans des chemins de code aléatoires, cherchez des **RTOS tasks** existantes qui sont inutilisées ou à faible impact en fonctionnement normal.

Pourquoi c’est utile :

- Le scheduler démarre naturellement votre payload pendant le boot.
- Vous évitez de corrompre le flux de contrôle critique.
- Les payloads différés ont moins de chances de déclencher des watchdog resets que s’ils s’exécutent dans un handler USB/réseau sensible à la latence.

De bonnes cibles sont les tasks de diagnostic, de factory-test, de telemetry ou de service coprocesseur qui semblent dormantes en usage normal.

## Itération rapide d’exploit : détourner des handlers de protocole bénins

Une fois le patching de firmware possible, une manière compacte d’accélérer le RE consiste à écraser un handler de commande inoffensif (par exemple un opcode **echo/debug**) avec des primitives personnalisées **memory read / write / execute**. Cela évite de reflasher complètement à chaque expérience et est particulièrement utile lorsque le périphérique supporte le handler modifié via un transport filaire rapide.

Utilisez cela pour :

- Vérifier des memory maps scatter-loaded
- Inspecter l’état heap/task en direct
- Tester de petits payloads avant de les graver en flash
- Récupérer des function pointers, des strings et des descriptor tables en toute sécurité

## Références

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
