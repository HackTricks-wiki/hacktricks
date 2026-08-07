# Intégrité du firmware

{{#include ../../banners/hacktricks-training.md}}

Le **custom firmware et/ou les binaires compilés peuvent être téléversés afin d'exploiter des failles d'intégrité ou de vérification de signature**. Les étapes suivantes peuvent être suivies pour compiler un backdoor bind shell :

1. Le firmware peut être extrait à l'aide de firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un cross compiler peut être construit à l'aide de Buildroot ou d'autres méthodes adaptées à l'environnement.
4. Le backdoor peut être compilé à l'aide du cross compiler.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé à l'aide de chroot et de QEMU.
8. Le backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné à l'aide de FMK.
11. Le firmware avec backdoor peut être testé en l'émulant avec firmware analysis toolkit (FAT) et en se connectant à l'IP et au port du backdoor cible à l'aide de netcat.

Si un root shell a déjà été obtenu via une analyse dynamique, une manipulation du bootloader ou des tests de sécurité matérielle, des binaires malveillants précompilés tels que des implants ou des reverse shells peuvent être exécutés. Des outils automatisés de payload/implant tels que le framework Metasploit et 'msfvenom' peuvent être utilisés en suivant les étapes suivantes :

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier le payload cible, l'adresse IP de l'hôte de l'attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré vers l'appareil compromis, en vérifiant qu'il dispose des permissions d'exécution.
4. Metasploit peut être préparé pour gérer les requêtes entrantes en démarrant msfconsole et en configurant les paramètres conformément au payload.
5. Le reverse shell meterpreter peut être exécuté sur l'appareil compromis.

## Ponts de transport non authentifiés vers des protocoles de mise à jour privilégiés

Une erreur courante de conception des systèmes embarqués consiste à exposer **le même protocole de commande interne via plusieurs transports**, tout en n'appliquant l'authentification que sur l'un d'eux. Par exemple, l'USB peut exiger un challenge-response, tandis que le BLE transfère simplement des **écritures GATT** non authentifiées vers le même gestionnaire privilégié de mise à jour du firmware.<sup>[[1]](#references)</sup>

Workflow offensif typique :

1. Énumérer la base de données BLE GATT et identifier les caractéristiques inscriptibles utilisées par l'application mobile officielle.
2. Sniffer le trafic de l'application et rechercher des **magic bytes / opcodes** correspondant au protocole filaire.
3. Rejouer les commandes privilégiées via BLE **sans appairage** et vérifier si les opérations sensibles fonctionnent toujours.
4. Si les opcodes de mise à niveau du firmware, d'écriture de configuration, de debug ou de test d'usine sont accessibles, considérer le BLE comme un **port d'administration accessible par radio**.

Vérifications rapides :
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Éléments à vérifier lors du reversing :

- Le BLE nécessite-t-il un **pairing/bonding** ou seulement une connexion simple ?
- Tous les transports sont-ils routés vers la même table de dispatch interne ?
- Les opcodes privilégiés sont-ils filtrés différemment sur USB / BLE / UART / Wi-Fi ?
- L’application mobile peut-elle déclencher à distance les handlers de mise à jour du firmware, de recovery ou de diagnostic ?

## Les conteneurs de firmware protégés uniquement par une checksum restent des firmwares contrôlés par l’attaquant

Un conteneur de firmware protégé uniquement par une **checksum non clé** (CRC32, SHA-256, MD5, etc.) fournit une détection de corruption, **pas une authentification**. Si l’attaquant peut atteindre la routine de mise à jour, il peut modifier l’image, recalculer la checksum et flasher du code arbitraire.<sup>[[1]](#references)</sup>

Signaux d’alerte lors du RE :

- Le code de mise à jour valide uniquement un blob de checksum final tel que `CHK2`, `CRC` ou `SHA256`.
- Aucune vérification de signature ni root of trust de secure boot n’est présente.
- Aucun MAC / HMAC lié à l’appareil ni chiffrement authentifié n’est utilisé.
- Le recovery mode accepte le même format d’image non authentifié.

Flux de validation pratique :

1. Extraire le conteneur de firmware et identifier le bootloader, le firmware principal et les métadonnées d’intégrité.
2. Modifier une chaîne ou une bannière sans danger dans l’image.
3. Recalculer la checksum exactement comme l’updater l’attend.
4. Reflasher l’image via le chemin de mise à jour normal.
5. Confirmer la modification au démarrage afin de prouver le remplacement arbitraire du firmware.

Si cela fonctionne via un transport accessible à distance tel que BLE/Wi-Fi, le bug constitue effectivement un **remplacement OTA non authentifié du firmware**.

## Transformer un périphérique USB de confiance en BadUSB via le reflashing du firmware

Lorsque l’appareil cible est déjà approuvé par l’hôte via USB, un firmware malveillant n’a pas forcément besoin d’implémenter une nouvelle stack USB complète. Un pivot bien plus simple consiste souvent à **réutiliser le support HID existant**.<sup>[[1]](#references)</sup>

Méthode utile :

1. Vérifier si l’appareil s’énumère déjà comme une interface **HID Consumer Control** / media / vendor HID.
2. Localiser le **descripteur de rapport HID** existant dans le firmware.
3. Ajouter ou remplacer des entrées du descripteur afin que l’appareil annonce également une capacité de **keyboard**.
4. Réutiliser les routines du firmware existantes qui envoient déjà des rapports HID au lieu d’écrire une nouvelle implémentation du transport.
5. Injecter des rapports de pression + relâchement de touches pour saisir des commandes sur l’hôte.

Cela transforme la compromission du firmware en **compromission de l’hôte**, car le PC fera confiance au périphérique reflashé comme à un clavier légitime.

### Checklist d’évaluation minimale

- `dmesg`, le Device Manager ou les descripteurs USB affichent-ils une interface HID existante ?
- Y a-t-il de l’espace disponible près du descripteur de rapport ou d’une table de descripteurs relogeable ?
- Les routines existantes d’envoi de commandes media peuvent-elles être réutilisées pour les rapports clavier ?
- L’hôte accepte-t-il automatiquement la nouvelle interface clavier après le reflashing ?

## Exécution fiable d’un payload dans un firmware RTOS

Au lieu d’insérer des trampolines fragiles dans des chemins de code aléatoires, rechercher des **tâches RTOS existantes** qui sont inutilisées ou peu impactantes en fonctionnement normal.<sup>[[1]](#references)</sup>

Pourquoi cette méthode est utile :

- Le scheduler démarre naturellement votre payload pendant le boot.
- Vous évitez de corrompre le flux de contrôle critique.
- Les payloads différés sont moins susceptibles de déclencher des resets du watchdog que lorsqu’ils sont exécutés dans un handler USB/réseau sensible à la latence.

Les bonnes cibles sont les tâches de diagnostic, de test en usine, de télémétrie ou de service de coprocesseur qui semblent dormantes en utilisation normale.

## Itération rapide des exploits : réutiliser des handlers de protocole inoffensifs

Une fois le patching du firmware possible, une méthode compacte pour accélérer le RE consiste à écraser un handler de commande inoffensif (par exemple un **opcode echo/debug**) avec des primitives personnalisées de **lecture / écriture / exécution mémoire**. Cela évite un reflashing complet à chaque expérimentation et s’avère particulièrement utile lorsque l’appareil prend en charge le handler modifié via un transport filaire rapide.<sup>[[1]](#references)</sup>

Utiliser cette méthode pour :

- Vérifier les memory maps chargées par scatter
- Inspecter en direct l’état du heap et des tâches
- Tester de petits payloads avant de les graver dans la flash
- Récupérer en toute sécurité les pointeurs de fonction, les chaînes et les tables de descripteurs

## Références

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
