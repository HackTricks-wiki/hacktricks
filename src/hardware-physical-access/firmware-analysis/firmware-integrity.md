# Intégrité du firmware

{{#include ../../banners/hacktricks-training.md}}

Lorsqu'une évaluation autorisée révèle une vérification faible ou inexistante de la signature du firmware, une image de firmware modifiée peut démontrer l'impact sur l'intégrité. Le workflow de laboratoire suivant ajoute un bind shell tout en conservant les étapes originales d'extraction, d'émulation et de repackaging.<sup>[[2]](#references)[[3]](#references)</sup>

1. Le firmware peut être extrait à l'aide de firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un cross compiler peut être construit à l'aide de Buildroot ou d'autres méthodes adaptées à l'environnement.
4. Le backdoor peut être compilé à l'aide du cross compiler.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé à l'aide de chroot et de QEMU.
8. Le backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être repackagé à l'aide de FMK.
11. Le firmware backdoored peut être testé en l'émulant avec firmware analysis toolkit (FAT) et en se connectant à l'adresse IP et au port du backdoor cible à l'aide de netcat.

Si un root shell a déjà été obtenu par le biais d'une analyse dynamique, d'une manipulation du bootloader ou de tests de sécurité matériels, des binaires de test précompilés tels que des implants ou des reverse shells peuvent être exécutés. Le `msfvenom` de Metasploit peut générer un payload spécifique à l'architecture pour ce workflow de validation :<sup>[[4]](#references)</sup>

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier le payload cible, l'adresse IP de l'hôte attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré vers l'appareil compromis, et il faut vérifier qu'il dispose des permissions d'exécution.
4. Metasploit peut être préparé pour gérer les requêtes entrantes en démarrant msfconsole et en configurant les paramètres conformément au payload.
5. Le reverse shell meterpreter peut être exécuté sur l'appareil compromis.

## Ponts de transport non authentifiés vers des protocoles de mise à jour privilégiés

Une erreur courante dans la conception des systèmes embarqués consiste à exposer le **même protocole de commandes interne sur plusieurs transports**, tout en n'appliquant l'authentification que sur l'un d'eux. Par exemple, l'USB peut exiger un challenge-response, tandis que le BLE transmet simplement des **écritures GATT** non authentifiées au même gestionnaire privilégié de mise à jour du firmware.<sup>[[1]](#references)</sup>

Workflow offensif typique :

1. Énumérer la base de données GATT du BLE et identifier les caractéristiques inscriptibles utilisées par l'application mobile officielle.
2. Sniffer le trafic de l'application et rechercher des **magic bytes / opcodes** correspondant au protocole filaire.
3. Rejouer les commandes privilégiées via BLE **sans appairage** et vérifier si les opérations sensibles fonctionnent toujours.
4. Si les opcodes de mise à niveau du firmware, d'écriture de configuration, de debug ou de test en usine sont accessibles, considérer le BLE comme un **port d'administration accessible par radio**.

Vérifications rapides :
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Things to verify while reversing:

- BLE require-t-il un **pairing/bonding** ou seulement une connexion simple ?
- Tous les transports sont-ils routés vers la même table de dispatch interne ?
- Les opcodes privilégiés sont-ils filtrés différemment sur USB / BLE / UART / Wi-Fi ?
- L'application mobile peut-elle déclencher à distance les handlers de mise à jour du firmware, de récupération ou de diagnostic ?

## Les containers de firmware protégés uniquement par un checksum restent des firmware contrôlés par l'attaquant

Un container de firmware protégé uniquement par un **checksum non clé** (CRC32, SHA-256, MD5, etc.) détecte la corruption, **pas l'authenticité**. Si l'attaquant peut atteindre la routine de mise à jour, il peut modifier l'image, recalculer le checksum et flasher du code arbitraire.<sup>[[1]](#references)</sup>

Signaux d'alerte pendant la RE :

- Le code de mise à jour valide uniquement un blob de checksum final tel que `CHK2`, `CRC` ou `SHA256`.
- Aucune vérification de signature ni racine de confiance de secure boot n'est présente.
- Aucun MAC / HMAC lié à l'appareil ni chiffrement authentifié n'est utilisé.
- Le recovery mode accepte le même format d'image non authentifié.

Procédure pratique de validation :

1. Extraire le container de firmware et identifier le bootloader, le firmware principal et les métadonnées d'intégrité.
2. Modifier une chaîne ou une bannière sans danger dans l'image.
3. Recalculer le checksum exactement comme l'updater l'attend.
4. Reflasher l'image via le chemin de mise à jour normal.
5. Confirmer la modification au démarrage afin de prouver le remplacement arbitraire du firmware.

Si cela fonctionne via un transport accessible à distance tel que BLE/Wi-Fi, le bug constitue effectivement un **remplacement OTA de firmware non authentifié**.

## Transformer un périphérique USB de confiance en BadUSB via le reflashage du firmware

Lorsque le périphérique cible est déjà approuvé par l'hôte via USB, un firmware malveillant n'a pas forcément besoin d'implémenter une nouvelle stack USB complète. Un pivot bien plus simple consiste souvent à **réutiliser le support HID existant**.<sup>[[1]](#references)</sup>

Pattern utile :

1. Vérifier si le périphérique s'énumère déjà comme une interface **HID Consumer Control** / média / vendor HID.
2. Localiser le **descripteur de rapport HID** existant dans le firmware.
3. Ajouter ou remplacer des entrées du descripteur afin que le périphérique annonce également une capacité de **clavier**.
4. Réutiliser les routines du firmware existantes qui envoient déjà des rapports HID au lieu d'écrire une nouvelle implémentation du transport.
5. Injecter des rapports d'appui + de relâchement de touches pour saisir des commandes sur l'hôte.

Cela transforme la compromission du firmware en **compromission de l'hôte**, car le PC fera confiance au périphérique reflasher comme à un clavier légitime.

### Checklist d'évaluation minimale

- `dmesg`, le Device Manager ou les descripteurs USB affichent-ils une interface HID existante ?
- Y a-t-il suffisamment d'espace près du descripteur de rapport ou d'une table de descripteurs relogeable ?
- Les routines existantes d'envoi de contrôle média peuvent-elles être réutilisées pour les rapports clavier ?
- L'hôte accepte-t-il automatiquement la nouvelle interface clavier après le reflashage ?

## Exécution fiable de payloads dans un firmware RTOS

Au lieu d'insérer des trampolines fragiles dans des chemins de code aléatoires, rechercher les **tâches RTOS existantes** qui sont inutilisées ou peu impactantes en fonctionnement normal.<sup>[[1]](#references)</sup>

Pourquoi cette approche est utile :

- Le scheduler démarre naturellement votre payload pendant le boot.
- Vous évitez de corrompre le flux de contrôle critique.
- Les payloads différés sont moins susceptibles de déclencher des resets du watchdog que lorsqu'ils sont exécutés dans un handler USB/réseau sensible à la latence.

Les bonnes cibles sont les tâches de diagnostic, de test usine, de télémétrie ou de service de coprocesseur qui semblent dormantes en utilisation normale.

## Itération rapide des exploits : détourner des handlers de protocole inoffensifs

Une fois le patching du firmware possible, une méthode compacte pour accélérer la RE consiste à remplacer un handler de commande inoffensif (par exemple un **opcode echo/debug**) par des primitives personnalisées de **lecture / écriture / exécution mémoire**. Cela évite un reflashage complet pour chaque expérimentation et est particulièrement utile lorsque le périphérique prend en charge le handler modifié via un transport filaire rapide.<sup>[[1]](#references)</sup>

Utiliser cette méthode pour :

- Vérifier les memory maps chargées par fragments
- Inspecter en direct l'état du heap et des tâches
- Tester de petits payloads avant de les graver dans la flash
- Récupérer en toute sécurité les pointeurs de fonction, les chaînes et les tables de descripteurs

## References

- [1] [Pwnd Blaster : Hacking votre PC à l'aide de votre haut-parleur sans jamais le toucher](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Comment utiliser `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
