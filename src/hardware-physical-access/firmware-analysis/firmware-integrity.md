# Intégrité du firmware

{{#include ../../banners/hacktricks-training.md}}

Lorsqu’une évaluation autorisée révèle une vérification faible ou absente de la signature du firmware, une image de firmware modifiée peut démontrer l’impact sur l’intégrité. Le workflow de laboratoire suivant ajoute un bind shell tout en conservant les étapes d’extraction, d’émulation et de reconditionnement d’origine.<sup>[[2]](#references)[[3]](#references)</sup>

1. Le firmware peut être extrait à l’aide de firmware-mod-kit (FMK).
2. L’architecture et l’endianness du firmware cible doivent être identifiées.
3. Un compilateur croisé peut être créé avec Buildroot ou d’autres méthodes adaptées à l’environnement.
4. Le backdoor peut être compilé avec le compilateur croisé.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé avec chroot et QEMU.
8. Le backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné à l’aide de FMK.
11. Le firmware contenant le backdoor peut être testé en l’émulant avec firmware analysis toolkit (FAT), puis en se connectant à l’adresse IP et au port du backdoor cible avec netcat.

Si un shell root a déjà été obtenu par analyse dynamique, manipulation du bootloader ou tests de sécurité matérielle, des binaires de test précompilés, tels que des implants ou des reverse shells, peuvent être exécutés. `msfvenom` de Metasploit peut générer un payload spécifique à l’architecture pour ce workflow de validation :<sup>[[4]](#references)</sup>

1. L’architecture et l’endianness du firmware cible doivent être identifiées.
2. Msfvenom peut servir à spécifier le payload cible, l’adresse IP de l’hôte attaquant, le numéro de port d’écoute, le type de fichier, l’architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré sur l’appareil compromis, puis ses permissions d’exécution vérifiées.
4. Metasploit peut être configuré pour gérer les requêtes entrantes en démarrant msfconsole et en réglant les paramètres conformément au payload.
5. Le reverse shell meterpreter peut être exécuté sur l’appareil compromis.

## Ponts de transport non authentifiés vers des protocoles de mise à jour privilégiés

Une erreur de conception courante dans les systèmes embarqués consiste à exposer le **même protocole de commande interne sur plusieurs transports**, tout en n’imposant l’authentification que sur un seul d’entre eux. Par exemple, l’USB peut exiger une authentification challenge-response, tandis que BLE transmet simplement des **écritures GATT** non authentifiées au même gestionnaire privilégié de mise à jour du firmware.<sup>[[1]](#references)</sup>

Workflow offensif typique :

1. Énumérer la base de données BLE GATT et identifier les caractéristiques inscriptibles utilisées par l’application mobile officielle.
2. Intercepter le trafic de l’application et rechercher des **octets magiques / opcodes** correspondant au protocole filaire.
3. Rejouer les commandes privilégiées via BLE **sans appairage** et vérifier si les opérations sensibles fonctionnent toujours.
4. Si des opcodes de mise à niveau du firmware, d’écriture de configuration, de débogage ou de test en usine sont accessibles, considérer BLE comme un **port d’administration accessible par radio**.

Vérifications rapides :

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Choses à vérifier lors du reverse engineering :

- BLE nécessite-t-il un **pairing/bonding** ou une simple connexion ?
- Tous les transports sont-ils acheminés vers la même table de dispatch interne ?
- Les opcodes privilégiés sont-ils filtrés différemment sur USB / BLE / UART / Wi-Fi ?
- L’application mobile peut-elle déclencher à distance la mise à jour du firmware, la récupération ou les gestionnaires de diagnostic ?

## Les conteneurs de firmware protégés uniquement par un checksum restent du firmware contrôlable par un attaquant

Un conteneur de firmware protégé uniquement par un **checksum non secret** (CRC32, SHA-256, MD5, etc.) permet de détecter une corruption, **pas d’authentifier le contenu**. Si l’attaquant peut accéder à la routine de mise à jour, il peut modifier l’image, recalculer le checksum et flasher du code arbitraire.<sup>[[1]](#references)</sup>

Signaux d’alerte pendant le RE :

- Le code de mise à jour valide uniquement un bloc de checksum final tel que `CHK2`, `CRC` ou `SHA256`.
- Aucune vérification de signature ni racine de confiance de secure boot n’est présente.
- Aucun MAC / HMAC lié à l’appareil ni chiffrement authentifié n’est utilisé.
- Le mode de récupération accepte le même format d’image non authentifié.

Procédure pratique de validation :

1. Extraire le conteneur de firmware et identifier le bootloader, le firmware principal et les métadonnées d’intégrité.
2. Modifier une chaîne de caractères ou une bannière sans conséquence.
3. Recalculer le checksum exactement comme l’attend le programme de mise à jour.
4. Flasher à nouveau l’image via le processus normal de mise à jour.
5. Confirmer la modification au démarrage pour prouver qu’il est possible de remplacer le firmware par du code arbitraire.

Si cela fonctionne via un transport accessible à distance, comme BLE/Wi-Fi, le bug permet effectivement le **remplacement non authentifié du firmware OTA**.

## État de mise à jour fragmenté et métadonnées d’intégrité modifiables

Un programme de mise à jour peut vérifier un en-tête de firmware signé lors de l’installation, puis démarrer les images en utilisant uniquement un hash d’intégrité stocké. Sur le Cypherock X1, le Bootloader invoquait des tâches Firewall distinctes pour vérifier l’en-tête et placer la version/taille en RAM, stocker la signature du firmware en RAM, vérifier l’image écrite, puis calculer le hash de l’image dans les données persistantes du Primary Bootloader. La signature elle-même n’était pas conservée. Ces tâches pouvaient être appelées indépendamment, sans imposer une transaction de mise à niveau authentifiée unique.<sup>[[5]](#references)</sup>

Avec l’exécution de code sur le MCU et un accès en écriture à la Flash, l’attaque rapportée réécrivait l’image de l’application, modifiait les valeurs de version/taille dans la RAM du Bootloader partagée avec le Firewall, puis appelait la dernière tâche de métadonnées pour stocker le hash de l’image malveillante et rétablir l’état de démarrage normal. La vérification d’intégrité au démarrage acceptait ce hash sans revérifier la signature. Lors de l’analyse d’un programme de mise à jour similaire, retracez **quel composant peut invoquer chaque tâche**, où sont stockées les valeurs vérifiées et si la décision prise au démarrage authentifie *la même image* que celle dont le hash est stocké. Ce cas est plus spécifique qu’un format d’image protégé uniquement par checksum : la vérification de signature existait, mais la transition d’état n’y était pas liée.<sup>[[5]](#references)</sup>

## Signatures du secure element sur des mesures de firmware non fiables

Un secure element n’atteste pas le code en cours d’exécution simplement en signant un hash fourni par ce code. Sur le même wallet, le secure element signait le numéro de série de l’appareil, puis le XOR d’un nonce du cloud et d’un hash de firmware transmis par le MCU. Un firmware compromis pouvait fournir le hash attendu pour signature tout en exécutant des octets différents. Le client associé envoyait également la version du firmware au cloud : la comparaison du hash attendu par le vérificateur reposait donc toujours sur une mesure provenant du MCU, plutôt que sur une lecture indépendante de la Flash.<sup>[[5]](#references)</sup>

Le résultat côté appareil constituait une frontière de confiance distincte : le cloud vérifiait l’appareil, mais l’appareil n’authentifiait pas la décision du cloud. Un client modifié pouvait signaler localement une réussite à un appareil altéré. Testez séparément la provenance de la mesure et l’authentification de la réponse ; une signature valide du secure element et un écran de réussite ne prouvent pas, à eux seuls, l’authenticité de l’application installée.<sup>[[5]](#references)</sup>

Pour découvrir comment l’accès au code protégé a permis l’analyse de ce programme de mise à jour, voir [Acquisition du firmware via une tâche de copie du Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Transformer un périphérique USB de confiance en BadUSB en reflashant son firmware

Lorsque l’hôte fait déjà confiance à l’appareil cible via USB, un firmware malveillant n’a peut-être pas besoin d’implémenter une nouvelle pile USB complète. Une solution de contournement bien plus simple consiste souvent à **réutiliser la prise en charge HID existante**.<sup>[[1]](#references)</sup>

Approche utile :

1. Vérifiez si l’appareil s’énumère déjà comme interface **HID Consumer Control** / média / HID propriétaire.
2. Repérez le **descripteur de rapport HID** existant dans le firmware.
3. Ajoutez ou remplacez des entrées du descripteur pour que l’appareil annonce également une capacité **clavier**.
4. Réutilisez les routines du firmware existantes qui envoient déjà des rapports HID, plutôt que d’écrire une nouvelle implémentation de transport.
5. Injectez des rapports d’appui + de relâchement de touches pour saisir des commandes sur l’hôte.

La compromission du firmware devient ainsi une **compromission de l’hôte**, car le PC fera confiance au périphérique reflashé comme à un clavier légitime.

### Liste de contrôle minimale pour l’évaluation

- `dmesg`, Device Manager ou les descripteurs USB révèlent-ils une interface HID existante ?
- Y a-t-il de l’espace disponible près du descripteur de rapport ou une table de descripteurs relogeable ?
- Les routines d’envoi de commandes média existantes peuvent-elles être réutilisées pour les rapports clavier ?
- L’hôte accepte-t-il automatiquement la nouvelle interface clavier après le reflash ?

## Exécution fiable de payloads dans un firmware RTOS

Au lieu d’insérer des trampolines fragiles dans des chemins de code choisis au hasard, recherchez des **tâches RTOS existantes** qui sont inutilisées ou ont peu d’impact en fonctionnement normal.<sup>[[1]](#references)</sup>

Pourquoi c’est utile :

- Le scheduler lance naturellement votre payload au démarrage.
- Vous évitez de corrompre le flux d’exécution critique.
- Les payloads différés risquent moins de déclencher des réinitialisations du watchdog que lorsqu’ils s’exécutent dans un gestionnaire USB/réseau sensible à la latence.

Les bonnes cibles sont les tâches de diagnostic, de test en usine, de télémétrie ou de service de coprocesseur qui semblent inactives en usage normal.

## Accélérer l’itération d’exploits : détourner des gestionnaires de protocole bénins

Une fois le patch du firmware possible, une méthode simple pour accélérer le RE consiste à remplacer un gestionnaire de commande inoffensif (par exemple un **opcode echo/debug**) par des primitives personnalisées de **lecture / écriture / exécution mémoire**. Cela évite de reflasher complètement l’appareil à chaque expérience et s’avère particulièrement utile lorsqu’il prend en charge le gestionnaire modifié via un transport filaire rapide.<sup>[[1]](#references)</sup>

Utilisez cette méthode pour :

- Vérifier les cartes mémoire chargées par segments
- Inspecter en direct l’état du heap/des tâches
- Tester de petits payloads avant de les graver dans la Flash
- Récupérer en toute sécurité des pointeurs de fonction, des chaînes et des tables de descripteurs

## References

- [1] [Pwnd Blaster : pirater votre PC à l’aide de votre haut-parleur sans jamais le toucher](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [kit de modification de firmware](https://github.com/rampageX/firmware-mod-kit)
- [3] [Boîte à outils d’analyse de firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Comment utiliser `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Comment et pourquoi nous avons piraté le wallet matériel Cypherock : l’histoire complète](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
