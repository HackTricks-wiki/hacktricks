# Nœuds terrain autorisés résilients à la capture

Un Raspberry Pi, un mini-PC, un routeur de voyage ou un équipement cellulaire installé sur site peut fournir à une red team autorisée un point d'observation durable. Il constitue également un point probable de découverte, de vol et d'attribution. Le bon objectif de conception est donc un **accès stable et contrôlé avec peu d'autorité sur le nœud terrain**, et non un implant intraçable.

Ce guide s'applique uniquement aux équipements placés avec l'autorisation écrite du propriétaire du site. Un café, un voisin, un hôtel ou un bâtiment partagé n'est pas inclus dans le périmètre simplement parce que son réseau est accessible. Ne dissimulez pas de matériel dans un lieu dont le propriétaire n'a pas donné son consentement, ne contournez pas de captive portal, n'utilisez pas les identifiants d'une autre personne, n'interférez pas avec la supervision et ne tentez pas d'effacer les preuves après une découverte.

{% hint style="warning" %}
Il n'existe aucun paramètre fiable permettant de « ne laisser aucune trace ». L'association radio, DHCP/NAT, les opérateurs, les caméras, les achats, les appareils, les fournisseurs, les contrôleurs et les destinations peuvent conserver des enregistrements après le retrait de l'appareil. Une red team responsable supprime plutôt les **secrets personnels et sans rapport avec l'engagement** du nœud, conserve une attribution protégée côté contrôleur et conçoit la capture de manière à la contenir facilement.
{% endhint %}

## Avantages et inconvénients

**Avantages :** source interne ou proche de la cible réaliste ; tests stables à haut débit ; validation de la NAC, de l'egress, de l'inventaire physique et de la couverture du SOC ; poursuite des opérations malgré les changements d'adresse de l'opérateur ; révocation centralisée d'un accès limité.

**Inconvénients :** le placement physique crée des preuves solides ; la perte peut exposer les identifiants de l'appareil, les profils réseau et les données collectées ; un trafic de contrôle répété est détectable ; l'alimentation, les captive portals et les changements radio nuisent à la fiabilité ; un tunnel trop large peut devenir un pivot incontrôlé.

## Modèle de menace et invariants de conception

Supposez qu'une personne qui trouve l'appareil puisse retirer le stockage, inspecter le firmware, copier tous les secrets conservés par les logiciels, observer le comportement réseau ultérieur et remettre l'appareil au client ou aux forces de l'ordre. Le chiffrement intégral du disque protège uniquement un appareil hors tension dans le cadre du modèle de menace défini ; un nœud déverrouillé en fonctionnement et les clés chargées en mémoire sont deux cas différents.

| Invariant | Conséquence pratique |
|---|---|
| Aucune identité directe entre l'opérateur et le nœud | L'opérateur se connecte à la gateway de l'organisation ; le nœud possède une identité d'appareil différente |
| Aucun élément provenant du poste de travail personnel | Aucune clé SSH personnelle, aucun profil de navigateur, e-mail, gestionnaire de mots de passe, appairage téléphonique ou cache de CLI cloud |
| Aucun secret maître du contrôleur | Un nœud ne peut pas inscrire un autre nœud, modifier la politique ou déchiffrer d'autres engagements |
| Sortant uniquement et limité | Le réseau terrain n'accepte aucun listener de gestion ; le nœud n'accède qu'aux services nommés de rendez-vous, de mise à jour et de temps |
| Autorité limitée dans le temps et dans son périmètre | Chaque identifiant correspond à un appareil, une audience, un service, une expiration et un moyen de révocation immédiate |
| Données locales minimales | Les résultats sont transmis au contrôleur ; les caches sont chiffrés, leur taille et leur TTL sont limités et ils ne font pas autorité |
| L'accountability du contrôleur survit à la capture | La correspondance entre l'actif et l'engagement, les approbations, les accès des opérateurs et les commandes sont stockés de manière centralisée et soumis à des contrôles d'accès |
| La perte entraîne l'arrêt des opérations | Une découverte ou une modification d'état inexpliquée déclenche l'arrêt, la révocation, la notification et la préservation des preuves, et non une destruction à distance |

Le socle IoT de NIST regroupe l'identification des appareils, la configuration, la protection des données, l'accès logique, la mise à jour sécurisée des logiciels et la connaissance de l'état de cybersécurité parmi les capacités fondamentales. Il considère spécifiquement la connaissance de l'état et les enregistrements d'événements hors appareil comme des éléments facilitant l'enquête en cas de compromission.<sup>[[1]](#references)</sup>

## Architecture de référence
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
La gateway doit savoir quel opérateur nommé a atteint quel appareil nommé. Le field node n'a besoin que d'un device credential pour le rendezvous. Il n'apprend jamais l'adresse source ni le secret d'authentification de l'opérateur, et l'opérateur ne lui copie jamais de clé de gestion privée. Cela réduit le lien personnel récupérable **depuis le stockage terrain** sans supprimer la traçabilité de l'exercice.

Pour une flotte plus importante, un système de workload identity peut émettre des identités X.509 à courte durée de vie et effectuer automatiquement la rotation des clés. SPIFFE recommande les X.509 SVID lorsque cela est possible et décrit les courtes durées de vie ainsi que la rotation fréquente comme des moyens de limiter l'exposition en cas de compromission d'une clé.<sup>[[2]](#references)</sup> Une petite équipe peut appliquer les mêmes propriétés avec une CA privée et des certificats automatisés par appareil ; installer SPIRE n'est pas nécessaire simplement pour respecter ce modèle.

## Étape 1 : autoriser et enregistrer le déploiement

1. Enregistrer le propriétaire, le site, la zone de placement exacte autorisée, les réseaux autorisés, la fenêtre d'évaluation, les destinations/actions autorisées et les contacts d'urgence.
2. Enregistrer le modèle, le numéro de série, le numéro de série du stockage, les adresses MAC filaires/sans fil, l'IMEI/eSIM ou l'ICCID de la SIM du modem, l'alimentation et une photographie récente.
3. Attribuer à l'appareil un identifiant d'engagement non personnel, par exemple `E2026-014-DROP03`. Ne pas encoder le nom d'un client dans les hostnames ou SSID diffusés.
4. Informer le responsable de l'exercice et le groupe restreint nécessaire de sécurité physique/SOC chargé de la déconfliction de ce que signifient « perdu », « déplacé » et « découvert » pour ce test.
5. Définir à l'avance les personnes autorisées à le récupérer et la manière dont une personne qui le trouve peut le signaler. Une étiquette de sécurité peut omettre les détails sensibles du client tout en fournissant un callback contrôlé.
6. Définir une expiration automatique de l'autorisation. Le maintien de la connectivité après la fin du périmètre ne doit pas prolonger l'autorisation.

## Étape 2 : créer une image minimale récupérable

Utiliser une image d'OS prise en charge, vérifier sa signature/son checksum via le canal documenté par le fournisseur, installer les mises à jour de sécurité et conserver un manifeste de build reproductible. Préférer une base en lecture seule ou immutable avec une petite partition de données inscriptible lorsque le logiciel le permet.

1. Supprimer les comptes par défaut, les services de démonstration, les compilateurs et les packages non nécessaires à la workload autorisée.
2. Désactiver la GUI locale, le Bluetooth, les protocoles de découverte, le partage de fichiers, le Wi-Fi P2P et l'administration entrante, sauf si l'exercice en exige explicitement un.
3. Activer le secure boot et le measured boot/la libération de clés basée sur le TPM si le matériel les prend réellement en charge ; ne pas prétendre qu'une configuration Raspberry Pi dispose d'un measured boot de classe PC sans avoir validé le modèle exact.
4. Chiffrer l'état local inscriptible et configurer une taille maximale ainsi qu'une durée de rétention strictes. Le chiffrement est un contrôle de délai/confinement, pas la preuve qu'un node en fonctionnement ne révèle rien.
5. Envoyer les logs importants hors de l'appareil. Limiter les journaux locaux pour empêcher l'épuisement du stockage, mais ne pas configurer leur effacement ni une suppression anti-forensic.
6. Stocker le manifeste de l'image, les versions des packages, le hash de configuration et les instructions de récupération auprès du contrôleur.
7. Réinstaller l'image d'un spare à partir du manifeste et exécuter le même health test. Une conception que seul son créateur peut récupérer n'est pas prête pour le terrain.

## Étape 3 : émettre des identités avec une confiance unidirectionnelle

Créer trois identités différentes :

- une **device identity**, acceptée uniquement par le rendezvous de cet appareil ;
- une **operator identity**, acceptée par la gateway de l'organisation et protégée par une MFA résistante au phishing ; et
- une **controller/deployment identity**, utilisée pour signer les jobs ou la configuration approuvés, conservée en dehors de l'opérateur et du field node.

Le node doit disposer de la clé publique nécessaire pour vérifier les jobs signés, jamais de la clé de signature. Un device credential capturé ne doit pas pouvoir s'authentifier auprès des consoles cloud, des source repositories, des comptes de paiement, d'autres nodes ou de la production du client.

Utiliser des certificats à courte durée de vie lorsque le renouvellement automatique est fiable. Lorsqu'une clé WireGuard à longue durée de vie est nécessaire sur le plan opérationnel, traiter sa clé publique comme le handle de révocation et la limiter avec une adresse de tunnel propre au peer, une politique de firewall et une autorisation du broker. Conserver une action du contrôleur testée qui supprime immédiatement ce peer.

## Étape 4 : rendezvous sortant stable

Le pattern de laboratoire détenu par l'organisation suivant fournit une gestion stable à travers le NAT sans exposer de service entrant. Il s'agit d'un réseau WireGuard ordinaire, et non d'un reverse shell covert. Utiliser des adresses de documentation et ne les remplacer que par des endpoints appartenant à l'organisation.

Au niveau du rendezvous de l'organisation, attribuer `10.77.0.1/32` ; attribuer `10.77.0.20/32` au field node. L'entrée peer de la gateway ne doit accepter que l'adresse unique du node :
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Le nœud établit une connexion sortante vers le rendezvous et ne conserve le mapping NAT que lorsque cela est nécessaire :
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard documente 25 secondes comme un intervalle de keepalive raisonnable avec de nombreuses implémentations NAT/firewall lorsque la persistance est nécessaire ; le laisser désactivé est préférable lorsqu'il ne l'est pas.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` en fait délibérément un chemin de gestion, et non un pivot via la route par défaut.

Appliquez ensuite des contrôles en dehors de WireGuard :

1. Résolvez `vpn.redteam.example` via le chemin DNS bootstrap approuvé et épinglez l'endpoint attendu de l'organisation dans les enregistrements de déploiement.
2. Sur le nœud, autorisez le DHCP/RA sortant, le DNS/NTP requis, l'endpoint de rendezvous et le chemin de mise à jour approuvé minimal. Refusez le trafic entrant non sollicité sur chaque uplink.
3. Sur le rendezvous, autorisez `10.77.0.20` à atteindre uniquement le service broker/health requis pour l'exercice. Ne le transférez pas de manière générale vers un réseau client.
4. Placez l'accès interactif des opérateurs derrière la gateway de l'organisation. Évitez d'exposer SSH depuis le nœud à travers le tunnel si une interface signed pull-job suffit pour l'évaluation.
5. Configurez le service manager pour démarrer le tunnel après le réseau, le redémarrer après une défaillance avec un backoff borné et déclencher une alerte après des échecs répétés. Une boucle de redémarrage ne doit pas submerger le site ni masquer le problème sous-jacent.
6. Vérifiez le dernier handshake du peer, mais n'utilisez pas « handshake existant » comme preuve que l'appareil n'est pas compromis.

TURN peut fournir une reachability relay-only pour un control plane WebRTC conçu à cet effet, et une message queue peut tolérer un service intermittent. TURN fournit explicitement à un client une adresse de relay publique derrière le NAT ; son serveur reste un observateur.<sup>[[4]](#references)</sup> Choisissez une architecture de contrôle plutôt que d'empiler des tunnels sans bénéfice déclaré en matière d'observation ou de fiabilité.

## Étape 5 : stabilité de l'uplink sans liens personnels

Pour un nœud de site autorisé, préférez cet ordre :

1. VLAN câblé ou VLAN de test dédié fourni par le client ;
2. profil Wi-Fi d'entreprise ou invité approuvé par le propriétaire ;
3. solution de secours cellulaire/APN privé sous contrat avec l'organisation.

Ne l'initialisez jamais avec un hotspot de téléphone personnel, un SSID domestique, une eSIM personnelle, un compte Apple/Google personnel ou un profil Wi-Fi exporté depuis un laptop quotidien. Ce sont précisément les artefacts auxquels une capture se connectera.

Pour chaque uplink approuvé :

- enregistrez le SSID/BSSID ou le switch/VLAN ainsi que le comportement attendu du captive portal ;
- définissez une priorité déterministe et un health check vers un endpoint détenu par l'organisation ;
- faites en sorte que le failover ne change que l'underlay ; les identités de l'appareil et de l'opérateur restent au niveau du broker ;
- assurez-vous que le DNS, l'IPv6 et le trafic applicatif ne contournent pas le rendezvous pendant la transition ;
- déclenchez une alerte en cas de SSID/BSSID inconnu, de changement de SIM, de nouvelle default gateway, de changement d'IP publique/ASN ou d'uplinks simultanés ;
- testez la perte d'alimentation, le renouvellement DHCP, le redémarrage de l'AP, le changement d'IP publique, 24 heures d'inactivité, la perte du tunnel et la récupération primaire-secondaire-primaire avant le déploiement.

L'adressage MAC privé peut réduire le suivi inter-réseaux opportuniste, mais un MAC stable par réseau est souvent nécessaire pour le NAC autorisé. Enregistrez le comportement réel de l'OS choisi et ne le faites pas tourner autour du contrôle d'accès d'un propriétaire.

## Étape 6 : limiter le travail et les données

Un nœud de terrain sûr ne doit pas accepter de texte shell arbitraire depuis une mailbox. Définissez des types de jobs signés tels que `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ou toute autre action explicitement nommée dans les règles d'engagement. Validez de nouveau la destination, la durée, le débit, la taille de sortie et le périmètre sur le nœud.

1. Attribuez à chaque job un ID unique, une audience d'appareils, une heure d'émission, une expiration, une référence de périmètre et une sortie maximale.
2. Signez-le avec l'identité du contrôleur/déploiement.
3. Rejetez les champs inconnus, les jobs expirés ou rejoués et les jobs destinés à un autre appareil.
4. Envoyez les résultats en streaming à un collector détenu par l'organisation ; chiffrez et appliquez un TTL à tout spool local inévitable.
5. Journalisez l'ID du job accepté/rejeté et le hash du résultat sur le contrôleur. Ne placez pas de paramètres de commande sensibles dans un canal de monitoring public.
6. Arrêtez le traitement lorsque l'autorisation expire, que la rotation d'identité échoue ou que le contrôleur place l'appareil en quarantaine.

## Monitoring de la découverte, de la perte ou de la compromission

Le monitoring peut indiquer au contrôleur que l'état observé a changé. Il ne peut pas prouver de manière fiable que des « enquêteurs ont trouvé l'appareil », et tenter de surveiller les intervenants ou de sonder leurs systèmes dépasserait le cadre d'une évaluation autorisée.

### Collecter l'état hors appareil

Envoyez au contrôleur un enregistrement de health signé et à faible volume selon un intervalle opérationnel randomisé mais borné. N'incluez que ce dont le contrôleur a besoin :

- ID de l'appareil, boot ID/compteur et uptime monotone ;
- hash de configuration/image et version logicielle ;
- numéro de série du certificat de l'appareil et état du renouvellement ;
- classe d'uplink, interface, BSSID ou contexte de switch selon autorisation, hash de la default gateway et IP publique/ASN observés par un service détenu par l'organisation ;
- âge du handshake du tunnel, compteurs de paquets et profondeur de file ;
- état du switch du boîtier ou du hardware-tamper si le propriétaire a approuvé le capteur ;
- pression disque, température, estimation du décalage d'horloge et ID du dernier job réussi ;
- numéro de séquence et signature pour révéler les replays ou les trous.

Stockez centralement l'authentification de la gateway, les décisions de policy, les accès opérateurs, la soumission des jobs, les hashes de résultats, les événements d'audit des providers et les alertes. La CISA recommande de centraliser les logs, de les protéger contre la suppression, d'établir une baseline de l'activité normale et de désigner des contacts d'incident response.<sup>[[5]](#references)</sup>

### Indicateurs de découverte/compromission

| Signal | Explications possibles | Action du contrôleur |
|---|---|---|
| Heartbeat absent | défaillance d'alimentation/réseau, changement de portail, dommage, blocage délibéré ou retrait | corroborer l'état du provider/site ; ne pas reconnecter via un chemin non approuvé |
| Compteur de boot modifié de manière inattendue | coupure d'alimentation, crash, retrait ou maintenance | mettre les jobs en quarantaine ; comparer l'heure et les événements du site |
| Hash de configuration/image modifié | erreur de mise à jour, défaillance du stockage ou tampering | arrêter le travail ; révoquer si ce n'est pas une release approuvée par le contrôleur |
| Nouvel uplink/BSSID/gateway/ASN | remplacement d'AP, roaming, déplacement de l'appareil ou interception | comparer à l'inventaire approuvé ; mettre en quarantaine toute transition inexpliquée |
| Rejet répété d'un job/de sa signature | corruption, replay ou contrôleur non autorisé | arrêter le traitement et examiner les logs de la gateway/du contrôleur |
| Credential de l'appareil utilisé deux fois ou depuis des chemins incompatibles | clé clonée, réutilisation d'un snapshot ou transition réseau | révoquer immédiatement ; conserver les deux enregistrements de session |
| Login local, interface, processus ou événement de privilège inattendu | maintenance ou compromission | isoler via la policy du broker ; préserver les preuves |
| Transition du switch/état du boîtier | intervention, déplacement ou découverte | notifier le contact du site désigné ; ne pas déclencher d'action destructive |
| Notification d'abus du provider/requête de compte ou alerte SOC | détection, mauvaise configuration ou trafic hors périmètre | arrêter l'activité et déclencher le processus de deconfliction/incident |
| Sentinel credential consulté | quelqu'un a lu un secret leurre sans privilège, unique à ce nœud | révoquer la véritable identité de l'appareil et préserver la trace d'alerte |

Un sentinel credential ne doit accorder **aucun accès**, appeler uniquement un service d'alerte détenu par l'organisation et être divulgué dans les règles d'engagement. Il s'agit d'un tripwire contre la lecture non autorisée, et non d'un beacon permettant de suivre la personne ayant trouvé l'équipement.

### Seuils d'alerte

Utilisez des règles stateful, et non une unique alerte spectaculaire signalant une « capture » :

- **warning:** un intervalle manqué, changement normal d'adresse ou croissance de la file ;
- **degraded:** trois intervalles consécutifs manqués, retard de renouvellement, perte de l'uplink primaire ou redémarrage répété ;
- **quarantine:** changement non approuvé du hash/boot/uplink, credential dupliqué, utilisation du sentinel ou événement privilégié inattendu ;
- **confirmed discovery/loss:** rapport du site/contrôleur, incohérence d'inventaire physique, récupération de l'appareil par une personne non planifiée ou escalation validée du provider/SOC.

Testez la remise des alertes via un canal indépendant du nœud de terrain. Évitez d'envoyer des détails sensibles sur le client/l'appareil vers des services de messagerie personnels ou des comptes push grand public.

## Runbook en cas de découverte ou de capture suspectée

1. **Stop:** suspendez les nouveaux jobs et les sessions opérateurs. N'envoyez pas de sonde pour « vérifier si vous êtes surveillé ».
2. **Quarantine:** faites en sorte que le broker refuse l'identité de l'appareil et ses routes tout en conservant les logs existants.
3. **Revoke:** révoquez le certificat/la clé de l'appareil, le token de queue, le credential de mise à jour et tout service token à usage unique. Suspendez la SIM de l'organisation si une perte physique est plausible.
4. **Preserve:** faites un snapshot des enregistrements du contrôleur, de la gateway, du provider et des alertes ; consignez l'heure de confiance, l'auteur de l'action et la dernière configuration connue. N'effacez pas et ne wipez pas le nœud à distance.
5. **Notify:** contactez le contrôleur de l'exercice, le contact incident du client et les contacts legal/privacy définis dans l'autorisation. Si un tiers l'a trouvé, utilisez le processus de récupération convenu à l'avance.
6. **Assess:** considérez que chaque secret et résultat mis en cache sur le nœud est exposé. Énumérez précisément ce à quoi chaque secret pouvait accéder et vérifiez s'il a été utilisé après l'événement suspect.
7. **Contain downstream:** faites tourner les credentials de service concernés, invalidez les jobs en attente et inspectez les logs des cibles/providers détenus par l'organisation à la recherche de comportements inattendus.
8. **Recover safely:** récupérez l'appareil uniquement par l'intermédiaire d'une personne autorisée ; photographiez-le/emballez-le, consignez la custody et acquérez les preuves forensiques selon les directives du client.
9. **Resume with a new identity:** ne réactivez jamais silencieusement le credential capturé. Reconstituez l'appareil depuis le manifest connu, corrigez la défaillance de contrôle et obtenez une approbation explicite.

Les recommandations actuelles du NIST en matière d'incident response intègrent la préparation, la détection, la réponse et la récupération dans la gestion des risques de cybersécurité à l'échelle de l'organisation ; préservez d'abord les éléments afin que le client puisse déterminer ce qui s'est produit et choisir la réponse appropriée.<sup>[[6]](#references)</sup>

## Exercice de capture avant le déploiement

Remettez une unité de test déverrouillée ou une copie de son stockage à un reviewer indépendant et demandez-lui d'énumérer :

1. les identifiants de l'appareil, du site et de l'engagement ;
2. les noms des opérateurs, les comptes personnels, les réseaux domestiques/de workstation et les contacts de récupération ;
3. les destinations et credentials du contrôleur/broker ;
4. les profils réseau du client et les résultats mis en cache ;
5. les autres appareils/projets accessibles avec chaque secret ;
6. les credentials de valeur ou de paiement ;
7. ce que le contrôleur peut révoquer et dans quel délai ;
8. les activités qui restent attribuables à partir des logs centralisés.

Critères de réussite : zéro compte personnel/clé de workstation ; zéro autorité inter-engagement ou d'enrollment ; aucun credential de paiement ; cache chiffré et borné ; une action documentée de révocation de l'appareil ; traçabilité complète côté contrôleur. Traitez tout lien personnel inattendu ou toute capacité latérale comme un bloqueur de release.

## Clôture

1. Arrêtez les jobs et désactivez la route du broker à la fin du périmètre.
2. Récupérez et rapprochez l'inventaire exact ; signalez tout élément manquant.
3. Préservez les logs/résultats et, si nécessaire, une image forensique conformément au plan de conservation de l'engagement.
4. Révoquez les identités de l'appareil, de la SIM, de la queue, de la mise à jour et des services même si le hardware a été récupéré.
5. Ce n'est qu'après la préservation/l'acceptation que vous devez assainir ou détruire les médias selon le processus de mise au rebut approuvé par le propriétaire et consigner la fin de l'opération. Il s'agit de gestion du cycle de vie, et non de dissimulation.
6. Supprimez les réservations NAC/DHCP du site, les routes du broker, le DNS, les rôles cloud, les règles d'alerte et les contacts temporaires.
7. Documentez la détection observée, la télémétrie manquée, le délai de mise en quarantaine et chaque artefact exposé par la capture.

## References

- [1] [NIST — Catalogue des capacités de cybersécurité des appareils IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts et identités de workloads à courte durée de vie](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start : Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Utiliser le logging sur les systèmes professionnels](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Recommandations et considérations relatives à l'incident response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
