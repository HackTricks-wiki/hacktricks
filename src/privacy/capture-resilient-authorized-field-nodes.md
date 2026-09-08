# Nœuds de terrain autorisés résilients à la capture

{{#include ../banners/hacktricks-training.md}}

Un Raspberry Pi, un mini-PC, un routeur de voyage ou un équipement cellulaire installé sur site peut fournir à une red team autorisée un point d'observation durable. Il constitue également un point probable de découverte, de vol et d'attribution. Le bon objectif de conception est donc un **accès stable et contrôlé avec peu d'autorité sur le nœud de terrain**, et non un implant intraçable.

Ce guide s'applique uniquement aux équipements placés avec l'autorisation écrite du propriétaire du site. Un café, un voisin, un hôtel ou un immeuble partagé n'entre pas dans le périmètre simplement parce que son réseau est accessible. Ne dissimulez pas de matériel dans un lieu dont le propriétaire n'a pas consenti, ne contournez pas de captive portal, n'utilisez pas les identifiants d'une autre personne, n'interférez pas avec la surveillance et ne tentez pas d'effacer les preuves après une découverte.

{% hint style="warning" %}
Il n'existe pas de paramètre fiable « ne laisser aucune trace ». Les enregistrements d'association radio, DHCP/NAT, opérateur, caméra, achat, appareil, fournisseur, contrôleur et destination peuvent survivre à l'appareil. Une red team responsable supprime plutôt du nœud les **secrets personnels et sans rapport**, conserve l'attribution protégée côté contrôleur et fait en sorte qu'une capture soit facile à contenir.
{% endhint %}

## Avantages et inconvénients

**Avantages :** source interne ou proche de la cible réaliste ; tests stables à haut débit ; validation du NAC, de l'egress, de l'inventaire physique et de la couverture du SOC ; possibilité de continuer malgré les changements d'adresse de l'opérateur ; révocation centralisée des accès limités.

**Inconvénients :** le placement physique crée des preuves solides ; la perte peut exposer les identifiants de l'appareil, les profils réseau et les données collectées ; un trafic de contrôle répété est détectable ; l'alimentation, les portails et les changements radio nuisent à la fiabilité ; un tunnel étendu peut devenir un pivot incontrôlé.

## Modèle de menace et invariants de conception

Supposez qu'une personne qui trouve l'appareil puisse retirer le stockage, inspecter le firmware, copier chaque secret conservé par les logiciels, observer les comportements réseau ultérieurs et remettre l'appareil au client ou aux forces de l'ordre. Le chiffrement intégral du disque protège un appareil éteint uniquement dans les limites de son modèle de menace déclaré ; un nœud en fonctionnement et déverrouillé, ainsi que les clés libérées en mémoire, sont des cas différents.

| Invariant | Conséquence pratique |
|---|---|
| Aucune identité directe de l'opérateur vers le nœud | L'opérateur se connecte à la gateway de l'organisation ; le nœud possède une identité d'appareil différente |
| Aucun élément provenant du poste de travail personnel | Aucune clé SSH personnelle, aucun profil de navigateur, e-mail, password manager, appairage de téléphone ou cache de CLI cloud |
| Aucun secret maître du contrôleur | Un nœud ne peut pas enrôler un autre nœud, modifier la policy ou déchiffrer d'autres engagements |
| Sortant uniquement et limité | Le réseau de terrain n'accepte aucun listener de management ; le nœud n'atteint que les services nommés de rendezvous, de mise à jour et de temps |
| Autorité limitée et de courte durée | Chaque credential est associé à un seul appareil, une audience, un service, une expiration et un moyen de révocation immédiate |
| Données locales minimales | Les résultats sont transmis au contrôleur ; les caches sont chiffrés, leur taille et leur TTL sont limités et ils ne font pas autorité |
| La responsabilité du contrôleur survit à la capture | La correspondance actif-engagement, les approbations, les accès des opérateurs et les commandes sont stockés de manière centralisée et soumis à des contrôles d'accès |
| La perte arrête le travail | Une découverte ou une modification d'état inexpliquée déclenche l'arrêt, la révocation, la notification et la préservation des preuves, et non une destruction à distance |

La base IoT de NIST regroupe l'identification des appareils, la configuration, la protection des données, l'accès logique, la mise à jour sécurisée des logiciels et la connaissance de l'état de cybersécurité comme capacités essentielles. Elle considère spécifiquement la connaissance de l'état et les enregistrements d'événements hors appareil comme un soutien à l'investigation d'une compromission.<sup>[[1]](#references)</sup>

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
La passerelle doit savoir quel opérateur nommé a atteint quel appareil nommé. Le field node n'a besoin que d'un device credential pour le rendezvous. Il n'apprend jamais l'adresse source ni le secret d'authentification de l'opérateur, et l'opérateur n'y copie jamais de clé de gestion privée. Cela réduit le lien personnel récupérable **à partir du stockage terrain** sans détruire la traçabilité de l'exercice.

Pour une flotte plus importante, un système d'identité de workload peut délivrer des identités X.509 à courte durée de vie et faire tourner automatiquement les clés. SPIFFE recommande les X.509 SVID lorsque cela est possible et décrit les courtes durées de vie ainsi que la rotation fréquente comme des mesures limitant l'exposition liée à la compromission d'une clé.<sup>[[2]](#references)</sup> Une petite équipe peut appliquer les mêmes propriétés avec une AC privée et des certificats automatisés par appareil ; installer SPIRE n'est pas nécessaire simplement pour respecter ce modèle.

## Étape 1 : autoriser et enregistrer l'installation

1. Enregistrer le propriétaire, le site, la zone d'installation exacte autorisée, les réseaux autorisés, la fenêtre d'évaluation, les destinations/actions autorisées et les contacts d'urgence.
2. Enregistrer le modèle, le numéro de série, le numéro de série du stockage, les adresses MAC filaires/sans fil, l'IMEI/eSIM ou l'ICCID de la SIM du modem, l'alimentation et une photographie récente.
3. Attribuer à l'appareil un identifiant d'engagement non personnel, par exemple `E2026-014-DROP03`. Ne pas encoder le nom d'un client dans les hostnames de broadcast ou les SSID.
4. Informer le contrôleur de l'exercice et le groupe le plus restreint nécessaire de sécurité physique/SOC de la signification de « perdu », « déplacé » et « découvert » pour ce test.
5. Définir à l'avance les personnes autorisées à le récupérer et la manière dont une personne qui le trouve peut le signaler. Une étiquette de sécurité peut omettre les informations sensibles du client tout en fournissant un callback contrôlé.
6. Définir une expiration automatique de l'autorisation. Le maintien de la connectivité après la fin du périmètre ne doit pas prolonger l'autorisation.

## Étape 2 : créer une image minimale récupérable

Utiliser une image d'OS supportée, vérifier sa signature/son checksum via le canal documenté par le fournisseur, installer les mises à jour de sécurité et conserver un manifeste de build reproductible. Privilégier une base en lecture seule ou immutable avec une petite partition de données inscriptible lorsque le logiciel le permet.

1. Supprimer les comptes par défaut, les services de démonstration, les compilateurs et les paquets inutiles pour le workload autorisé.
2. Désactiver la GUI locale, le Bluetooth, les protocoles de découverte, le partage de fichiers, le Wi-Fi P2P et l'administration entrante, sauf si l'exercice en exige explicitement un.
3. Activer le secure boot et le measured boot/la libération de clés adossée au TPM si le matériel les prend réellement en charge ; ne pas prétendre qu'une configuration Raspberry Pi dispose d'un measured boot de niveau PC sans avoir validé le modèle exact.
4. Chiffrer l'état local inscriptible et configurer une taille maximale ainsi qu'une durée de rétention strictes. Le chiffrement est un contrôle de délai/confinement, et non la preuve qu'un nœud en fonctionnement ne révèle rien.
5. Envoyer les logs importants hors de l'appareil. Limiter les journaux locaux afin d'empêcher l'épuisement du stockage, mais ne pas configurer d'effacement des logs ni de suppression anti-forensic.
6. Stocker le manifeste de l'image, les versions des paquets, le hash de configuration et les instructions de récupération auprès du contrôleur.
7. Réinstaller l'image sur un appareil de secours à partir du manifeste et exécuter le même test de santé. Une conception que seul son créateur peut récupérer n'est pas prête pour le terrain.

## Étape 3 : délivrer des identités avec une confiance unidirectionnelle

Créer trois identités différentes :

- une **device identity**, acceptée uniquement par le rendezvous correspondant à cet appareil ;
- une **operator identity**, acceptée par la passerelle de l'organisation et protégée par une MFA résistante au phishing ; et
- une **controller/deployment identity**, utilisée pour signer les jobs ou configurations approuvés, conservée en dehors de l'opérateur et du field node.

Le nœud doit disposer de la clé publique nécessaire pour vérifier les jobs signés, jamais de la clé de signature. Un device credential capturé ne doit pas pouvoir s'authentifier auprès des consoles cloud, des dépôts source, des comptes de paiement, des autres nœuds ou de la production du client.

Utiliser des durées de vie de certificats courtes lorsque le renouvellement automatique est fiable. Lorsqu'une clé WireGuard à longue durée de vie est nécessaire sur le plan opérationnel, traiter sa clé publique comme le handle de révocation et la contraindre avec une adresse de tunnel propre au peer, une policy de firewall et une autorisation du broker. Conserver une action du contrôleur testée qui supprime immédiatement ce peer.

## Étape 4 : rendezvous sortant stable

Le pattern de laboratoire détenu par l'organisation ci-dessous fournit une gestion stable à travers le NAT sans exposer de service entrant. Il s'agit d'un réseau WireGuard ordinaire, et non d'un reverse shell furtif. Utiliser des adresses de documentation et ne les remplacer que par des endpoints appartenant à l'organisation.

Au niveau du rendezvous de l'organisation, attribuer `10.77.0.1/32` ; attribuer `10.77.0.20/32` au field node. L'entrée peer de la passerelle ne doit accepter que l'adresse unique du nœud :
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Le nœud pointe vers le rendezvous en sortie et ne conserve le mappage NAT que lorsque cela est nécessaire :
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
WireGuard documente 25 secondes comme un intervalle de keepalive raisonnable pour de nombreuses implémentations NAT/firewall lorsque la persistance est nécessaire ; il est préférable de le laisser désactivé lorsqu'il n'est pas nécessaire.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` en fait délibérément un chemin de gestion, et non un pivot via la route par défaut.

Appliquez ensuite les contrôles en dehors de WireGuard :

1. Résolvez `vpn.redteam.example` via le chemin DNS bootstrap approuvé et épinglez l'endpoint de l'organisation attendu dans les enregistrements de déploiement.
2. Sur le nœud, autorisez le DHCP/RA sortant, le DNS/NTP requis, l'endpoint de rendez-vous et le chemin de mise à jour approuvé minimal. Refusez le trafic entrant non sollicité sur chaque uplink.
3. Sur le rendez-vous, autorisez `10.77.0.20` à atteindre uniquement le service broker/health requis pour l'exercice. Ne le transférez pas généralement vers un réseau client.
4. Placez l'accès interactif des opérateurs derrière la passerelle de l'organisation. Évitez d'exposer SSH depuis le nœud à travers le tunnel si une interface signed pull-job suffit pour l'évaluation.
5. Configurez le service manager pour démarrer le tunnel après le réseau, le redémarrer après une panne avec un backoff borné et déclencher une alerte après des pannes répétées. Une boucle de redémarrage ne doit ni surcharger le site ni masquer la panne sous-jacente.
6. Vérifiez le dernier handshake du peer, mais n'utilisez pas l'existence d'un « handshake » comme preuve que l'appareil n'est pas compromis.

TURN peut fournir une reachability relay-only pour un control plane WebRTC conçu à cet effet, et une message queue peut tolérer un service intermittent. TURN fournit explicitement à un client une adresse de relay publique derrière un NAT ; son serveur reste un observateur.<sup>[[4]](#references)</sup> Choisissez une architecture de contrôle plutôt que d'empiler des tunnels sans avantage déclaré en matière d'observation ou de fiabilité.

## Étape 5 : stabilité de l'uplink sans liens personnels

Pour un nœud de site autorisé, privilégiez cet ordre :

1. VLAN filaire ou de test dédié fourni par le client ;
2. profil Wi-Fi d'entreprise/invité approuvé par le propriétaire ;
3. fallback cellulaire/APN privé sous contrat avec l'organisation.

Ne le préconfigurez jamais avec un hotspot de téléphone personnel, un SSID domestique, une eSIM personnelle, un compte Apple/Google personnel ou un profil Wi-Fi exporté depuis un laptop quotidien. Ce sont précisément les artefacts auxquels une capture se connectera.

Pour chaque uplink approuvé :

- enregistrez le SSID/BSSID ou le switch/VLAN ainsi que le comportement attendu du captive portal ;
- définissez une priorité déterministe et un health check vers un endpoint détenu par l'organisation ;
- faites en sorte que le failover ne modifie que l'underlay ; les identités de l'appareil et de l'opérateur restent au niveau du broker ;
- assurez-vous que le DNS, IPv6 et le trafic applicatif ne contournent pas le rendez-vous pendant la transition ;
- déclenchez une alerte en cas de SSID/BSSID inconnu, de changement de SIM, de nouvelle passerelle par défaut, de changement d'IP publique/ASN ou d'uplinks simultanés ;
- testez la perte d'alimentation, le renouvellement DHCP, le redémarrage de l'AP, le changement d'IP publique, 24 heures d'inactivité, la perte du tunnel et la récupération primaire-secondaire-primaire avant le déploiement.

L'adressage MAC privé peut réduire le suivi inter-réseaux courant, mais un MAC stable par réseau est souvent nécessaire pour le NAC autorisé. Documentez ce que fait réellement l'OS choisi et ne le faites pas tourner autour du contrôle d'accès du propriétaire.

## Étape 6 : limiter le travail et les données

Un nœud de site sûr ne devrait pas accepter du texte shell arbitraire depuis une boîte mail. Définissez des types de jobs signés tels que `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ou toute autre action explicitement nommée dans les rules of engagement. Validez à nouveau la destination, la durée, le débit, la taille de sortie et le périmètre sur le nœud.

1. Attribuez à chaque job un ID unique, une audience d'appareil, une heure d'émission, une expiration, une référence de périmètre et une sortie maximale.
2. Signez-le avec l'identité du controller/deployment.
3. Rejetez les champs inconnus, les jobs expirés ou rejoués et les jobs destinés à un autre appareil.
4. Transmettez les résultats à un collector détenu par l'organisation ; chiffrez et appliquez un TTL à tout spool local inévitable.
5. Journalisez l'ID du job accepté/rejeté et le hash du résultat au niveau du controller. Ne placez pas de paramètres de commande sensibles dans un canal public de monitoring.
6. Arrêtez le traitement lorsque l'autorisation expire, que la rotation d'identité échoue ou que le controller place l'appareil en quarantaine.

## Monitoring de la découverte, de la perte ou de la compromission

Le monitoring peut indiquer au controller que l'état observé a changé. Il ne peut pas prouver de manière fiable que des « enquêteurs ont trouvé l'appareil », et tenter de surveiller les intervenants ou de sonder leurs systèmes dépasserait le cadre d'une évaluation autorisée.

### Collecter l'état hors appareil

Envoyez au controller un enregistrement de santé signé et de faible volume à un intervalle opérationnel aléatoire mais borné. N'incluez que ce dont le controller a besoin :

- ID de l'appareil, ID/compteur de boot et uptime monotone ;
- hash de la configuration/image et version logicielle ;
- numéro de série du certificat de l'appareil et état du renouvellement ;
- classe d'uplink, interface, BSSID ou contexte du switch si autorisé, hash de la passerelle par défaut et IP publique/ASN observés par un service détenu par l'organisation ;
- âge du handshake du tunnel, compteurs de paquets et profondeur de file ;
- état du switch de boîtier ou du tamper matériel si le propriétaire a approuvé le capteur ;
- pression disque, température, estimation du décalage d'horloge et dernier ID de job réussi ;
- numéro de séquence et signature pour révéler les replays ou les trous.

Stockez centralement l'authentification de la passerelle, les décisions de policy, les accès opérateur, la soumission des jobs, les hash de résultats, les événements d'audit du provider et les alertes. CISA recommande de centraliser les logs, de les protéger contre la suppression, d'établir une baseline de l'activité normale et de désigner des contacts d'incident response.<sup>[[5]](#references)</sup>

### Indicateurs de découverte/compromission

| Signal | Explications possibles | Action du controller |
|---|---|---|
| Heartbeat absent | panne d'alimentation/réseau, changement de portail, dommage, blocage délibéré ou retrait | corroborer l'état du provider/site ; ne pas reconnecter depuis un chemin non approuvé |
| Compteur de boot modifié de manière inattendue | coupure d'alimentation, crash, retrait ou maintenance | mettre les jobs en quarantaine ; comparer l'heure et les événements du site |
| Hash de configuration/image modifié | erreur de mise à jour, panne de stockage ou tampering | arrêter le travail ; révoquer si ce n'est pas une release approuvée par le controller |
| Nouvel uplink/BSSID/passerelle/ASN | remplacement de l'AP, roaming, déplacement de l'appareil ou interception | comparer à l'inventaire approuvé ; mettre en quarantaine toute transition inexpliquée |
| Rejet répété d'un job/signature | corruption, replay ou controller non autorisé | arrêter le traitement et examiner les logs de la passerelle/du controller |
| Credential de l'appareil utilisé deux fois ou depuis des chemins incompatibles | clé clonée, réutilisation d'un snapshot ou transition réseau | révoquer immédiatement ; conserver les deux enregistrements de session |
| Login local, interface, processus ou événement de privilège inattendu | maintenance ou compromission | isoler via la policy du broker ; préserver les preuves |
| Transition du switch/état du boîtier | intervention, déplacement ou découverte | notifier le contact de site désigné ; ne pas déclencher d'action destructive |
| Notification d'abus du provider/requête de compte ou alerte du SOC | détection, mauvaise configuration ou trafic hors périmètre | arrêter l'activité et lancer le processus de deconfliction/incident |
| Sentinel credential consulté | quelqu'un a lu un secret leurre sans privilège, unique à ce nœud | révoquer l'identité réelle de l'appareil et préserver la trace d'alerte |

Un sentinel credential ne doit accorder **aucun accès**, appeler uniquement un service d'alerte détenu par l'organisation et être déclaré dans les rules of engagement. Il s'agit d'un tripwire détectant une lecture non autorisée, et non d'une balise destinée à suivre la personne qui a trouvé l'équipement.

### Seuils d'alerte

Utilisez des règles stateful, et non une unique alerte spectaculaire indiquant que l'appareil a été « découvert » :

- **warning :** un intervalle manqué, un changement d'adresse normal ou une croissance de la file ;
- **degraded :** trois intervalles consécutifs manqués, un retard de renouvellement, une perte de l'uplink primaire ou un redémarrage répété ;
- **quarantine :** hash/boot/uplink non approuvé, credential dupliqué, utilisation du sentinel ou événement privilégié inattendu ;
- **confirmed discovery/loss :** rapport du site/controller, incohérence de l'inventaire physique, récupération de l'appareil par une personne non prévue ou escalade validée du provider/SOC.

Testez la livraison des alertes via un canal indépendant du nœud de site. Évitez d'envoyer des informations sensibles sur le client/l'appareil vers une messagerie personnelle ou des comptes push grand public.

## Runbook en cas de découverte ou de capture suspectée

1. **Arrêter :** suspendez les nouveaux jobs et les sessions opérateur. N'envoyez pas de probe pour « vérifier si vous êtes surveillé ».
2. **Mettre en quarantaine :** faites en sorte que le broker refuse l'identité de l'appareil et ses routes tout en conservant les logs existants.
3. **Révoquer :** révoquez le certificat/la clé de l'appareil, le queue token, le credential de mise à jour et tout service token à usage unique. Suspendez la SIM de l'organisation lorsqu'une perte physique est plausible.
4. **Préserver :** faites un snapshot des enregistrements du controller, de la passerelle, du provider et des alertes ; consignez l'heure fiable, l'auteur de l'action et la dernière configuration connue. N'effacez pas et n'effacez pas à distance le nœud.
5. **Notifier :** contactez le controller de l'exercice, le contact incident du client et les contacts juridiques/confidentialité définis dans l'autorisation. Si un tiers l'a trouvé, utilisez le processus de récupération convenu à l'avance.
6. **Évaluer :** supposez que chaque secret et résultat mis en cache sur le nœud est exposé. Énumérez exactement ce à quoi chaque secret pouvait donner accès et vérifiez s'il a été utilisé après l'événement suspect.
7. **Contenir en aval :** faites tourner les credentials de service concernés, invalidez les jobs en attente et inspectez les logs des cibles/providers détenus par l'organisation afin de détecter tout comportement inattendu.
8. **Récupérer en sécurité :** récupérez l'appareil uniquement par l'intermédiaire d'une personne autorisée ; photographiez-le/emballez-le, consignez la custody et acquérez les preuves forensic selon les directives du client.
9. **Reprendre avec une nouvelle identité :** ne réactivez jamais silencieusement le credential capturé. Recompilez depuis le manifest connu, corrigez la défaillance de contrôle et obtenez une approbation explicite.

Les recommandations actuelles de NIST en matière d'incident response intègrent la préparation, la détection, la réponse et la récupération dans la gestion des risques de cybersécurité à l'échelle de l'organisation ; préservez d'abord afin que le client puisse déterminer ce qui s'est passé et choisir la réponse appropriée.<sup>[[6]](#references)</sup>

## Exercice de capture avant le déploiement

Remettez une unité de test déverrouillée ou une copie de son stockage à un reviewer indépendant et demandez-lui d'énumérer :

1. les identifiants de l'appareil, du site et de l'engagement ;
2. les noms des opérateurs, les comptes personnels, les réseaux domestiques/de workstation et les contacts de récupération ;
3. les destinations et credentials du controller/broker ;
4. les profils réseau du client et les résultats mis en cache ;
5. les autres appareils/projets accessibles avec chaque secret ;
6. les credentials de valeur ou de paiement ;
7. ce que le controller peut révoquer et à quelle vitesse ;
8. l'activité qui reste attribuable depuis les logs centralisés.

Critères de réussite : zéro compte personnel/clé de workstation ; zéro autorité inter-engagement ou d'enrollment ; aucun credential de paiement ; cache chiffré borné ; une action documentée de révocation de l'appareil ; traçabilité complète côté controller. Traitez tout lien personnel inattendu ou toute capacité latérale comme un blocker de release.

## Clôture

1. Arrêtez les jobs et désactivez la route du broker à la fin du périmètre.
2. Récupérez et rapprochez l'inventaire exact ; signalez tout élément manquant.
3. Préservez les logs/résultats et, si nécessaire, une image forensic conformément au plan de rétention de l'engagement.
4. Révoquez les identités de l'appareil, de la SIM, de la queue, de la mise à jour et des services, même si le matériel a été récupéré.
5. Uniquement après la préservation/l'acceptation, assainissez ou détruisez les supports via le processus de destruction des données approuvé par le propriétaire et consignez l'achèvement. Il s'agit de gestion du cycle de vie, et non de dissimulation.
6. Supprimez les réservations NAC/DHCP du site, les routes du broker, le DNS, les rôles cloud, les règles d'alerte et les contacts temporaires.
7. Documentez la détection observée, la télémétrie manquante, le délai de mise en quarantaine et chaque artefact exposé par la capture.

## References

- [1] [NIST — Catalogue des capacités de cybersécurité des appareils IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts et workload identities à courte durée de vie](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start : Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Utiliser le logging sur les systèmes métier](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Recommandations et considérations relatives à l'incident response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
