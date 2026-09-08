# Architectures avancées de confidentialité réseau

La complexité n'est utile que lorsqu'elle élimine un observateur ou un mode de défaillance spécifique. Une pile de tunnels unique, une forme de paquet personnalisée, un user agent rare ou une infrastructure fréquemment renouvelée peuvent devenir une empreinte plus distinctive qu'une configuration standard utilisée par des milliers de personnes.

L'[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fournit le schéma commun `Pros`/`Cons`/`Procedure`/`Detection`. Cette page développe les architectures et les limites de confiance plus complexes.

L'objectif avancé est donc la **séparation des connaissances** : aucun composant ordinaire ne devrait posséder simultanément l'identité de l'utilisateur, la destination, le texte en clair et l'historique d'activité à long terme. Il ne s'agit pas d'invisibilité, et la collusion, une procédure légale, la compromission du endpoint ou la corrélation du trafic de bout en bout peuvent toujours reconstituer le chemin.

## Sélection de l'architecture

| Pattern | Propriété obtenue | Nouvelle confiance/défaillance | Utilisation adaptée |
|---|---|---|---|
| Standard Tor Browser | Empreinte de navigateur partagée et chemin passant par plusieurs relais | La faible latence permet la corrélation du trafic | Navigation web anonyme générale |
| Tor bridge + pluggable transport | Rend le blocage/la classification directs de Tor plus difficiles | Le bridge/transport peut toujours être détecté ; le bridge apprend la source | Réseaux censurés |
| Onion service | Masque l'IP du service ; évite l'exit ; authentifie l'identité onion | La clé onion et le endpoint du serveur deviennent des actifs critiques | Publication privée, collecte ou administration |
| Relais d'entrée et de sortie indépendants | Aucun relais unique ne voit normalement la source et la destination | Les opérateurs peuvent collaborer ; le timing traverse les deux | Applications prises en charge à haute performance |
| Oblivious HTTP | Sépare l'adresse IP source de la requête HTTP chiffrée et stateless | Nécessite la prise en charge par l'application, le relais et la gateway | Télémétrie, requêtes et soumissions sans état de session |
| Namespace de workload uniquement via VPN | Absence d'une route vers un réseau en clair imposée par le kernel | Le VPN voit toujours les deux extrémités ; l'hôte/root reste de confiance | Outils d'engagement autorisés et sortie fixe |
| Navigateur distant jetable | La destination est isolée du navigateur/endpoint local | Le fournisseur du Workspace voit l'activité et l'identité de connexion | Sites/fichiers non fiables et recherche contrôlée |
| Service interne I2P | Tunnels overlay entrants/sortants séparés ; aucun exit officiel | Écosystème plus restreint/différent ; comportement des pairs sur une longue durée | Services natifs à I2P, et non remplacement du web ordinaire |
| Mixnet/livraison asynchrone | Le délai, le regroupement et le trafic de couverture résistent à l'analyse temporelle | Latence élevée, applications et maturité limitées | Messages/tâches qui ne nécessitent pas d'interaction |

## Relais à connaissance fractionnée

Un modèle de relais à deux opérateurs peut surpasser un VPN unique pour une application spécifique :
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay est un exemple déployé : Apple gère l'ingress tandis qu'un autre fournisseur de contenu gère l'egress, de sorte qu'en temps normal aucun des deux ne voit à la fois l'adresse IP du client et la destination de navigation.<sup>[[1]](#references)</sup> Il s'agit d'un service de confidentialité Safari/DNS spécifique au produit, et non d'un réseau d'anonymat couvrant tous les appareils ; il préserve délibérément une région approximative.

Oblivious HTTP (OHTTP) standardise un modèle applicatif plus limité. Le relay voit le client et le trafic chiffré vers la gateway ; la gateway déchiffre le message HTTP, mais voit le relay et non le client. La RFC 9458 avertit que ce modèle nécessite le support volontaire du relay et de la gateway, qu'il convient surtout aux requêtes sans cookies, authentification ou état de session, et qu'il n'inclut pas l'analyse du trafic dans ses garanties.<sup>[[2]](#references)</sup>

### Liste de contrôle de conception

1. Définissez précisément les messages applicatifs à protéger ; ne proxifiez pas silencieusement des sessions web authentifiées arbitraires.
2. Utilisez, lorsque cela est possible, des organisations d'ingress et d'egress gérées indépendamment, avec une administration, des identifiants, des journaux et un contrôle juridique séparés.
3. Chiffrez la requête applicative vers la gateway afin que l'ingress ne puisse pas la lire.
4. Supprimez les en-têtes de transfert dérivés du client, les identifiants TLS et les tokens stables propres à chaque utilisateur au niveau approprié.
5. Évitez les clés, cookies ou champs de payload uniques permettant à la gateway de relier les requêtes malgré la séparation du transport.
6. Agrégez, minimisez et faites expirer les journaux des deux côtés ; documentez les risques de collusion et de divulgation forcée.
7. N'effectuez du padding ou du batching que conformément à un protocole révisé. Une mise en forme artisanale du trafic peut créer une signature unique sans empêcher la corrélation.
8. Testez avec des requêtes canary contrôlées et comparez ce que consignent respectivement le client, l'ingress, la gateway et la cible.

Pour la navigation interactive ordinaire, utilisez Tor Browser plutôt que d'inventer un proxy OHTTP privé. OHTTP protège une transaction applicative prise en charge, et non l'identité complète d'un navigateur.

## Appliquer la route par workload

Un kill switch basé uniquement sur des routes d'hôte modifiables peut échouer lors du renouvellement DHCP, de la mise en veille/réactivation, de changements IPv6 ou d'un crash du tunnel. Un modèle Linux plus robuste ne donne à un conteneur ou à un network namespace qu'une interface loopback et une interface de tunnel. WireGuard documente qu'une interface peut être créée dans un namespace physique, déplacée dans un namespace de workload et conserver son socket UDP chiffré dans le namespace d'origine.<sup>[[3]](#references)</sup>

### Modèle de déploiement

1. Commencez par construire cela sur un hôte jetable ou avec une console locale ; des erreurs de namespace peuvent supprimer l'accès distant.
2. Placez l'interface Ethernet/Wi-Fi physique ainsi que DHCP/supplicant dans un namespace **physical**.
3. Créez l'interface WireGuard dans ce namespace afin que son socket de transport chiffré dispose d'un accès au réseau physique.
4. Déplacez uniquement l'interface WireGuard dans le namespace **workload** et faites-en l'unique route par défaut.
5. Donnez au workload un resolver propre au namespace, accessible uniquement via le tunnel. Prenez explicitement en compte IPv6.
6. Exécutez le conteneur du navigateur ou de l'outil dans ce namespace, sans host networking, capability privilégiée, répertoire de navigateur partagé ni agent d'identifiants personnel.
7. Arrêtez le tunnel et vérifiez que le workload ne peut ni résoudre ni joindre un endpoint IPv4 ou IPv6 contrôlé.
8. Testez le roaming des endpoints, le renouvellement DHCP, la suspension/reprise et la gestion des captive portals en dehors du namespace du workload.
9. Journalisez le hash de la configuration namespace/tunnel ainsi que l'adresse d'egress approuvée pour assurer la traçabilité de l'engagement.

Cela fournit un **enforcement de route**, et non l'anonymat vis-à-vis du VPN ou du bastion d'engagement. Un hôte ou root compromis peut inspecter ou modifier les namespaces.

## Bridges Tor et pluggable transports

Les bridges sont des relays d'entrée Tor non publics. Les pluggable transports modifient le trafic du premier saut afin de compliquer le blocage simple ou la classification du protocole. Ils n'ajoutent pas de couches de relay anonymes après l'entrée et ne neutralisent pas un observateur capable d'effectuer une corrélation temporelle plus large.

| Transport | Approche du premier saut | Compromis pratique |
|---|---|---|
| **obfs4** | Rend le trafic aléatoire en apparence et résiste au probing actif | Une adresse de bridge connue peut toujours être bloquée |
| **Snowflake** | Utilise des proxies WebRTC bénévoles et de courte durée pour atteindre un bridge | Les performances varient ; des schémas broker/STUN/WebRTC existent |
| **WebTunnel** | Transporte le trafic du bridge dans un tunnel WebSocket ressemblant à HTTPS | Dépend d'un front web accessible et peut toujours être classifié |

Le Tor Project décrit Snowflake et WebTunnel comme des transports de contournement de la censure, et non comme une indistinguishabilité parfaite.<sup>[[4]](#references)</sup>

### Workflow sûr

1. Commencez par la connexion directe de Tor Browser. N'ajoutez un bridge que lorsque le blocage ou la visibilité dans le modèle d'observateur local le justifie.
2. Utilisez les transports intégrés ou les lignes de bridge obtenues via les canaux du Tor Project. Ne téléchargez pas de binaires de transport aléatoires ni de listes publiques de bridges depuis des forums.
3. Essayez l'option prise en charge la moins complexe qui se connecte de manière fiable ; consignez la raison de ce choix.
4. Gardez Tor Browser standard par ailleurs. Un bridge ne rend pas sûres les extensions personnalisées, les connexions à des comptes ou les paramètres inhabituels du navigateur.
5. Testez la reconnexion et l'exactitude de l'horloge. Ne faites pas tourner répétitivement les transports d'une manière qui envoie une séquence distinctive au même observateur local.
6. Réévaluez la situation si la censure ou la politique réseau change ; l'utilisation peut elle-même être sensible ou limitée dans certains endroits.

## Onion services comme point de rendez-vous privé

Un onion service établit des circuits Tor sortants vers des points d'introduction et des relays de rendez-vous ; il n'a donc besoin d'aucun port entrant public et n'expose pas l'IP de son serveur via le protocole onion. Le trafic client-service reste à l'intérieur de Tor et l'adresse onion authentifie la clé du service.<sup>[[5]](#references)</sup>

Pour un portail légal de réception, un dépôt privé, une interface administrative ou un dépôt de preuves d'engagement :

1. Exécutez l'application sur un hôte ou une VM dédiée et liez-la à loopback ou à un socket Unix isolé.
2. Installez Tor depuis son repository officiel et suivez la configuration officielle d'un onion service v3 ; n'utilisez jamais d'anciennes instructions v2.
3. Protégez la clé privée de l'onion service comme une clé TLS/de signature. Ne la sauvegardez que si une identité stable est requise.
4. Ajoutez l'autorisation des clients de l'onion service pour un groupe fermé et transmettez les identifiants via un canal authentifié indépendamment.<sup>[[6]](#references)</sup>
5. Empêchez l'origin de récupérer des fonts tierces, des analytics, des mises à jour ou des webhooks révélant son IP publique ou le compte de l'opérateur.
6. Implémentez également l'authentification et l'autorisation dans l'application ; la possession de l'adresse onion ne constitue pas un contrôle d'accès.
7. Appliquez les patchs, imposez des rate limits et surveillez le service sans intégrer de télémétrie tierce.
8. Depuis un contexte de test distinct, confirmez que le DNS, les e-mails, les pages d'erreur, les métadonnées de fichiers et les en-têtes de réponse ne divulguent pas l'origin.
9. Pour une utilisation red-team, indiquez le service, le propriétaire, l'objectif et l'heure d'arrêt dans le ROE. Ne l'utilisez pas pour dissimuler un C2 hors périmètre.

## Navigateur distant et workspace jetable

Un navigateur distant déplace le rendu et les contenus risqués hors de l'endpoint local et peut fournir un egress cloud propre à l'engagement. Il protège l'appareil local contre certains contenus et mécanismes de persistence ; il ne rend pas l'opérateur anonyme vis-à-vis du fournisseur du workspace. AWS, par exemple, documente la collecte de données de portail, d'identité, de politiques, de préférences et de journaux de session, même lorsque l'instance de navigateur jetable est supprimée à la fin de la session.<sup>[[7]](#references)</sup>

Utilisez un workspace contrôlé par l'organisation pour chaque engagement, limitez les téléchargements/uploads/presse-papiers, désactivez les identity providers personnels, faites transiter son egress fixe par le bastion approuvé et faites expirer le workspace après l'export des preuves. Considérez la console du fournisseur, l'IdP et l'administrateur comme des observateurs.

## I2P et overlays internes

I2P crée des tunnels entrants et sortants unidirectionnels séparés et ne dispose d'aucun exit officiel au niveau réseau ; il est principalement destiné aux services à l'intérieur d'I2P.<sup>[[8]](#references)</sup> Ce n'est pas une méthode plus rapide utilisable directement pour naviguer sur l'Internet public. Les outproxies introduisent un point de confiance, et le threat model officiel appelle explicitement à davantage de recherches et ne revendique pas une anonymité parfaite.

N'utilisez I2P que lorsque les deux extrémités le prennent intentionnellement en charge, isolez son router à longue durée de vie des applications personnelles et comprenez que les peers/réseaux locaux peuvent observer la participation à I2P. N'augmentez pas le nombre de hops et n'ajustez pas la sélection des peers sans éléments probants : des paramètres inhabituels peuvent réduire les performances et l'anonymity set.

## Opérations résistantes à la corrélation

- Préférez une configuration client commune et prise en charge à un build unique.
- Séparez les identités au niveau de l'endpoint ; aucune topologie de routage ne répare la réutilisation de comptes, de paiements, de mécanismes de récupération ou de contenus.
- Pour les tâches non interactives, préférez un protocole asynchrone révisé ou un mixnet plutôt que d'ajouter manuellement des délais ou du trafic factice.
- Évitez d'exploiter des identités supposées séparées selon un schéma synchronisé depuis le même contexte physique.
- Utilisez une gate d'export à sens unique : le contenu non fiable entre dans un renderer jetable ; seul un résultat révisé et nettoyé en sort.
- Gardez les horloges correctes pour la sécurité des protocoles, mais supprimez les timestamps précis inutiles des artefacts publiés.
- Minimisez la durée des sessions et l'infrastructure obsolète sans rotation rapide de type « fast-flux », qui est visible et nuit à la traçabilité.

## Techniques qui ne peuvent pas utiliser de tiers non impliqués

Il s'agit de techniques adverses réelles, et non de techniques imaginaires ou insignifiantes. Leurs mécanismes et leur détection sont couverts dans [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) et les [études de cas APT](government-and-apt-case-studies.md). Lors d'un exercice autorisé, reproduisez leur comportement observable avec des substituts contrôlés :

- modélisez la rotation d'egress résidentiel/mobile avec des pools de relays contrôlés, jamais avec des marchés au consentement incertain ;
- modélisez les open proxies, les routeurs compromis et les botnets avec des VM/routeurs appartenant à l'organisation ;
- modélisez les comptes cloud volés avec un tenant d'exercice désigné et une identité de victime synthétique ;
- modélisez le domain fronting sur un reverse proxy contrôlé plutôt que sur un CDN non consentant ;
- modélisez le Wi-Fi d'un tiers avec deux AP isolés appartenant au laboratoire ;
- traitez le chiffrement personnalisé, les chaînes multi-VPN et la rotation d'identifiants comme des hypothèses de test dont les flux, les comptes et les artefacts d'endpoint restent détectables.

Pour une red team autorisée, toute tentative visant à rendre le trafic moins reconnaissable doit constituer un objectif de détection explicite dans le ROE, disposer d'une cartographie d'attribution conservée par le contrôleur et inclure un mécanisme d'arrêt/deconfliction.

## Matrice de vérification

| Test | Résultat attendu | Signification d'un échec |
|---|---|---|
| Tunnel/bridge arrêté | Le workload ne dispose d'aucun chemin IPv4/IPv6/DNS direct | L'enforcement de route est incomplet |
| Journal de la cible inspecté | Seuls l'egress et l'identité applicative prévus apparaissent | Header, route ou compte leak |
| Journal de l'ingress inspecté | La source est présente ; la cible/requête en clair est absente | La séparation de confiance a échoué au niveau de l'ingress |
| Journal de l'egress inspecté | Le relay/la requête sont présents ; l'identité source est absente | La séparation de confiance a échoué au niveau de l'egress |
| Origin onion scannée de l'extérieur | Aucun service origin public n'est accessible ou lié | L'origin a leak ou est dual-homed |
| Session jetable terminée | L'état de l'instance a disparu ; les preuves approuvées sont conservées séparément | La limite de persistence a échoué |
| Recherche du contrôleur effectuée | L'activité est rapidement associée à l'engagement/à l'opérateur | La traçabilité red-team a échoué |

## References

- [1] [Apple Platform Security — sécurité d'iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routage et Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake et pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Fonctionnement des Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Paramètres avancés des Onion Services et autorisation des clients](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Chiffrement des données dans Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
