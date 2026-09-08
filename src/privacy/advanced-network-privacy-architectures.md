# Architectures avancées de confidentialité réseau

{{#include ../banners/hacktricks-training.md}}

La complexité n'est utile que lorsqu'elle élimine un observateur ou un mode de défaillance spécifique. Une pile de tunnels unique, une forme de paquet personnalisée, un user agent rare ou une infrastructure fréquemment renouvelée peuvent devenir une empreinte plus distinctive qu'une configuration standard utilisée par des milliers de personnes.

L'[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fournit le schéma commun `Pros`/`Cons`/`Procedure`/`Detection`. Cette page détaille les architectures plus complexes et les limites de confiance.

L'objectif avancé est donc la **séparation des connaissances** : aucun composant ordinaire ne devrait posséder simultanément l'identité de l'utilisateur, la destination, le texte en clair et l'historique d'activité à long terme. Il ne s'agit pas d'invisibilité, et la collusion, une procédure légale, la compromission de l'endpoint ou la corrélation de trafic de bout en bout peuvent toujours reconstituer le chemin.

## Sélection de l'architecture

| Pattern | Propriété obtenue | Nouvelle confiance/défaillance | Utilisation appropriée |
|---|---|---|---|
| Standard Tor Browser | Empreinte de navigateur partagée et chemin multi-relay | La faible latence permet la corrélation du trafic | Navigation web anonyme générale |
| Tor bridge + pluggable transport | Rend le blocage/la classification directe de Tor plus difficile | Le bridge/transport peut toujours être détecté ; le bridge apprend la source | Réseaux censurés |
| Onion service | Masque l'IP du service ; évite l'exit ; authentifie l'identité onion | La clé onion et l'endpoint du serveur deviennent des actifs critiques | Publication privée, collecte ou administration |
| Independent ingress + egress relays | Aucun relay unique ne voit normalement la source et la destination | Les opérateurs peuvent colluder ; le timing traverse les deux | Applications prises en charge à hautes performances |
| Oblivious HTTP | Sépare l'IP source de la requête HTTP stateless chiffrée | Nécessite la prise en charge de l'application, du relay et de la gateway | Télémétrie, requêtes et soumissions sans état de session |
| VPN-only workload namespace | Absence d'une route vers le réseau en clair imposée par le kernel | Le VPN voit toujours les deux extrémités ; l'hôte/root reste de confiance | Outils d'engagement autorisés et egress fixe |
| Disposable remote browser | La destination est isolée du navigateur/de l'endpoint local | Le fournisseur de Workspace voit l'activité et l'identité de connexion | Sites/fichiers non fiables et recherche contrôlée |
| I2P internal service | Tunnels overlay entrants/sortants séparés ; aucun exit officiel | Écosystème plus restreint/différent ; comportement des pairs de longue durée | Services natifs à I2P, et non remplacement du web ordinaire |
| Mixnet/asynchronous delivery | Le délai, le regroupement et le cover traffic résistent à l'analyse temporelle | Latence élevée, applications et maturité limitées | Messages/tâches ne nécessitant pas d'interaction |

## Relays à connaissance séparée

Un modèle de relay géré par deux opérateurs peut être plus performant qu'un VPN unique pour une application ciblée :
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
Apple Private Relay est un exemple déployé : Apple exploite l'ingress tandis qu'un autre fournisseur de contenu exploite l'egress, de sorte qu'en règle générale aucun des deux ne voit à la fois l'adresse IP du client et la destination de navigation.<sup>[[1]](#references)</sup> Il s'agit d'un service de confidentialité Safari/DNS spécifique au produit, et non d'un réseau d'anonymat couvrant tous les appareils ; il préserve délibérément une région approximative.

Oblivious HTTP (OHTTP) standardise un modèle applicatif plus limité. Le relay voit le client et le trafic chiffré vers la gateway ; la gateway déchiffre le message HTTP, mais voit le relay et non le client. La RFC 9458 avertit que ce mécanisme nécessite le support volontaire du relay et de la gateway, qu'il convient surtout aux requêtes sans cookies, authentification ou état de session, et qu'il n'offre aucune garantie contre l'analyse du trafic.<sup>[[2]](#references)</sup>

### Liste de contrôle de conception

1. Définir précisément les messages applicatifs à protéger ; ne pas mettre silencieusement en proxy des sessions web authentifiées arbitraires.
2. Utiliser, lorsque c'est possible, des organisations ingress et egress exploitées indépendamment, avec une administration, des identifiants, une journalisation et un contrôle juridique distincts.
3. Chiffrer la requête applicative à destination de la gateway afin que l'ingress ne puisse pas la lire.
4. Supprimer les en-têtes de forwarding dérivés du client, les identifiants TLS et les tokens stables par utilisateur au niveau approprié.
5. Éviter les clés uniques, cookies ou champs de payload qui permettraient à la gateway de relier les requêtes malgré la séparation du transport.
6. Agréger, minimiser et faire expirer les logs des deux côtés ; documenter les risques de collusion et de divulgation forcée.
7. N'ajouter du padding ou du batching que conformément à un protocole révisé. Le traffic shaping fait maison peut créer une signature unique sans empêcher la corrélation.
8. Tester avec des requêtes canary contrôlées et comparer ce que le client, l'ingress, la gateway et la cible enregistrent chacun.

Pour la navigation interactive ordinaire, utiliser Tor Browser plutôt que d'inventer un proxy OHTTP privé. OHTTP protège une transaction applicative prise en charge, et non l'identité complète d'un navigateur.

## Appliquer la route par workload

Un kill switch fondé uniquement sur des routes d'hôte modifiables peut échouer lors du renouvellement DHCP, de la mise en veille/réactivation, de changements IPv6 ou d'un crash du tunnel. Un modèle Linux plus robuste donne à un container ou à un network namespace uniquement une interface loopback et une interface de tunnel. WireGuard documente qu'une interface peut être créée dans un namespace physique, déplacée dans un namespace de workload, et conserver son socket UDP chiffré dans le namespace d'origine.<sup>[[3]](#references)</sup>

### Modèle de déploiement

1. Construire d'abord ce modèle sur un hôte jetable/à console locale ; des erreurs de namespace peuvent supprimer l'accès distant.
2. Placer l'interface Ethernet/Wi-Fi physique ainsi que DHCP/supplicant dans un namespace **physique**.
3. Créer l'interface WireGuard à cet endroit afin que son socket de transport chiffré dispose d'un accès au réseau physique.
4. Déplacer uniquement l'interface WireGuard dans le namespace **workload** et en faire la seule route par défaut.
5. Fournir au workload un resolver propre au namespace, accessible uniquement via le tunnel. Prendre explicitement en compte IPv6.
6. Exécuter le container du navigateur/de l'outil dans ce namespace, sans host networking, capability privilégiée, répertoire de navigateur partagé ni agent d'identifiants personnel.
7. Arrêter le tunnel et vérifier que le workload ne peut résoudre ni contacter un endpoint IPv4 ou IPv6 contrôlé.
8. Tester le roaming de l'endpoint, le renouvellement DHCP, la suspension/reprise et la gestion des captive portals en dehors du namespace du workload.
9. Journaliser le hash de configuration du namespace/tunnel ainsi que l'adresse egress approuvée pour assurer la traçabilité de l'engagement.

Cela fournit un **enforcement de route**, et non l'anonymat vis-à-vis du VPN ou du bastion d'engagement. Un hôte compromis ou le root peut inspecter ou modifier les namespaces.

## Bridges Tor et transports pluggable

Les bridges sont des relays d'entrée Tor non publics. Les transports pluggable modifient le trafic du premier saut afin de rendre plus difficile le blocage simple ou la classification du protocole. Ils n'ajoutent pas de couches de relay anonymes après l'entrée et ne résistent pas à un observateur capable d'effectuer une corrélation temporelle plus large.

| Transport | Approche du premier saut | Compromis pratique |
|---|---|---|
| **obfs4** | Rend le trafic aléatoire en apparence et résiste au probing actif | Une adresse de bridge connue peut toujours être bloquée |
| **Snowflake** | Utilise des proxies WebRTC bénévoles à courte durée de vie pour atteindre un bridge | Les performances varient ; des patterns broker/STUN/WebRTC existent |
| **WebTunnel** | Transporte le trafic du bridge dans un tunnel WebSocket semblable à HTTPS | Dépend d'un front web joignable et peut toujours être classifié |

Le Tor Project décrit Snowflake et WebTunnel comme des transports de contournement de la censure, et non comme des mécanismes d'indistinguishability parfaite.<sup>[[4]](#references)</sup>

### Workflow sûr

1. Commencer par la connexion directe de Tor Browser. Ajouter un bridge uniquement lorsque le blocage ou la visibilité dans le modèle d'observateur local le justifie.
2. Utiliser les transports intégrés ou les lignes de bridge obtenues via les canaux du Tor Project. Ne pas télécharger de binaires de transport aléatoires ni de listes publiques de bridges depuis des forums.
3. Essayer l'option prise en charge la moins complexe qui se connecte de manière fiable ; consigner la raison de ce choix.
4. Conserver Tor Browser dans sa configuration standard par ailleurs. Un bridge ne rend pas sûrs les extensions personnalisées, les connexions à des comptes ou les paramètres inhabituels du navigateur.
5. Tester la reconnexion et l'exactitude de l'horloge. Ne pas alterner répétitivement les transports d'une manière qui enverrait une séquence distinctive au même observateur local.
6. Réévaluer la situation si la censure ou la politique réseau change ; l'utilisation peut elle-même être sensible ou restreinte dans certains endroits.

## Onion services comme rendez-vous privé

Un onion service établit des circuits Tor sortants vers des points d'introduction et des relays de rendez-vous ; il n'a donc besoin d'aucun port entrant public et n'expose pas l'IP de son serveur via le protocole onion. Le trafic client-service reste à l'intérieur de Tor et l'adresse onion authentifie la clé du service.<sup>[[5]](#references)</sup>

Pour un portail légal de collecte, un repository privé, une interface d'administration ou un dépôt de preuves d'engagement :

1. Exécuter l'application sur un hôte/VM dédié et la lier à loopback ou à un socket Unix isolé.
2. Installer Tor depuis son repository officiel et suivre la configuration officielle d'un onion service v3 ; ne jamais utiliser d'instructions v2 obsolètes.
3. Protéger la clé privée de l'onion service comme une clé TLS/signature. N'en faire une sauvegarde que si une identité stable est nécessaire.
4. Ajouter l'autorisation des clients de l'onion service pour un groupe fermé et transmettre les identifiants via un canal authentifié indépendamment.<sup>[[6]](#references)</sup>
5. Empêcher l'origin de récupérer des polices tierces, des outils d'analytics, des mises à jour ou des webhooks susceptibles de révéler son IP publique ou le compte de l'opérateur.
6. Implémenter également l'authentification et l'autorisation dans l'application ; posséder l'adresse onion ne constitue pas un contrôle d'accès.
7. Appliquer les correctifs, limiter le rate et surveiller le service sans intégrer de télémétrie tierce.
8. Depuis un contexte de test distinct, confirmer que le DNS, les e-mails, les pages d'erreur, les métadonnées de fichiers et les en-têtes de réponse ne divulguent pas l'origin.
9. Pour un usage red-team, inscrire le service, son propriétaire, son objectif et son heure d'arrêt dans le ROE. Ne pas l'utiliser pour dissimuler un C2 hors périmètre.

## Navigateur distant et workspace jetable

Un navigateur distant déplace le rendu et le contenu risqué hors de l'endpoint local et peut présenter un egress cloud propre à l'engagement. Il protège l'appareil local contre certains contenus et mécanismes de persistance ; il ne rend pas l'opérateur anonyme vis-à-vis du fournisseur du workspace. AWS, par exemple, documente la collecte de données de portail, d'identité, de politiques, de préférences et de logs de session, même si l'instance de navigateur jetable est supprimée à la fin de la session.<sup>[[7]](#references)</sup>

Utiliser un workspace contrôlé par l'organisation pour chaque engagement, restreindre les téléchargements, uploads et accès au presse-papiers, désactiver les fournisseurs d'identité personnels, faire passer son egress fixe par le bastion approuvé et supprimer le workspace après l'export des preuves. Considérer la console du fournisseur, l'IdP et l'administrateur comme des observateurs.

## I2P et overlays internes

I2P construit des tunnels entrants et sortants unidirectionnels distincts et ne possède aucun exit officiel au niveau réseau ; il est principalement destiné aux services à l'intérieur d'I2P.<sup>[[8]](#references)</sup> Ce n'est pas une méthode plus rapide prête à l'emploi pour naviguer sur l'Internet public. Les outproxies introduisent un point de confiance, et le modèle de menace officiel appelle explicitement à davantage de recherche sans revendiquer un anonymat parfait.

Utiliser I2P uniquement lorsque les deux extrémités le prennent intentionnellement en charge, isoler son router persistant des applications personnelles et comprendre que les pairs/réseaux locaux peuvent observer la participation à I2P. Ne pas augmenter le nombre de hops ni régler la sélection des pairs sans éléments probants : des paramètres inhabituels peuvent réduire les performances et l'ensemble d'anonymat.

## Opérations résistantes à la corrélation

- Préférer une configuration client courante et prise en charge à un build unique.
- Séparer les identités au niveau de l'endpoint ; aucune topologie de routage ne répare la réutilisation de comptes, de paiements, de mécanismes de récupération ou de contenu.
- Pour les tâches non interactives, préférer un protocole asynchrone/mixnet révisé plutôt que d'ajouter manuellement des délais ou du trafic factice.
- Éviter d'exploiter des identités supposées distinctes selon un modèle synchronisé depuis le même contexte physique.
- Utiliser une gate d'export à sens unique : le contenu non fiable entre dans un renderer jetable ; seul un résultat révisé et nettoyé en sort.
- Conserver des horloges correctes pour la sécurité du protocole, mais supprimer les timestamps précis inutiles des artefacts publiés.
- Minimiser la durée des sessions et l'infrastructure obsolète sans rotation « fast-flux » rapide, qui est visible et nuit à la traçabilité.

## Techniques ne pouvant pas utiliser des tiers non impliqués

Il s'agit de techniques adverses réelles, et non de techniques imaginaires ou insignifiantes. Leur fonctionnement et leur détection sont décrits dans [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) et les [APT case studies](government-and-apt-case-studies.md). Lors d'un exercice autorisé, reproduire leur comportement observable avec des substituts détenus en propre :

- modéliser la rotation d'egress résidentiel/mobile avec des pools de relays contrôlés, jamais avec des marchés au consentement incertain ;
- modéliser les open proxies, routeurs compromis et botnets avec des VM/routeurs détenus en propre ;
- modéliser des comptes cloud volés avec un tenant d'exercice désigné et une identité de victime synthétique ;
- modéliser le domain fronting sur un reverse proxy détenu en propre plutôt que sur un CDN non consentant ;
- modéliser le Wi-Fi tiers avec deux AP isolés appartenant au laboratoire ;
- traiter le chiffrement personnalisé, les chaînes multi-VPN et la rotation d'identifiants comme des hypothèses de test dont les flux, comptes et artefacts d'endpoint restent détectables.

Pour une red team autorisée, toute tentative visant à rendre le trafic moins reconnaissable doit constituer un objectif de détection explicite dans le ROE, disposer d'une cartographie d'attribution conservée par le contrôleur et inclure un mécanisme d'arrêt/deconfliction.

## Matrice de vérification

| Test | Résultat attendu | Signification d'un échec |
|---|---|---|
| Tunnel/bridge arrêté | Le workload ne dispose d'aucun chemin IPv4/IPv6/DNS direct | L'enforcement de route est incomplet |
| Log de la cible inspecté | Seuls l'egress/l'identité applicative prévus apparaissent | Leak d'en-tête, de route ou de compte |
| Log de l'ingress inspecté | La source est présente ; la cible/requête en clair est absente | La séparation de confiance a échoué à l'ingress |
| Log de l'egress inspecté | Le relay/la requête sont présents ; l'identité source est absente | La séparation de confiance a échoué à l'egress |
| Origin onion analysée de l'extérieur | Aucun service d'origin public n'est joignable/associé | L'origin a fuité ou dispose de deux connexions réseau |
| Session jetable terminée | L'état de l'instance a disparu ; les preuves approuvées sont conservées séparément | La limite de persistance a échoué |
| Recherche du contrôleur exécutée | L'activité est rapidement associée à l'engagement/à l'opérateur | La traçabilité de la red team a échoué |

## References

- [1] [Sécurité des plateformes Apple — Sécurité d'iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routage et Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake et transports pluggable](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Fonctionnement des Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Paramètres avancés des Onion Services et autorisation des clients](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Chiffrement des données dans Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Modèle de menace](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
