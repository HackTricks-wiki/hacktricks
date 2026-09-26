# Infrastructure offensive et évasion de l’attribution

{{#include ../banners/hacktricks-training.md}}

Un opérateur obtient rarement un anonymat significatif à partir d’un seul proxy. Les campagnes réelles construisent un **graphe de séparation** : l’opérateur atteint un nœud d’accès, des nœuds de transit dissimulent ce nœud à la sortie, des redirectors protègent le véritable C2, et des noms jetables pointent vers le front-end public.

Utilisez le [Catalogue des techniques d’accès anonyme à Internet](anonymous-internet-access-techniques.md) pour obtenir une vue normalisée des avantages/inconvénients, du déploiement et de la détection de chaque chemin. Cette page approfondit la composition d’infrastructures adverses.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La dernière adresse vue par une cible constitue donc une preuve d’un chemin, et non la preuve de l’identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d’infrastructure

| Classe | Pourquoi un acteur l’utilise | Exposition durable | Meilleur pivot pour le défenseur |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable et facile à reconstruire | historique du tenant, de la facturation, de la console, des connexions initiales et des images | événements du compte/control plane et fingerprint récurrent du serveur |
| VPN commercial/Tor | Large ensemble d’adresses de sortie partagées ; aucune administration de serveur | visibilité du fournisseur/guard et timing de bout en bout | comportement de la destination, preuves sur les endpoints et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | données du broker/client ; comportement de proxyware ou d’hôte infecté | impossible travel, protocoles de proxy et changement d’adresse par session |
| Serveur/routeur/IoT compromis | Emprunte la réputation et la juridiction de la victime | implant, flux de gestion et contrôleur upstream récurrent | télémétrie des appareils et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l’edge public du C2 back-end | grammaire TLS/HTTP, certificat, routage et artefacts du compte cloud | corrélation edge-to-origin et regroupement par forme des requêtes |
| Service web légitime | Se fond dans le trafic GitHub/cloud/social autorisé | token d’API, identifiants du tenant/de l’objet et lignée inhabituelle des processus | processus de l’endpoint et sémantique du service/de l’API |
| Liaison physique/cellulaire/satellite | Modifie l’origine physique apparente | données RF, opérateur, abonné, appareil et localisation | combinaison des preuves radio/physiques et réseau |

## Réseaux de relais opérationnels

Un **réseau ORB** est une flotte de proxies gérée et utilisée comme service intermédiaire. Mandiant les divise en réseaux provisionnés de serveurs loués, réseaux non provisionnés de routeurs/IoT compromis et réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d’administration (ACOS) :** maintient l’inventaire, les identifiants, l’état de santé et la politique de routage.
2. **Nœud d’accès/relais :** authentifie les clients ou les opérateurs ; il constitue le point d’entrée stable vers un mesh changeant.
3. **Nœuds de traversal :** un ou plusieurs systèmes loués ou compromis relaient des connexions opaques.
4. **Nœud de sortie/staging :** présente l’adresse source finale aux cibles de reconnaissance, d’exploitation ou de C2.

Le mesh peut sélectionner les sorties selon le pays, l’ASN, la latence ou la disponibilité, et faire tourner les nœuds défaillants. Plusieurs threat groups peuvent louer le même réseau. Mandiant a observé qu’une adresse IPv4 restait associée à certains ORBs pendant seulement 31 jours ; il recommande donc de considérer le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d’IP.<sup>[[2]](#references)</sup>

### Ce que cela apporte — et ce que cela leak

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le saut précédent, mais pas nécessairement l’opérateur.
- Le service d’accès voit le client et la demande de routage. Un mesh géré indépendamment peut isoler le client des sorties, mais il crée un puissant enregistrement chez le contrepartiste.
- Les ports récurrents, l’ordre des handshakes, les server banners, les certificats, les fenêtres d’activité et les relations avec les contrôleurs peuvent révéler la flotte, même lorsque les IP tournent.
- Un routeur compromis ne dispose souvent d’aucune télémétrie d’endpoint, mais son FAI possède tout de même les données d’abonné et de flux ; une saisie révèle les artefacts de l’implant et de sa configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l’organisation et conservez la cartographie d’attribution du contrôleur. Ne recrutez pas de proxies ouverts ni d’appareils de tiers. Le [guide du lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de sauts visible par le défenseur sans victimiser un intermédiaire.
{% endhint %}

## Réseaux de proxies résidentiels et mobiles

Les services de proxies résidentiels attribuent les sessions à des adresses haut débit grand public ; les proxies mobiles sortent via les pools de NAT des opérateurs. L’offre peut provenir d’appareils explicitement inscrits, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malware. Ces origines ne sont pas équivalentes : l’absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influencent la détection :

- **rotation par requête** produit des discontinuités rapides d’IP et d’ASN/géographie, tandis que l’identité des couches supérieures reste stable ;
- **sticky sessions** maintiennent une sortie pendant quelques minutes ou quelques heures, ce qui ressemble à un abonné ordinaire ;
- **backconnect gateways** exposent un endpoint de broker au client et choisissent les sorties en interne ;
- **pools mobiles** placent de nombreux abonnés réels derrière un petit ensemble d’adresses NAT d’opérateur, ce qui rend le blocage d’une IP coûteux.

Les défenseurs doivent corréler l’IP avec la session authentifiée, le fingerprint TLS/client, l’ordre HTTP, le cookie de l’appareil et le comportement. Une connexion résidentielle supposément locale suivie d’une connexion depuis un autre pays, alors que toutes les caractéristiques des couches supérieures restent identiques, constitue un signal plus fort que la réputation seule. À l’inverse, le partage d’adresses et le handoff mobile créent une rotation légitime ; ne considérez donc jamais la classification résidentielle/proxy comme une conclusion.

### Control planes de proxyware et chevauchement des revendeurs

Ne modélisez pas un pool résidentiel comme une simple liste de sorties. L’analyse de l’écosystème IPIDEA a révélé un **control plane à deux niveaux réutilisable** : un SDK intégré envoie d’abord les métadonnées de l’appareil et de son inscription à un domaine Tier One, puis reçoit la planification ainsi que des paires IP:port `connect`/`proxy` de Tier Two. Le nœud interroge périodiquement le port connect de Tier Two pour obtenir une tâche encodée, ouvre une seconde connexion vers le port proxy associé et relaie les octets fournis vers la destination demandée. Des SDK et marques de proxy apparemment différents possédaient des domaines de découverte distincts, mais convergeaient vers une infrastructure Tier Two commune et des pools de sorties qui se chevauchaient, via une propriété commune et des relations de revendeurs.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Cela produit des pivots de hunting plus durables qu'un bloc d'IP résidentielle :<sup>[[13]](#references)</sup>

- un processus inattendu d'utilitaire, de VPN, de jeu ou d'appareil embarqué envoie un identifiant stable de l'appareil ou une clé client et reçoit une liste de serveurs changeante ;
- l'endpoint interroge une IP directe sur un port inhabituel, puis se connecte immédiatement à un autre port sur la même adresse avant d'ouvrir un nouveau socket vers une destination ;
- plusieurs marques apparentes partagent des adresses Tier Two, une grammaire de protocole, du code SDK ou un chevauchement de nœuds de sortie ;
- des applications distinctes qui contactent différents domaines Tier One reçoivent des adresses provenant du même pool Tier Two.

Ce chevauchement limite également l'attribution : voir une IP dans le pool annoncé d'un fournisseur ne permet pas d'établir quel revendeur, client ou threat actor l'a utilisée au moment pertinent. Conservez les horodatages des flux, la filiation des processus, les corps des réponses Tier One et les identifiants de tâches Tier Two.<sup>[[13]](#references)</sup> Dans un exercice autorisé, n'émulez cette hiérarchie qu'avec des endpoints appartenant à l'organisation ; n'inscrivez jamais d'appareils grand public ni de proxyware tiers.

## Chaînes de proxy multi-hop

MITRE distingue les external proxies des **multi-hop proxies (T1090.003)**. La propriété importante n'est pas le nombre de hops, mais la séparation des connaissances et de l'administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si une même partie exploite A et B, les logs partagés ou le timing des flux peuvent permettre de reconstituer le circuit. L'ajout de VPN commerciaux séquentiels depuis le même endpoint/compte peut accroître la latence tout en laissant des éléments communs liés à l'identité, au paiement et au timing. Tor réduit ce problème grâce à des relais sélectionnés indépendamment et à une conception client partagée, mais un réseau interactif à faible latence ne peut pas garantir une résistance à un observateur qui mesure les deux extrémités.

Les échecs courants sont les bypass DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic de gestion qui atteint directement les relais, les activités synchronisées, la réutilisation de clés SSH et la connexion à des comptes identifiants. La vérification correcte est un test d'échec : arrêter chaque relais à tour de rôle et montrer que la charge de travail ne peut pas basculer vers un chemin en clair.

### Effondrement du tunnel et fuite en amont

Une architecture de relais est souvent plus attribuable lorsqu'elle échoue. Unit 42 a documenté un chemin d'espionnage à plusieurs niveaux utilisant des VPS exposés aux victimes, des VPS relais, des proxies résidentiels, Tor et d'autres services proxy ; lorsqu'un tunnel était omis ou s'effondrait, l'infrastructure amont dissimulée se connectait directement aux systèmes relais et exposés aux victimes. La même enquête a également utilisé un certificat X.509 brièvement exposé sur l'infrastructure amont comme pivot entre les niveaux.<sup>[[14]](#references)</sup>

Maintenez séparés le **data plane** (`victim <-> exit`) et le **control plane** (`operator/upstream -> relay administration`). Conservez les logs d'entrée et d'authentification à chaque niveau contrôlé, l'historique des certificats et les connexions échouées de courte durée, et pas uniquement les sessions C2 réussies. Une source qui n'apparaît que pendant les pannes de relais ou qui administre directement plusieurs nœuds exposés aux victimes constitue un candidat amont plus solide qu'une sortie ordinaire, mais son ASN/sa géolocalisation reste une hypothèse, et non une preuve de l'identité d'un opérateur.

Un lab autorisé doit faire échouer la charge de travail de manière fermée. Pour une charge de travail isolée dans un network namespace Linux, la première route doit utiliser le tunnel ; après sa suppression, la requête et la recherche de route doivent toutes deux échouer plutôt que sélectionner l'uplink physique :
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Répétez le test pour le DNS et l’IPv6, ainsi qu’à chaque frontière entre relais. Si une sonde réussit, enregistrez l’interface ou l’adresse source réelle avant de corriger le policy routing ou le firewall ; cette observation constitue le leak d’attribution qu’un enquêteur verrait.

## Redirector tiers and traffic shaping

Un **redirector** public accepte le trafic correspondant à une grammaire spécifique à l’opération et le transmet à un team server protégé. Tout le reste peut être rejeté ou recevoir du contenu inoffensif.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Plusieurs niveaux limitent l’exposition : l’abandon d’un domaine public ne doit pas nécessairement exposer le team server. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux edge deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins et l’ordre distinctifs des headers, la taille des réponses, le comportement des redirections et les allowlists d’origin peuvent regrouper des fronts supposés indépendants.

Pour la détection, enregistrez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, examinez les combinaisons rares de headers, regroupez les corps de réponse et les empreintes TLS, puis recherchez les recoupements de configuration dans les journaux d’audit cloud/CDN. Pour les red teams autorisées, évitez de copier une marque réelle ou de placer une collecte d’identifiants derrière un tiers sans rapport.

## Domain fronting and domainless fronting

Avec le **domain fronting (T1090.004)** classique, la connexion TLS annonce un domaine front autorisé dans le SNI, tandis que le `Host` HTTP chiffré ou l’autorité `:authority` HTTP/2 demande un autre domaine back-end. Un CDN coopérant effectue le routage à partir de la valeur interne. Un observateur réseau sans déchiffrement TLS voit le front ; le CDN voit les deux valeurs ainsi que l’origin. Dans les variantes domainless, le SNI peut être vide tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Ce n’est pas une usurpation magique : cela ne fonctionne que lorsque l’intermédiaire autorise intentionnellement ou accidentellement cette discordance et sait comment router le nom interne. Les principaux fournisseurs ont restreint le fronting inter-comptes. L’Encrypted ClientHello (ECH) modifie ce qu’un observateur situé sur le chemin peut voir, mais n’efface pas les enregistrements du CDN, de l’endpoint ou de l’application.

Les points de détection comprennent :

- l’ascendance du processus endpoint et une destination inattendue pour cette application ;
- la discordance entre SNI et autorité HTTP lorsque l’inspection TLS est légale et disponible ;
- les journaux CDN indiquant qu’un tenant/front route vers une autre autorité/un autre origin ;
- des sessions inhabituellement longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence stables de flux chiffrés malgré la variation des domaines front.

Le lab sécurisé simule la discordance de routage sur un reverse proxy contrôlé ; il n’abuse pas d’un CDN public.

## Dynamic resolution: DDNS, DGA and fast flux

La résolution dynamique découple un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable après un changement d’adresse.
- **DGA :** l’endpoint et le controller dérivent tous deux des noms de domaine candidats à partir d’une seed temporelle ou secrète ; l’opérateur n’enregistre qu’un petit sous-ensemble.
- **Fast flux :** un nom renvoie un ensemble changeant rapidement d’adresses compromises ou de proxy, souvent avec des TTL faibles.
- **Double flux :** les adresses des services et celles des name servers faisant autorité tournent toutes deux, masquant également la couche de contrôle.

Le fast flux est un modèle de distribution de charge utilisé à des fins adverses, et pas simplement « beaucoup de réponses DNS ». Des éléments plus probants combinent un TTL faible, un nombre élevé d’adresses uniques, une large dispersion d’ASN et de zones géographiques, une courte durée de vie des nœuds, un comportement applicatif répété et un historique d’enregistrement suspect. Les CDN possèdent légitimement plusieurs de ces propriétés. MITRE recommande de corréler le comportement DNS avec le processus et les connexions ultérieures.<sup>[[5]](#references)</sup>

Un DGA peut être détecté grâce à l’entropie lexicale, aux motifs de consonnes/chiffres, aux rafales de NXDOMAIN, aux domaines synchronisés nouvellement observés et au contexte du processus. Les DGA fondés sur des wordlists et les modèles génératifs contournent les règles d’entropie simples, ce qui rend le clustering temporel à l’échelle de la flotte et la lineage des endpoints plus importants.

## Compromised domains and domain shadowing

Un acteur peut détourner un compte de registrar/DNS, prendre le contrôle d’un sous-domaine orphelin ou ajouter des enregistrements sous un domaine par ailleurs réputé. Le **domain shadowing** préserve l’apex légitime tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de diffusion ou de C2 changeants. Il bénéficie de l’ancienneté et de la réputation du domaine et peut échapper au blocage à l’échelle du domaine.<sup>[[6]](#references)</sup>

Les defenders ont besoin des journaux d’audit du registrar et du DNS faisant autorité, de la MFA, de verrous registry/registrar, d’alertes pour les nouvelles délégations/tokens API/name servers, d’une surveillance de la transparency des certificats et d’un inventaire des ressources cloud référencées par le DNS. Examinez la résolution et l’historique des certificats d’un sous-domaine indépendamment de la réputation de l’apex.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans un post, un profil, un document, un repository, un objet cloud ou un champ blockchain légitime. Le malware récupère l’objet public, décode un domaine/IP et contacte l’étape suivante. Les variantes bidirectionnelles échangent des commandes ou des fichiers via les APIs des services.<sup>[[7]](#references)</sup>

Cela assure une certaine résilience et dissimule le C2 back-end à l’analyse statique du binaire. Cela crée également des identifiants stables liés à l’objet, au tenant, au repository, à l’API et aux modèles d’accès. Les defenders devraient relier :

1. le processus qui a contacté le service ;
2. le chemin API/l’objet exact et le hash de la réponse ;
3. l’activité de décodage ou de traitement des chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. un comportement identique ailleurs dans la flotte.

Bloquer l’ensemble de GitHub, du cloud storage ou des réseaux sociaux est rarement viable. Une egress policy tenant compte des services et la corrélation au niveau du processus sont plus efficaces qu’un blocage fondé uniquement sur les domaines.

## Personas, accounts and procurement compartments

L’anonymat de l’infrastructure échoue lorsqu’un persona, un e-mail de récupération, un téléphone, un paiement, un navigateur ou une IP d’administration relie des compartiments. Les opérations liées à des États ont développé des profils sociaux, des identités e-mail et des comptes cloud bien avant leur utilisation ; ATT&CK documente cela sous Establish Accounts (T1585), notamment avec les sous-techniques sociales, e-mail et cloud.<sup>[[8]](#references)</sup>

Un defender ou un investigator construit un graphe à partir des éléments suivants :

- l’heure de création et de première connexion, la locale, le fuseau horaire et les horaires d’activité ;
- les champs de récupération, les appareils MFA, les documents d’identité et les moyens de paiement ;
- les empreintes de navigateur/TLS et l’historique des réseaux sources ;
- la réutilisation d’avatars, la provenance des images, le style rédactionnel et la croissance du graphe social ;
- un registrant de domaine, un name server, un certificat, un identifiant analytics ou un commit de repository partagé ;
- les actions du plan de gestion qui contournent l’architecture publique de relay.

Pour une red team autorisée, les personas synthétiques doivent être documentés auprès du responsable de l’exercice, utiliser des canaux de récupération/paiement appartenant à l’organisation, éviter d’usurper l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester aveugle ; l’opération ne doit pas devenir incontrôlable.

## Emerging compound patterns to threat-model

Les éléments suivants sont des **compositions guidées par le defender**, et non l’affirmation qu’un acteur nommé a déployé chacune de ces conceptions exactes. Ils combinent des primitives déjà observées et constituent des hypothèses utiles pour les purple teams.

### Asymmetric one-way tasking

Les commandes arrivent via une source publique, broadcast ou append-only, tandis que les résultats partent par un canal sans rapport après un délai. Les exemples de primitives comprennent la communication one-way via web service et les dead drops. Cette séparation empêche un flux unique de paraître bidirectionnel et complique la corrélation simple requête/réponse.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus et les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez un processus rare lisant le même objet public, même lorsqu’aucune réponse immédiate ne suit.

### Multi-stage channel promotion

Une première étape discrète effectue l’inventaire et ne promeut que certains systèmes vers un canal de deuxième étape sans rapport. Le deuxième endpoint, le protocole et le processus peuvent ne partager aucune infrastructure avec le premier. Cela limite l’exposition de l’infrastructure capable et est explicitement modélisé par ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** reliez `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` ; ne clôturez pas l’incident après avoir bloqué le premier domaine.

### Cross-protocol relay translation

Différents hops traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de message-queue au lieu de transférer les paquets de manière transparente. La traduction supprime une empreinte de protocole unique de bout en bout, mais crée des gateways aux caractéristiques distinctives de timing, de buffering et de conversion sémantique. Le protocol tunneling (T1572) peut être combiné à des proxy et à l’imitation de services.<sup>[[11]](#references)</sup>

**Détection :** recherchez les gateways qui reçoivent un protocole et en initient un autre avec un comportement d’octets/temps étroitement couplé ; comparez l’intention de l’endpoint au protocole effectivement transporté.

### Passive activation on edge devices

Au lieu d’émettre des beacons, un implant surveille le trafic atteignant déjà un routeur/VPN et ne s’active que sur une valeur magique, un motif de port source ou un token authentifié. Le trafic normal continue vers le véritable service. ATT&CK appelle cela Traffic Signaling (T1205), avec des exemples documentés sur des network devices et liés à des APT.<sup>[[12]](#references)</sup>

**Détection :** intégrité du firmware/des fichiers, capture de paquets bruts pendant un hunt autorisé, filtres de socket inattendus et comportement différentiel du service. L’absence d’un beacon périodique ne prouve pas qu’un edge device est sain.

### Serverless and ephemeral origin rotation

Un front conserve une identité logique stable tandis que des fonctions/containers éphémères traitent les étapes individuelles dans plusieurs régions/comptes. Cela réduit la durée de vie sur disque et le nombre d’IPs d’origin fixes, mais la création dans le plan de contrôle, l’image/layer, le rôle, le secret, l’identifiant de requête et la télémétrie de facturation deviennent le graphe durable.

**Détection :** conservez les journaux d’audit et d’invocation cloud en dehors du workload ; regroupez les templates de déploiement, les rôles, les clés d’environnement et les relations front-to-origin.

### Privacy-layer diversity

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relay loué, le tasking utilise un objet public, un exit provient d’une liaison cellulaire de lab contrôlée et l’administration utilise un réseau distinct de l’organisation. Cela réduit l’intérêt de compromettre un seul fournisseur, mais augmente les risques liés au timing inter-couches et aux erreurs opérationnelles.

**Détection :** construisez des timelines de campagne couvrant les capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez des transitions d’état synchronisées plutôt que des indicateurs identiques.

### Decentralized or transparency-log dead drops

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable append-only, store content-addressed ou flux de type transparency log. L’objet public est résilient, mais son index/hash de contenu exact et le comportement de polling du client deviennent des identifiants stables.

**Détection :** enregistrez les identifiants complets d’API/d’objet et les hashes de réponse ; alertez sur les processus non standard qui interrogent des objets immuables, suivis d’un décodage ou de nouvelles connexions.

### Delayed store-and-forward operations

Un C2 interactif crée une forte corrélation temporelle. Une conception store-and-forward regroupe les jobs chiffrés et renvoie les résultats plusieurs minutes ou heures plus tard via une autre queue ou un transfert physique. Elle sacrifie la réactivité au profit d’un timing de bout en bout plus faible.

**Détection :** allongez les fenêtres de corrélation, modélisez l’accès périodique aux queues et examinez le staging des endpoints. Le batching déplace le signal du timing des paquets vers le comportement planifié des processus/fichiers ; il ne l’efface pas.

## Design review: think in observers

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Responsable de la conservation/aspects légaux |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS faisant autorité/registrar | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur ordinaire peut remplir chaque colonne, l’architecture assure une dissimulation vis-à-vis de la cible, mais pas une séparation robuste. Si aucun controller interne ne peut relier l’activité à un engagement, elle ne convient pas au red teaming professionnel.

## References

- [1] [MITRE ATT&CK — Acquérir une infrastructure (T1583), compromettre une infrastructure (T1584) et Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromettre une infrastructure : domaines (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service : Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service : One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Perturber le plus grand réseau de proxy résidentiel au monde](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Les campagnes de l’ombre : révéler l’espionnage mondial](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
