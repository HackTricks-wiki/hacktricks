# Infrastructure offensive et évasion de l'attribution

Un opérateur obtient rarement un anonymat significatif grâce à un seul proxy. Les campagnes réelles construisent un **graphe de séparation** : l'opérateur atteint un nœud d'accès, les nœuds de traversée dissimulent ce nœud à la sortie, les redirectors protègent le véritable C2, et des noms jetables pointent vers le point d'exposition public.

Utilisez le [Catalogue des techniques d'accès anonyme à Internet](anonymous-internet-access-techniques.md) pour obtenir une vue normalisée des avantages/inconvénients, du déploiement et de la détection de chaque chemin. Cette page approfondit la composition d'une infrastructure adversaire.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La dernière adresse vue par une cible constitue donc la preuve d'un chemin, et non la preuve de l'identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d'infrastructure

| Classe | Pourquoi un acteur l'utilise | Exposition durable | Meilleur pivot du défenseur |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable et facile à reconstruire | locataire, facturation, console, connexions source et historique des images | événements du compte/control plane et fingerprint récurrent du serveur |
| VPN/Tor commercial | Grand ensemble d'adresses de sortie partagées ; aucune administration de serveur | visibilité du fournisseur/guard et timing de bout en bout | comportement de destination, preuves sur les endpoints et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | enregistrements du broker/client ; comportement de proxyware ou d'hôte infecté | impossible travel, protocoles de proxy et changement d'adresse par session |
| Serveur/routeur/IoT compromis | Emprunte la réputation et la juridiction de la victime | implant, flux de gestion et contrôleur upstream récurrent | télémétrie des appareils et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l'edge public du C2 back-end | grammaire TLS/HTTP, certificat, routage et artefacts du compte cloud | corrélation edge-to-origin et regroupement par forme des requêtes |
| Service web légitime | Se fond dans le trafic GitHub/cloud/social autorisé | token API, identifiants de tenant/objet et lignée inhabituelle des processus | processus de l'endpoint et sémantique du service/de l'API |
| Chemin physique/cellulaire/satellite | Modifie l'origine physique apparente | enregistrements RF, opérateur, abonné, appareil et localisation | éléments radio/physiques et réseau combinés |

## Réseaux de relais de type Operational relay box

Un **réseau ORB** est une flotte de proxy gérée et utilisée comme service intermédiaire. Mandiant les divise en réseaux provisioned de serveurs loués, réseaux non-provisioned de routeurs/IoT compromis et réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d'administration (ACOS) :** gère l'inventaire, les identifiants, l'état de santé et la politique de routage.
2. **Nœud d'accès/relais :** authentifie les clients ou les opérateurs ; il constitue le point d'entrée stable vers un mesh changeant.
3. **Nœuds de traversal :** un ou plusieurs systèmes loués ou compromis relaient des connexions opaques.
4. **Nœud de sortie/staging :** présente l'adresse source finale lors de la reconnaissance, de l'exploitation ou auprès des cibles C2.

Le mesh peut sélectionner les sorties selon le pays, l'ASN, la latence ou la disponibilité, et faire tourner les nœuds défaillants. Plusieurs groupes de menace peuvent louer le même réseau. Mandiant a observé qu'une adresse IPv4 pouvait rester associée à certains ORB pendant seulement 31 jours ; il recommande donc de traiter le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d'IP.<sup>[[2]](#references)</sup>

### Ce que cela offre — et ce que cela leak

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le saut précédent, mais pas nécessairement l'opérateur.
- Le service d'accès voit le client et la demande de routage. Un mesh géré indépendamment peut séparer le client des sorties, mais il crée un puissant enregistrement auprès du tiers.
- Des ports récurrents, l'ordre des handshakes, les bannières de serveur, les certificats, les fenêtres de disponibilité et les relations avec les contrôleurs peuvent révéler la flotte même lorsque les IP changent.
- Un routeur compromis dispose souvent de peu de télémétrie d'endpoint, mais son ISP possède toujours les données d'abonné et de flux ; sa saisie révèle des artefacts de l'implant et de sa configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l'organisation et conservez la carte d'attribution du contrôleur. Ne recrutez pas de proxies ouverts ni d'appareils tiers. Le [guide de lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de sauts visible par le défenseur sans victimiser un intermédiaire.
{% endhint %}

## Réseaux de proxy résidentiels et mobiles

Les services de proxy résidentiels attribuent les sessions à des adresses haut débit grand public ; les proxies mobiles sortent via des pools de NAT d'opérateurs. L'approvisionnement peut provenir d'appareils explicitement inscrits, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malware. Ces origines ne sont pas équivalentes : l'absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influencent la détection :

- **rotation par requête** produit des discontinuités rapides d'IP, d'ASN et de géographie, tandis que l'identité des couches supérieures reste stable ;
- **sticky sessions** conservent une sortie pendant quelques minutes ou quelques heures, ce qui ressemble à un abonné ordinaire ;
- les **backconnect gateways** exposent un endpoint de broker au client et sélectionnent les sorties en interne ;
- les **pools mobiles** placent de nombreux abonnés réels derrière un petit ensemble d'adresses NAT d'opérateur, ce qui rend un blocage d'IP coûteux.

Les défenseurs doivent corréler l'IP avec la session authentifiée, le fingerprint TLS/client, l'ordre HTTP, le cookie de l'appareil et le comportement. Une connexion résidentielle supposément locale, suivie d'une autre depuis un autre pays alors que toutes les caractéristiques des couches supérieures restent identiques, constitue un indicateur plus solide que la réputation seule. À l'inverse, le partage d'adresses et le handoff mobile créent une rotation légitime ; ne considérez donc jamais la classification résidentielle/proxy comme un verdict.

## Chaînes de proxy multi-hop

MITRE distingue les proxies externes des **multi-hop proxies (T1090.003)**. La propriété importante n'est pas le nombre de hops, mais la séparation des connaissances et de l'administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si une même partie exploite A et B, les logs partagés ou la synchronisation temporelle des flux peuvent permettre de reconstituer le circuit. Ajouter des VPN commerciaux séquentiels depuis le même endpoint/compte peut augmenter la latence tout en laissant des éléments communs d'identité, de paiement et de synchronisation. Tor réduit ce problème grâce à des relays sélectionnés indépendamment et à une conception client partagée, mais un réseau interactif à faible latence ne peut pas garantir une résistance à un observateur qui mesure les deux extrémités.

Les échecs courants sont le contournement via DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic de gestion qui atteint directement les relays, les activités synchronisées, la réutilisation de clés SSH et la connexion à des comptes permettant l'identification. La bonne vérification est un test de défaillance : arrêter chaque relay à tour de rôle et montrer que la charge de travail ne peut pas basculer vers un chemin en clair.

## Redirector tiers et façonnage du trafic

Un **redirector** public accepte le trafic correspondant à une grammaire spécifique à l'opération et le transmet à un serveur d'équipe protégé. Tout le reste peut être rejeté ou recevoir un contenu inoffensif.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Plusieurs niveaux limitent l’exposition : la compromission d’un domaine public ne doit pas nécessairement exposer le team server. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux edge deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins et l’ordre distinctifs des en-têtes, la taille des réponses, le comportement des redirections et les allowlists d’origine peuvent regrouper des fronts supposés sans lien.

Pour la détection, enregistrez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, examinez les combinaisons rares d’en-têtes, regroupez les corps de réponse et les empreintes TLS, puis recherchez les chevauchements de configuration dans les journaux d’audit cloud/CDN. Pour les red teams autorisées, évitez de copier une véritable marque ou de placer la collecte d’identifiants derrière un tiers sans rapport.

## Domain fronting et fronting sans domaine

Avec le **domain fronting (T1090.004)** classique, la connexion TLS annonce un domaine front autorisé dans SNI, tandis que le `Host` HTTP chiffré ou l’`authority` HTTP/2 `:authority` demande un domaine back-end différent. Un CDN coopératif effectue le routage à partir de la valeur interne. Un observateur réseau sans déchiffrement TLS voit le front ; le CDN voit les deux valeurs ainsi que l’origine. Dans les variantes sans domaine, le SNI peut être vide tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Il ne s’agit pas d’une usurpation magique : cela ne fonctionne que lorsque l’intermédiaire autorise intentionnellement ou accidentellement cette discordance et sait comment router le nom interne. Les principaux fournisseurs ont restreint le fronting inter-comptes. Encrypted ClientHello (ECH) modifie ce qu’un observateur sur le chemin peut voir, mais n’efface pas les enregistrements du CDN, de l’endpoint ou de l’application.

Les points de détection comprennent :

- l’ascendance du processus de l’endpoint et une destination inattendue pour cette application ;
- la discordance entre SNI et l’autorité HTTP lorsque l’inspection TLS est légale et disponible ;
- les journaux CDN montrant qu’un tenant/front route vers une autre autorité/origine ;
- les sessions inhabituellement longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence stables de flux chiffrés malgré la variation des domaines front.

Le lab sûr simule la discordance de routage sur un reverse proxy détenu par l’organisation ; il n’exploite pas un CDN public.

## Résolution dynamique : DDNS, DGA et fast flux

La résolution dynamique découple un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable après la modification de son adresse.
- **DGA :** l’endpoint et le controller dérivent tous deux des noms de domaine candidats à partir d’une seed temporelle ou d’une clé ; l’opérateur enregistre un petit sous-ensemble.
- **Fast flux :** un nom renvoie un ensemble changeant rapidement d’adresses compromises ou de proxy, souvent avec des TTL faibles.
- **Double flux :** les adresses des services et celles des serveurs de noms faisant autorité changent toutes deux, masquant également la couche de contrôle.

Le fast flux est un modèle de distribution de charge utilisé à des fins adverses, pas simplement « beaucoup de réponses DNS ». Des éléments plus solides combinent un TTL faible, un nombre élevé d’adresses uniques, une large dispersion d’ASN/géographique, une courte durée de vie des nœuds, un comportement applicatif répété et un historique d’enregistrement suspect. Les CDN possèdent légitimement plusieurs de ces caractéristiques. MITRE recommande de corréler le comportement DNS avec le processus et les connexions ultérieures.<sup>[[5]](#references)</sup>

Un DGA peut être détecté grâce à l’entropie lexicale, aux motifs de consonnes/chiffres, aux rafales de NXDOMAIN, aux domaines vus pour la première fois de manière synchronisée et au contexte du processus. Les DGA fondés sur des wordlists et les modèles génératifs contournent les règles d’entropie simples, ce qui rend le clustering temporel à l’échelle de la flotte et la lignée des endpoints plus importants.

## Domaines compromis et domain shadowing

Un acteur peut détourner un compte de registrar/DNS, prendre le contrôle d’un sous-domaine orphelin ou ajouter des enregistrements sous un domaine par ailleurs réputé. Le **domain shadowing** conserve l’apex légitime tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de diffusion ou de C2 changeants. Il bénéficie de l’ancienneté et de la réputation du domaine et peut contourner le blocage à l’échelle du domaine.<sup>[[6]](#references)</sup>

Les défenseurs ont besoin des journaux d’audit du registrar et du DNS faisant autorité, de la MFA, de verrous registry/registrar, d’alertes concernant les nouvelles délégations, les jetons API et les serveurs de noms, d’une surveillance de la transparence des certificats, ainsi que d’un inventaire des ressources cloud référencées par le DNS. Examinez la résolution et l’historique des certificats d’un sous-domaine indépendamment de la réputation de l’apex.

## Web services et dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans une publication, un profil, un document, un repository, un objet cloud ou un champ de blockchain légitime. Le malware récupère l’objet public, décode un domaine ou une adresse IP, puis contacte l’étape suivante. Les variantes bidirectionnelles échangent des commandes ou des fichiers via les API des services.<sup>[[7]](#references)</sup>

Cela apporte de la résilience et masque le C2 back-end à l’analyse statique des binaires. Cela crée également des identifiants stables d’objet, de tenant, de repository, d’API et de modèles d’accès. Les défenseurs devraient relier :

1. le processus qui a contacté le service ;
2. le chemin API ou l’objet exact et le hash de la réponse ;
3. l’activité de décodage ou de traitement des chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. un comportement identique ailleurs dans la flotte.

Bloquer l’ensemble de GitHub, du cloud storage ou des réseaux sociaux est rarement viable. Une politique d’egress adaptée aux services et la corrélation au niveau des processus sont plus efficaces qu’un blocage fondé uniquement sur les domaines.

## Personas, comptes et compartiments d’approvisionnement

L’anonymat de l’infrastructure échoue lorsqu’un persona, un e-mail de récupération, un téléphone, un moyen de paiement, un navigateur ou une IP d’administration relie des compartiments. Les opérations liées à des États ont développé des profils sociaux, des identités e-mail et des comptes cloud bien avant leur utilisation ; ATT&CK documente cela sous Establish Accounts (T1585), notamment avec les sous-techniques sociales, e-mail et cloud.<sup>[[8]](#references)</sup>

Un défenseur ou un enquêteur construit un graphe à partir des éléments suivants :

- heure de création et de première connexion, locale, fuseau horaire et horaires d’activité ;
- champs de récupération, appareils MFA, documents d’identité et moyens de paiement ;
- empreintes de navigateur/TLS et historique des réseaux sources ;
- réutilisation d’avatars, provenance des images, style rédactionnel et croissance du graphe social ;
- registrant de domaine, serveur de noms, certificat, identifiant analytics ou commit de repository commun ;
- actions du plan de management qui contournent l’architecture publique de relais.

Pour une red team autorisée, les personas synthétiques doivent être documentés auprès du responsable de l’exercice, utiliser des canaux de récupération/paiement appartenant à l’organisation, éviter d’usurper l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester aveugle ; l’opération ne doit pas devenir irresponsable.

## Compositions émergentes à prendre en compte dans le threat modeling

Les éléments suivants sont des **compositions pilotées par le défenseur**, et non des affirmations selon lesquelles un acteur nommé aurait déployé chacune de ces conceptions exactes. Ils combinent des primitives déjà observées et constituent des hypothèses utiles pour les purple teams.

### Tasking unidirectionnel asymétrique

Les commandes arrivent via une source publique, broadcast ou append-only, tandis que les résultats sortent par un canal sans rapport après un délai. Les exemples de primitives incluent la communication unidirectionnelle via web service et les dead drops. Cette séparation empêche un flux unique de sembler bidirectionnel et complique la corrélation simple requête/réponse.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus et les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez un processus rare lisant le même objet public, même lorsqu’aucune réponse immédiate ne suit.

### Promotion de canal multi-étapes

Une première étape discrète effectue un inventaire et ne promeut que certains systèmes vers un canal de seconde étape sans rapport. Le second endpoint, le protocole et le processus peuvent ne partager aucune infrastructure avec le premier. Cela limite l’exposition de l’infrastructure capable et est explicitement modélisé par ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** reliez `premier processus réseau -> état téléchargé/configuré -> nouveau processus ou injection -> destination sans rapport` ; ne clôturez pas l’incident après avoir bloqué le premier domaine.

### Traduction par relais interprotocoles

Différents hops traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de message queue au lieu de transmettre les paquets de manière transparente. La traduction supprime une empreinte de protocole unique de bout en bout, mais crée des gateways aux caractéristiques distinctives en matière de timing, de buffering et de conversion sémantique. Le Protocol tunneling (T1572) peut être combiné avec des proxy et de l’usurpation de service.<sup>[[11]](#references)</sup>

**Détection :** recherchez les hôtes gateway qui reçoivent un protocole et en initient un autre avec un comportement octet/temps étroitement corrélé ; comparez l’intention de l’endpoint avec le protocole effectivement transporté.

### Activation passive sur les edge devices

Au lieu d’émettre des beacons, un implant surveille le trafic atteignant déjà un routeur/VPN et ne s’active que sur une valeur magique, un motif de port source ou un token authentifié. Le trafic normal continue vers le véritable service. ATT&CK appelle cela Traffic Signaling (T1205), avec des exemples documentés concernant les network devices et les APT.<sup>[[12]](#references)</sup>

**Détection :** intégrité du firmware/des fichiers, capture de paquets bruts pendant un hunt autorisé, filtres de socket inattendus et comportement différentiel du service. L’absence d’un beacon périodique ne prouve pas qu’un edge device est sain.

### Rotation des origines serverless et éphémères

Un front conserve une identité logique stable tandis que des fonctions/conteneurs de courte durée gèrent chaque étape dans plusieurs régions/comptes. Cela réduit la durée de vie sur disque et les IP d’origine fixes, mais la création dans le plan de contrôle, l’image/layer, le rôle, le secret, l’identifiant de requête et la télémétrie de facturation deviennent le graphe durable.

**Détection :** conservez les journaux d’audit et d’invocation cloud en dehors de la workload ; regroupez les templates de déploiement, les rôles, les clés d’environnement et les relations front-origine.

### Diversité des privacy layers

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relais loué, le tasking utilise un objet public, un exit provient d’une liaison cellulaire de lab détenue par l’organisation, et l’administration utilise un autre réseau de l’organisation. Cela réduit l’intérêt de compromettre un seul fournisseur, mais augmente les risques liés à la corrélation temporelle inter-couches et aux erreurs opérationnelles.

**Détection :** construisez des chronologies de campagne à travers les capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez des transitions d’état synchronisées plutôt que des indicateurs identiques.

### Dead drops décentralisés ou fondés sur des transparency logs

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable append-only, store adressé par contenu ou flux comparable à un transparency log. L’objet public est résilient, mais son index/hash de contenu exact et le comportement de polling du client deviennent des identifiants stables.

**Détection :** enregistrez les identifiants API/objet complets et les hash des réponses ; alertez lorsqu’un processus non standard interroge des objets immuables, puis effectue un décodage ou de nouvelles connexions.

### Opérations store-and-forward différées

Un C2 interactif crée une forte corrélation temporelle. Une conception store-and-forward regroupe les tâches chiffrées et renvoie les résultats plusieurs minutes ou heures plus tard via une autre queue ou un transfert physique. Elle sacrifie la réactivité au profit d’une corrélation temporelle de bout en bout plus faible.

**Détection :** allongez les fenêtres de corrélation, modélisez l’accès périodique aux queues et examinez le staging des endpoints. Le batching déplace le signal du timing des paquets vers le comportement planifié des processus/fichiers ; il ne l’efface pas.

## Revue de conception : raisonner en observateurs

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Responsable de la conservation/légalité |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS faisant autorité/registrar | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur ordinaire peut remplir chaque colonne, l’architecture assure la dissimulation vis-à-vis de la cible, mais pas une séparation robuste. Si aucun contrôleur interne ne peut relier l’activité à un engagement, elle ne convient pas au red teaming professionnel.

## References

- [1] [MITRE ATT&CK — Acquisition d’infrastructure (T1583), Compromission d’infrastructure (T1584) et Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromission d’infrastructure : domaines (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service : Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service : One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
