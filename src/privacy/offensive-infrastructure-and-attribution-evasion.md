# Infrastructure offensive et évasion de l'attribution

{{#include ../banners/hacktricks-training.md}}

Un opérateur obtient rarement un anonymat significatif grâce à un seul proxy. Les campagnes réelles construisent un **graphe de séparation** : l'opérateur atteint un nœud d'accès, les nœuds de transit dissimulent ce nœud à la sortie, les redirectors protègent le véritable C2, et des noms jetables pointent vers l'extrémité publique.

Consultez le [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) pour une vue normalisée des avantages/inconvénients, du déploiement et de la détection de chaque chemin. Cette page approfondit la composition d'infrastructures adverses.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La dernière adresse observée par une cible constitue donc la preuve d'un chemin, et non la preuve de l'identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d'infrastructure

| Classe | Pourquoi un acteur l'utilise | Exposition durable | Meilleur pivot du défenseur |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable et facile à reconstruire | historique du tenant, de la facturation, de la console, des connexions initiales et des images | événements du compte/control plane et fingerprint récurrent du serveur |
| VPN/Tor commercial | Grand ensemble d'adresses de sortie partagées ; aucune administration de serveur | visibilité du fournisseur/guard et timing de bout en bout | comportement de destination, preuves sur les endpoints et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | enregistrements du broker/client ; comportement de proxyware ou d'hôte infecté | déplacements impossibles, protocoles de proxy et rotation des adresses par session |
| Serveur/routeur/IoT compromis | Emprunte la réputation et la juridiction de la victime | implant, flux de gestion et contrôleur upstream récurrent | télémétrie de l'équipement et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l'edge public du C2 back-end | grammaire TLS/HTTP, certificat, routage et artefacts du compte cloud | corrélation edge-to-origin et regroupement par forme des requêtes |
| Web service légitime | Se fond dans le trafic GitHub/cloud/social autorisé | token API, identifiants de tenant/objet et lignée inhabituelle des processus | processus de l'endpoint et sémantique du service/de l'API |
| Chemin physique/cellulaire/satellite | Modifie l'origine physique apparente | enregistrements RF, opérateur, abonné, appareil et localisation | combinaison des preuves radio/physiques et réseau |

## Réseaux de relais de type Operational relay box

Un **réseau ORB** est une flotte de proxy gérée utilisée comme service intermédiaire. Mandiant les divise en réseaux provisionnés composés de serveurs loués, en réseaux non provisionnés composés de routeurs/équipements IoT compromis, et en réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d'administration (ACOS) :** gère l'inventaire, les identifiants, l'état et la politique de routage.
2. **Nœud d'accès/relais :** authentifie les clients ou les opérateurs ; il constitue le point d'entrée stable vers un mesh changeant.
3. **Nœuds de traversal :** un ou plusieurs systèmes loués ou compromis relaient des connexions opaques.
4. **Nœud de sortie/staging :** présente l'adresse source finale lors de la reconnaissance, de l'exploitation ou auprès des cibles C2.

Le mesh peut sélectionner les sorties selon le pays, l'ASN, la latence ou la disponibilité et faire tourner les nœuds défaillants. Plusieurs threat groups peuvent louer le même réseau. Mandiant a observé qu'une adresse IPv4 pouvait rester associée à certains ORB pendant seulement 31 jours ; il recommande donc de traiter le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d'IP.<sup>[[2]](#references)</sup>

### Ce que cela achète — et ce que cela leak

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le hop précédent, mais pas nécessairement l'opérateur.
- Le service d'accès voit le client et la demande de routage. Un mesh géré indépendamment peut séparer le client des sorties, mais il crée un puissant enregistrement chez la contrepartie.
- Les ports récurrents, l'ordre des handshakes, les bannières de serveur, les certificats, les fenêtres de disponibilité et les relations avec les contrôleurs peuvent révéler la flotte même lorsque les IP tournent.
- Un routeur compromis dispose fréquemment de peu de télémétrie endpoint, mais son FAI possède malgré tout les données d'abonné et de flux ; une saisie expose les artefacts de l'implant et de la configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l'organisation et conservez la cartographie d'attribution du contrôleur. Ne recrutez pas de proxies ouverts ni d'équipements tiers. Le [guide de laboratoire](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de hops visible par le défenseur sans victimiser un intermédiaire.
{% endhint %}

## Réseaux de proxy résidentiels et mobiles

Les services de proxy résidentiel attribuent les sessions à des adresses haut débit grand public ; les proxies mobiles sortent via des pools NAT d'opérateurs. L'approvisionnement peut provenir d'équipements explicitement inscrits, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malware. Ces origines ne sont pas équivalentes : l'absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influencent la détection :

- **rotation par requête** produit de rapides discontinuités d'IP, d'ASN et de géographie, tandis que l'identité des couches supérieures reste stable ;
- **sessions sticky** conservent une sortie pendant quelques minutes ou quelques heures, ce qui ressemble à un abonné ordinaire ;
- **passerelles backconnect** exposent un seul endpoint de broker au client et sélectionnent les sorties en interne ;
- **pools mobiles** placent de nombreux abonnés réels derrière un petit ensemble d'adresses NAT d'opérateur, ce qui rend un blocage IP coûteux.

Les défenseurs doivent corréler l'IP avec la session authentifiée, le fingerprint TLS/client, l'ordre HTTP, le cookie de l'appareil et le comportement. Une connexion résidentielle supposée locale suivie d'une connexion depuis un autre pays, alors que toutes les caractéristiques des couches supérieures restent identiques, constitue un indice plus solide que la réputation seule. À l'inverse, le partage d'adresses et le handoff mobile créent une rotation légitime ; il ne faut donc jamais considérer la classification résidentielle/proxy comme une conclusion définitive.

## Chaînes de proxy multi-hop

MITRE distingue les proxies externes des **proxies multi-hop (T1090.003)**. La propriété importante n'est pas le nombre de hops, mais la séparation des connaissances et de l'administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si une même partie exploite A et B, les logs partagés ou la synchronisation des flux peuvent permettre de reconstituer le circuit. Ajouter des VPN commerciaux séquentiels depuis le même endpoint/compte peut accroître la latence tout en laissant des preuves communes liées à l’identité, au paiement et au timing. Tor réduit ce problème grâce à des relais sélectionnés indépendamment et à une conception client partagée, mais un réseau interactif à faible latence ne peut pas garantir une résistance face à un observateur qui mesure les deux extrémités.

Les échecs courants sont les contournements DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic de gestion qui atteint directement les relais, les activités synchronisées, la réutilisation de clés SSH et la connexion à des comptes permettant d’identifier l’utilisateur. La vérification correcte consiste en un test de défaillance : arrêter chaque relais tour à tour et démontrer que la charge de travail ne peut pas basculer vers un chemin en clair.

## Niveaux de redirector et façonnage du trafic

Un **redirector** public accepte le trafic correspondant à une grammaire propre à l’opération et le transmet à un team server protégé. Tout le reste peut être rejeté ou recevoir du contenu inoffensif.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Plusieurs niveaux limitent l’exposition : l’abandon d’un domaine public ne doit pas nécessairement exposer le serveur de l’équipe. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux edge deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins distinctifs/l’ordre des en-têtes, les tailles de réponse, le comportement des redirections et les allowlists d’origin peuvent regrouper des fronts supposément sans lien.

Pour la détection, enregistrez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, inspectez les combinaisons rares d’en-têtes, regroupez les corps de réponse et les empreintes TLS, puis recherchez les chevauchements de configuration dans les journaux d’audit cloud/CDN. Pour les red teams autorisées, évitez de copier une vraie marque ou de placer la collecte d’identifiants derrière un tiers sans rapport.

## Domain fronting and domainless fronting

Avec le **domain fronting classique (T1090.004)**, la connexion TLS annonce un domaine front autorisé dans le SNI, tandis que le `Host` HTTP chiffré ou `:authority` HTTP/2 demande un autre domaine back-end. Un CDN coopérant route selon la valeur interne. Un observateur réseau sans déchiffrement TLS voit le front ; le CDN voit les deux valeurs ainsi que l’origin. Dans les variantes domainless, le SNI peut être vide tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Il ne s’agit pas d’une usurpation magique : cela ne fonctionne que lorsque l’intermédiaire autorise intentionnellement ou accidentellement cette discordance et sait router le nom interne. Les principaux fournisseurs ont restreint le fronting inter-comptes. Encrypted ClientHello (ECH) modifie ce qu’un observateur sur le chemin peut voir, mais n’efface pas les enregistrements du CDN, de l’endpoint ou de l’application.

Les points de détection comprennent :

- l’ascendance du processus endpoint et une destination inattendue pour cette application ;
- la discordance entre SNI et autorité HTTP lorsque l’inspection TLS est légale et disponible ;
- les journaux CDN montrant qu’un tenant/front route vers une autre autorité/un autre origin ;
- des sessions inhabituelles, longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence stables de flux chiffrés malgré la variation des domaines front.

Le lab sûr simule la discordance de routage sur un reverse proxy détenu par l’organisation ; il n’exploite pas un CDN public.

## Dynamic resolution: DDNS, DGA and fast flux

La résolution dynamique découple un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable après un changement d’adresse.
- **DGA :** l’endpoint et le contrôleur dérivent tous deux des noms de domaine candidats à partir d’une seed temporelle ou d’une clé ; l’opérateur enregistre un petit sous-ensemble.
- **Fast flux :** un nom renvoie un ensemble qui change rapidement d’adresses compromises ou de proxy, souvent avec des TTL faibles.
- **Double flux :** les adresses du service et celles des serveurs de noms faisant autorité tournent toutes deux, dissimulant également la couche de contrôle.

Le fast flux est un modèle de distribution de charge utilisé à des fins adverses, pas simplement « de nombreuses réponses DNS ». Des éléments plus solides combinent un TTL faible, un nombre élevé d’adresses uniques, une large dispersion d’ASN et de zones géographiques, une courte durée de vie des nœuds, un comportement applicatif répété et un historique d’enregistrement suspect. Les CDN possèdent légitimement plusieurs de ces propriétés. MITRE recommande de corréler le comportement DNS avec le processus et les connexions ultérieures.<sup>[[5]](#references)</sup>

Un DGA peut être détecté grâce à l’entropie lexicale, aux motifs de consonnes/chiffres, aux rafales de NXDOMAIN, aux domaines synchronisés vus pour la première fois et au contexte du processus. Les DGA fondés sur des wordlists et les modèles génératifs contournent les règles d’entropie simples, ce qui rend le clustering temporel à l’échelle de la flotte et la lineage des endpoints plus importants.

## Compromised domains and domain shadowing

Un acteur peut détourner un compte de registrar/DNS, prendre le contrôle d’un sous-domaine dangling ou ajouter des enregistrements sous un domaine par ailleurs réputé. Le **domain shadowing** préserve l’apex légitime tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de delivery ou de C2 changeants. Il tire parti de l’ancienneté et de la réputation du domaine et peut contourner le blocage à l’échelle du domaine.<sup>[[6]](#references)</sup>

Les défenseurs ont besoin des journaux d’audit du registrar et du DNS faisant autorité, de MFA, de verrous registry/registrar, d’alertes concernant les nouvelles délégations, les API tokens et les name servers, d’une surveillance de la certificate transparency, ainsi que d’un inventaire des ressources cloud référencées par le DNS. Étudiez la résolution et l’historique des certificats d’un sous-domaine indépendamment de la réputation de l’apex.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans un post, un profil, un document, un repository, un objet cloud ou un champ blockchain légitime. Le malware récupère l’objet public, décode un domaine ou une IP, puis contacte la next stage. Les variantes bidirectionnelles échangent des commandes ou des fichiers via les API des services.<sup>[[7]](#references)</sup>

Cela offre une résilience et dissimule le C2 back-end lors de l’analyse statique du binaire. Cela crée également des identifiants stables liés à l’objet, au tenant, au repository, à l’API et aux modèles d’accès. Les défenseurs doivent relier :

1. le processus qui a contacté le service ;
2. le chemin API/l’objet exact et le hash de réponse ;
3. l’activité de décodage ou de traitement de chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. un comportement identique ailleurs dans la flotte.

Bloquer entièrement GitHub, le cloud storage ou les réseaux sociaux est rarement viable. Une politique d’egress adaptée aux services et la corrélation au niveau des processus sont plus efficaces qu’un blocage limité aux domaines.

## Personas, accounts and procurement compartments

L’anonymat de l’infrastructure échoue lorsqu’un persona, un e-mail de récupération, un téléphone, un moyen de paiement, un navigateur ou une IP d’administration relie des compartiments. Les opérations liées à un État ont cultivé des profils sociaux, des identités e-mail et des comptes cloud bien avant leur utilisation ; ATT&CK répertorie cela sous Establish Accounts (T1585), y compris les sous-techniques sociales, e-mail et cloud.<sup>[[8]](#references)</sup>

Un défenseur ou un enquêteur construit un graphe à partir de :

- l’heure de création et de première connexion, la locale, le fuseau horaire et les horaires d’activité ;
- les champs de récupération, les appareils MFA, les documents d’identité et les moyens de paiement ;
- les empreintes de navigateur/TLS et l’historique des réseaux sources ;
- la réutilisation d’avatars, la provenance des images, le style rédactionnel et la croissance du graphe social ;
- un registrant de domaine, un name server, un certificat, un analytics ID ou un commit de repository partagé ;
- les actions du plan de management qui contournent l’architecture publique de relay.

Pour une red team autorisée, les personas synthétiques doivent être documentés auprès du responsable de l’exercice, utiliser des canaux de récupération/paiement détenus par l’organisation, éviter d’usurper l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester aveugle ; l’opération ne doit pas devenir impossible à attribuer.

## Emerging compound patterns to threat-model

Les éléments suivants sont des **compositions pilotées par le défenseur**, et non des affirmations selon lesquelles un acteur nommé aurait déployé chacune de ces architectures exactes. Ils combinent des primitives déjà observées et constituent des hypothèses utiles pour les purple teams.

### Asymmetric one-way tasking

Les commandes arrivent via une source publique, broadcast ou append-only, tandis que les résultats sortent par un canal sans rapport après un délai. Les primitives comprennent notamment la communication unidirectionnelle via web service et les dead drops. Cette séparation empêche un flux unique de ressembler à une communication bidirectionnelle et complique la corrélation simple requête/réponse.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus et les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez un processus rare lisant le même objet public même lorsqu’aucune réponse immédiate ne suit.

### Multi-stage channel promotion

Une première stage discrète effectue un inventaire et ne promeut que certains systèmes vers un canal de seconde stage sans rapport. Le second endpoint, le protocole et le processus peuvent ne partager aucune infrastructure avec le premier. Cela limite l’exposition de l’infrastructure capable et est explicitement modélisé sous ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** reliez `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` ; ne clôturez pas l’incident après avoir bloqué le premier domaine.

### Cross-protocol relay translation

Différents hops traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de message-queue au lieu de transférer les paquets de manière transparente. La traduction supprime une empreinte de protocole unique de bout en bout, mais crée des gateways aux caractéristiques distinctives de temporisation, de buffering et de conversion sémantique. Le protocol tunneling (T1572) peut être combiné à des proxy et à la service impersonation.<sup>[[11]](#references)</sup>

**Détection :** recherchez les hôtes gateway qui reçoivent un protocole et en initient un autre avec un comportement octet/temps étroitement corrélé ; comparez l’intention de l’endpoint avec le protocole effectivement transporté.

### Passive activation on edge devices

Au lieu d’émettre des beacons, un implant surveille le trafic atteignant déjà un routeur/VPN et ne s’active qu’à la réception d’une valeur magique, d’un motif de port source ou d’un token authentifié. Le trafic normal continue vers le service réel. ATT&CK appelle cela Traffic Signaling (T1205), avec des exemples documentés concernant les network devices et les APT.<sup>[[12]](#references)</sup>

**Détection :** contrôlez l’intégrité du firmware et des fichiers, effectuez une capture de paquets bruts lors d’un hunt autorisé, recherchez les socket filters inattendus et les différences de comportement du service. L’absence d’un beacon périodique ne prouve pas qu’un edge device est sain.

### Serverless and ephemeral origin rotation

Un front conserve une identité logique stable tandis que des functions/containers éphémères traitent chaque stage dans plusieurs régions ou comptes. Cela réduit la durée de vie sur disque et les IP d’origin fixes, mais la création dans le control plane, l’image/layer, le rôle, le secret, l’identifiant de requête et la télémétrie de facturation deviennent le graphe durable.

**Détection :** conservez les journaux d’audit cloud et d’invocation en dehors de la workload ; regroupez les templates de déploiement, les rôles, les clés d’environnement et les relations front-to-origin.

### Privacy-layer diversity

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relay loué, le tasking utilise un objet public, une sortie provient d’un lien cellulaire de lab détenu par l’organisation et l’administration utilise un réseau distinct de l’organisation. Cela réduit l’intérêt de compromettre un seul fournisseur, mais augmente les risques de corrélation temporelle entre couches et d’erreur opérationnelle.

**Détection :** construisez des timelines de campagne à partir des capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez des transitions d’état synchronisées plutôt que des indicateurs identiques.

### Decentralized or transparency-log dead drops

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable append-only, dans un stockage adressé par contenu ou dans un flux de type transparency log. L’objet public est résilient, mais son index/hash de contenu exact et le comportement de polling du client deviennent des identifiants stables.

**Détection :** enregistrez les identifiants API/objet complets et les hashes de réponse ; alertez lorsqu’un processus non standard interroge des objets immuables, suivi d’un décodage ou de nouvelles connexions.

### Delayed store-and-forward operations

Un C2 interactif crée une forte corrélation temporelle. Une architecture store-and-forward regroupe les jobs chiffrés et renvoie les résultats plusieurs minutes ou heures plus tard via une autre queue ou un transfert physique. Elle sacrifie la réactivité pour réduire la corrélation temporelle de bout en bout.

**Détection :** allongez les fenêtres de corrélation, modélisez l’accès périodique aux queues et examinez le staging côté endpoint. Le batching déplace le signal du timing des paquets vers le comportement planifié des processus/fichiers ; il ne l’efface pas.

## Design review: think in observers

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Responsable de la conservation/légalité |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de traversal | | | | | |
| sortie/redirector/CDN | | | | | |
| DNS faisant autorité/registrar | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur courant peut remplir toutes les colonnes, l’architecture assure la dissimulation vis-à-vis de la cible, mais pas une séparation robuste. Si aucun contrôleur interne ne peut relier l’activité à un engagement, elle ne convient pas au red teaming professionnel.

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
{{#include ../banners/hacktricks-training.md}}
