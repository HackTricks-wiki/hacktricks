# Infrastructure offensive et évasion de l’attribution

{{#include ../banners/hacktricks-training.md}}

Un opérateur obtient rarement un anonymat significatif avec un seul proxy. Les campagnes réelles construisent un **graphe de séparation** : l’opérateur atteint un nœud d’accès, des nœuds de transit masquent ce nœud à la sortie, des redirectors protègent le véritable C2 et des noms jetables pointent vers le point d’entrée public.

Consultez le [catalogue des techniques d’accès anonyme à Internet](anonymous-internet-access-techniques.md) pour une vue normalisée des avantages et inconvénients, du déploiement et de la détection de chaque chemin. Cette page approfondit la composition d’infrastructures adverses.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La dernière adresse vue par une cible est donc la preuve d’un chemin, et non la preuve de l’identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d’infrastructure

| Classe | Pourquoi un acteur l’utilise | Exposition durable | Meilleur pivot pour le défenseur |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable, facile à reconstruire | Locataire, facturation, console, historique des connexions source et des images | Événements du compte/plan de contrôle et empreinte serveur récurrente |
| VPN commercial/Tor | Large ensemble de sorties partagées ; aucune administration de serveur | Visibilité du fournisseur/de l’opérateur et chronologie de bout en bout | Comportement de destination, preuves sur l’endpoint et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | Données du courtier/client ; comportement de proxyware ou d’hôte infecté | Déplacements impossibles, protocoles de proxy et changement d’adresse par session |
| Serveur/routeur/IoT compromis | Emprunte la réputation et la juridiction de la victime | Implant, flux de gestion et contrôleur amont récurrent | Télémétrie des appareils et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l’edge public du C2 back-end | Artefacts de grammaire TLS/HTTP, certificat, routage et compte cloud | Corrélation edge-origine et regroupement par forme de requête |
| Service Web légitime | Se fond dans le trafic autorisé de GitHub/cloud/réseaux sociaux | Token API, identifiants de locataire/objet et lignée inhabituelle des processus | Processus sur l’endpoint et sémantique du service/de l’API |
| Chemin physique/cellulaire/satellite | Modifie l’origine physique apparente | Données RF, opérateur, abonné, appareil et localisation | Preuves radio/physiques et réseau combinées |

## Réseaux opérationnels de relais

Un **réseau ORB** est une flotte de proxy gérée et utilisée comme service intermédiaire. Mandiant les répartit en réseaux provisionnés de serveurs loués, réseaux non provisionnés de routeurs/IoT compromis et réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d’administration (ACOS) :** gère l’inventaire, les identifiants, l’état de fonctionnement et la politique de routage.
2. **Nœud d’accès/relais :** authentifie les clients ou les opérateurs ; c’est le point d’entrée stable d’un maillage changeant.
3. **Nœuds de transit :** un ou plusieurs systèmes loués ou compromis relaient les connexions opaques.
4. **Nœud de sortie/de staging :** présente l’adresse source finale aux cibles de reconnaissance, d’exploitation ou de C2.

Le maillage peut sélectionner les sorties par pays, ASN, latence ou disponibilité et remplacer les nœuds défaillants. Plusieurs groupes de menace peuvent louer le même réseau. Mandiant a observé que certaines adresses IPv4 restaient associées à certains ORB pendant seulement 31 jours ; l’organisation recommande donc de traiter le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d’IP.<sup>[[2]](#references)</sup>

### Ce que cela apporte — et ce que cela révèle

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le saut précédent, mais pas nécessairement l’opérateur.
- Le service d’accès voit le client et la requête de routage. Un maillage géré indépendamment peut séparer le client des sorties, mais cela crée des traces importantes chez un tiers.
- La récurrence des ports, l’ordre des handshakes, les bannières serveur, les certificats, les plages de disponibilité et les relations entre contrôleurs peuvent révéler la flotte même lorsque les IP changent.
- Un routeur compromis ne fournit souvent aucune télémétrie d’endpoint, mais son FAI conserve les données d’abonné et de flux ; une saisie révèle des artefacts d’implant/configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l’organisation et conservez la cartographie d’attribution du contrôleur. Ne recrutez pas de proxies ouverts ni d’appareils tiers. Le [guide de laboratoire](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de sauts visible par les défenseurs sans victimiser un intermédiaire.
{% endhint %}

## Réseaux de proxy résidentiel et mobile

Les services de proxy résidentiel attribuent les sessions à des adresses de connexions haut débit grand public ; les proxies mobiles sortent par des pools de NAT d’opérateurs. L’approvisionnement peut provenir d’appareils inscrits explicitement, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malware. Ces origines ne sont pas équivalentes : l’absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influent sur la détection :

- **rotation par requête** : provoque des discontinuités rapides d’IP et d’ASN/de géographie alors que l’identité de couche supérieure reste stable ;
- **sessions persistantes** : conservent une sortie pendant plusieurs minutes ou heures, ce qui ressemble à un abonné ordinaire ;
- **passerelles backconnect** : exposent un point de terminaison du courtier au client et choisissent les sorties en interne ;
- **pools mobiles** : regroupent de nombreux abonnés réels derrière un petit nombre d’adresses NAT d’opérateur, ce qui rend le blocage d’IP coûteux.

Les défenseurs devraient corréler l’IP avec la session authentifiée, l’empreinte TLS/client, l’ordre HTTP, le cookie de l’appareil et le comportement. Une connexion supposément locale depuis une adresse résidentielle, suivie d’une autre depuis un autre pays alors que toutes les caractéristiques de couche supérieure restent identiques, est un indice plus probant que la réputation seule. À l’inverse, le partage d’adresses et le changement de relais mobile entraînent des variations légitimes ; ne considérez donc jamais la classification résidentielle/proxy comme un verdict.

### Plans de contrôle de proxyware et chevauchement des revendeurs

Ne modélisez pas un pool résidentiel comme une simple liste de sorties. L’analyse de l’écosystème IPIDEA a révélé un **plan de contrôle réutilisable à deux niveaux** : un SDK intégré signale d’abord les métadonnées de l’appareil/de l’inscription à un domaine Tier One, puis reçoit des paires IP:port `connect`/`proxy` de Tier Two pour l’ordonnancement. Le nœud interroge périodiquement le port de connexion Tier Two à la recherche d’une tâche encodée, ouvre une deuxième connexion au port proxy associé et relaie les octets fournis vers la destination demandée. Des SDK et des marques de proxy nominalement différents avaient des domaines de découverte distincts, mais convergeaient vers une infrastructure Tier Two partagée et des pools de sortie qui se chevauchaient, en raison de propriétaires communs et de relations de revente.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Cela produit des pivots de chasse plus durables qu’un bloc d’adresses IP résidentielles :<sup>[[13]](#references)</sup>

- un processus inattendu d’utilitaire, de VPN, de jeu ou d’appareil intégré envoie un ID d’appareil/une clé client stable et reçoit une liste de serveurs qui change ;
- le point de terminaison interroge une adresse IP directe sur un port inhabituel, puis se connecte à un autre port sur la même adresse juste avant d’ouvrir une socket vers une nouvelle destination ;
- plusieurs marques apparentes partagent des adresses Tier Two, une grammaire de protocole, du code SDK ou des nœuds de sortie communs ;
- des applications distinctes qui contactent différents domaines Tier One reçoivent des adresses provenant du même pool Tier Two.

Ce chevauchement limite également l’attribution : voir une adresse IP dans le pool annoncé d’un fournisseur ne permet pas d’établir quel revendeur, client ou acteur de la menace l’a utilisée à ce moment-là. Conservez les horodatages des flux, la filiation des processus, les corps des réponses Tier One et les identifiants de tâche Tier Two.<sup>[[13]](#references)</sup> Dans le cadre d’un exercice autorisé, émulez cette hiérarchie uniquement avec des points de terminaison appartenant à l’organisation ; n’inscrivez jamais d’appareils grand public ni de proxyware tiers.

## Chaînes de proxy multi-hop

MITRE distingue les external proxies des **multi-hop proxies (T1090.003)**. La propriété importante n’est pas le nombre de sauts, mais la séparation des connaissances et de l’administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si une même partie exploite A et B, les journaux partagés ou la synchronisation des flux peuvent permettre de reconstituer le circuit. Ajouter des VPN commerciaux en série depuis le même point de terminaison/compte peut accroître la latence tout en laissant des traces communes d’identité, de paiement et de synchronisation. Tor réduit ce problème grâce à des relais sélectionnés indépendamment et à une architecture cliente partagée, mais un réseau interactif à faible latence ne peut pas garantir de résister à un observateur qui mesure les deux extrémités.

Les défaillances courantes sont les fuites DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic d’administration qui atteint directement les relais, les activités synchronisées, la réutilisation de clés SSH et la connexion à des comptes identifiants. La bonne méthode de vérification est un test de défaillance : arrêter chaque relais à tour de rôle et montrer que la charge de travail ne peut pas basculer vers une voie en clair.

### Effondrement du tunnel et fuite vers l’amont

Une architecture de relais est souvent plus facile à attribuer lorsqu’elle échoue. Unit 42 a documenté un chemin d’espionnage à plusieurs niveaux utilisant des VPS exposés aux victimes, des VPS relais, des proxys résidentiels, Tor et d’autres services proxy ; lorsqu’un tunnel était omis ou s’effondrait, l’infrastructure amont dissimulée se connectait directement aux systèmes relais et aux systèmes exposés aux victimes. La même enquête a également utilisé un certificat X.509 brièvement exposé sur l’infrastructure amont comme pivot entre les niveaux.<sup>[[14]](#references)</sup>

Séparez le **plan de données** (`victim <-> exit`) du **plan de contrôle** (`operator/upstream -> relay administration`). Conservez les journaux d’ingress et d’authentification à chaque niveau que vous contrôlez, l’historique des certificats et les connexions infructueuses de courte durée — pas seulement les sessions C2 réussies. Une source qui n’apparaît que pendant les pannes de relais ou qui administre directement plusieurs nœuds exposés aux victimes constitue un candidat amont plus solide qu’un exit ordinaire, mais son ASN et sa géolocalisation restent des hypothèses, pas des preuves de l’identité d’un opérateur.

Dans un laboratoire autorisé, la charge de travail doit échouer en mode fermé. Pour une charge de travail isolée dans un espace de noms réseau Linux, la première route doit emprunter le tunnel ; après son retrait, la requête et la recherche de route doivent échouer au lieu de sélectionner la liaison physique vers l’extérieur :

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Répétez le test pour le DNS et l’IPv6, ainsi qu’à chaque relais. Si une sonde réussit, relevez l’interface et l’adresse source réelles avant de corriger le routage par stratégie ou le pare-feu ; c’est cette observation qui constitue la fuite d’attribution qu’un enquêteur verrait.

## Niveaux de redirectors et façonnage du trafic

Un **redirector** public accepte le trafic conforme à une grammaire propre à l’opération et le transmet à un team server protégé. Tout le reste peut être rejeté ou recevoir un contenu anodin.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Plusieurs niveaux limitent l’exposition : brûler un domaine public ne doit pas nécessairement exposer le serveur de l’équipe. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux de périphérie deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins distinctifs, l’ordre des en-têtes, la taille des réponses, le comportement des redirections et les listes d’autorisation des origines peuvent regrouper des fronts prétendument sans lien.

Pour la détection, consignez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, examinez les combinaisons d’en-têtes rares, regroupez les corps de réponse et les empreintes TLS, et recherchez les recoupements de configuration dans les journaux d’audit du cloud/CDN. Pour les red teams autorisées, évitez de copier une marque réelle ou de placer la collecte d’identifiants derrière un tiers sans rapport.

## Domain fronting et domainless fronting

Avec le **domain fronting (T1090.004)** classique, la connexion TLS annonce un domaine front autorisé dans SNI tandis que le `Host` HTTP ou `:authority` HTTP/2 chiffré demande un autre domaine back-end. Un CDN coopératif effectue le routage selon la valeur interne. Un observateur réseau sans déchiffrement TLS voit le front ; le CDN voit les deux valeurs et l’origine. Dans les variantes domainless, SNI peut être vide tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Ce n’est pas une usurpation magique : cela ne fonctionne que si l’intermédiaire autorise intentionnellement ou accidentellement cette discordance et sait router le nom interne. Les principaux fournisseurs ont restreint le fronting entre comptes. Encrypted ClientHello (ECH) modifie ce qu’un observateur sur le chemin peut voir, mais n’efface pas les enregistrements du CDN, du point de terminaison ni de l’application.

Les points de détection comprennent :

- la filiation des processus du point de terminaison et une destination inattendue pour cette application ;
- une discordance entre SNI et l’autorité HTTP lorsque l’inspection TLS est légale et disponible ;
- les journaux CDN montrant qu’un tenant/front achemine vers une autre autorité/origine ;
- des sessions inhabituellement longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence de flux chiffrés stables malgré des domaines front différents.

Un laboratoire sûr simule la discordance de routage sur un reverse proxy détenu par l’organisation ; il n’abuse pas d’un CDN public.

## Résolution dynamique : DDNS, DGA et fast flux

La résolution dynamique dissocie un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable après un changement d’adresse.
- **DGA :** le point de terminaison et le contrôleur dérivent des noms de domaine candidats à partir d’une graine temporelle/clé ; l’opérateur enregistre un petit sous-ensemble.
- **Fast flux :** un nom renvoie un ensemble d’adresses compromises/de proxy qui change rapidement, souvent avec de faibles TTL.
- **Double flux :** les adresses du service et celles des serveurs de noms faisant autorité changent toutes deux, masquant également la couche de contrôle.

Le fast flux est un modèle de distribution de charge utilisé à des fins adverses, et pas simplement « de nombreuses réponses DNS ». Des éléments plus probants combinent un TTL faible, un nombre élevé d’adresses uniques, une large dispersion entre ASN et zones géographiques, une courte durée de vie des nœuds, un comportement applicatif récurrent et un historique d’enregistrement suspect. Les CDN présentent légitimement plusieurs de ces propriétés. MITRE recommande de corréler le comportement DNS avec le processus et les connexions ultérieures.<sup>[[5]](#references)</sup>

Un DGA peut être détecté à l’aide de l’entropie lexicale, des motifs de consonnes/chiffres, des rafales de NXDOMAIN, des domaines synchronisés vus pour la première fois et du contexte du processus. Les DGA fondés sur des listes de mots et les modèles génératifs contournent les règles simples basées sur l’entropie ; le regroupement temporel à l’échelle de la flotte et la filiation des points de terminaison deviennent donc plus importants.

## Domaines compromis et domain shadowing

Un acteur peut détourner un compte de registrar/DNS, prendre le contrôle d’un sous-domaine abandonné ou ajouter des enregistrements sous un domaine par ailleurs réputé. Le **domain shadowing** préserve le domaine apex légitime tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de distribution ou C2 changeants. Il emprunte l’ancienneté et la réputation du domaine et peut échapper au blocage de l’ensemble du domaine.<sup>[[6]](#references)</sup>

Les défenseurs ont besoin des journaux d’audit du registrar et du DNS faisant autorité, de MFA, de verrous au niveau du registre/registrar, d’alertes concernant les nouvelles délégations, les jetons API et les serveurs de noms, d’une surveillance de la transparence des certificats et d’un inventaire des ressources cloud référencées par DNS. Examinez indépendamment de la réputation du domaine apex la résolution et l’historique des certificats d’un sous-domaine.

## Services Web et dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans une publication, un profil, un document, un dépôt, un objet cloud ou un champ de blockchain légitime. Le malware récupère l’objet public, décode un domaine/IP et contacte l’étape suivante. Les variantes bidirectionnelles échangent des commandes ou des fichiers par l’intermédiaire des API de services.<sup>[[7]](#references)</sup>

Une variante de resolver propre à GitHub utilise l’API de recherche Issues uniquement lorsqu’un canal de dépôt authentifié échoue. Le client recherche les issues correspondant à la date du jour, au dépôt et au type d’issue, suit l’URL des commentaires de chaque issue et extrait le texte chiffré situé entre les marqueurs `<!--` et `-->`. Après déchiffrement propre à chaque hôte et dérivé de la date, des champs tels que `Owner`, `LicRepo` et `LicToken` remplacent le propriétaire du dépôt principal, le chemin et le jeton. L’opérateur peut ainsi renouveler les identifiants et les points de terminaison sans remplacer le client ; le commentaire de l’issue sert de resolver, tandis que les fichiers du dépôt restent le canal de tasking.<sup>[[15]](#references)</sup>

Une variante Android sélectionne au démarrage l’une de deux pages Telegram publiques et extrait le texte chiffré situé entre deux occurrences d’un marqueur intégré à l’APK. Elle décode la valeur en Base64URL et la déchiffre avec AES-128-CBC : les 16 premiers octets de `SHA-256(marker)` sont la clé et les 16 suivants sont le IV. Le texte en clair est l’URL de base C2 réelle, et non l’URL de la page Telegram. Pour reproduire la résolution, conservez le contenu de la page et le marqueur exact ; modifier la page publique renouvelle le point de terminaison sans reconstruire l’APK.<sup>[[16]](#references)</sup>

Cela apporte de la résilience et masque le C2 back-end à l’analyse statique des binaires. Cela crée aussi des identifiants stables liés aux objets, tenants, dépôts, API et habitudes d’accès. Les défenseurs devraient corréler :

1. le processus qui a contacté le service ;
2. le chemin API/objet exact et le hash de la réponse ;
3. l’activité de décodage ou de traitement de chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. un comportement identique ailleurs dans la flotte.

Bloquer GitHub, le stockage cloud ou les réseaux sociaux dans leur intégralité est rarement viable. Une politique de sortie tenant compte des services et une corrélation au niveau des processus sont plus efficaces que le blocage par domaine seul.

## Personas, comptes et compartiments d’approvisionnement

L’anonymat de l’infrastructure échoue lorsqu’un persona, une adresse e-mail de récupération, un numéro de téléphone, un paiement, un navigateur ou une IP d’administration relie des compartiments. Les opérations liées à des États ont créé des profils sociaux, des identités de messagerie et des comptes cloud bien avant leur utilisation ; ATT&CK répertorie cela sous Establish Accounts (T1585), avec des sous-techniques concernant les réseaux sociaux, la messagerie et le cloud.<sup>[[8]](#references)</sup>

Un défenseur ou un enquêteur établit un graphe à partir des éléments suivants :

- la date de création et de première connexion, la langue, le fuseau horaire et les horaires d’activité ;
- les champs de récupération, les appareils MFA, les documents d’identité et les moyens de paiement ;
- les empreintes de navigateur/TLS et l’historique des réseaux sources ;
- la réutilisation d’avatars, la provenance des images, le style rédactionnel et l’évolution du graphe social ;
- le registrar de domaine, le serveur de noms, le certificat, l’identifiant analytique ou le commit de dépôt partagés ;
- les actions du plan de gestion qui contournent l’architecture de relais public.

Pour une red team autorisée, les personas synthétiques doivent être documentés auprès du responsable de l’exercice, utiliser des canaux de récupération/paiement appartenant à l’organisation, éviter d’usurper l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester dans l’ignorance ; l’opération ne doit pas devenir impossible à attribuer.

## Motifs composites émergents à modéliser comme menaces

Les compositions suivantes sont des **combinaisons conçues du point de vue de la défense**, et non des affirmations selon lesquelles un acteur nommé aurait déployé chacune de ces conceptions précises. Elles combinent des primitives déjà observées et constituent des hypothèses utiles pour les équipes purple.

### Tasking unidirectionnel asymétrique

Les commandes arrivent par une source publique, diffusée ou en ajout seulement, tandis que les résultats repartent par un canal sans rapport, après un délai. Les primitives comprennent notamment la communication unidirectionnelle par service Web et les dead drops. Cette séparation empêche un flux unique de paraître bidirectionnel et complique la corrélation simple des requêtes et réponses.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus avec les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez un processus rare qui lit le même objet public même lorsqu’aucune réponse immédiate ne suit.

### Promotion multi-étape des canaux

Une première étape discrète effectue l’inventaire et ne promeut que certains systèmes vers un canal de seconde étape sans rapport. Le deuxième point de terminaison, le protocole et le processus peuvent n’avoir aucune infrastructure en commun avec le premier. Cela limite l’exposition d’une infrastructure plus puissante et est explicitement modélisé par ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** corrélez `premier processus réseau -> état téléchargé/configuré -> nouveau processus ou injection -> destination sans rapport` ; ne clôturez pas l’incident après avoir bloqué le premier domaine.

### Traduction de relais entre protocoles

Les différents sauts traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de file de messages au lieu de transférer les paquets de manière transparente. La traduction élimine une empreinte de protocole unique de bout en bout, mais crée des passerelles aux caractéristiques distinctives en matière de minutage, de mise en mémoire tampon et de conversion sémantique. Le tunneling de protocole (T1572) peut être associé à des proxies et à l’usurpation de service.<sup>[[11]](#references)</sup>

**Détection :** recherchez les hôtes passerelles qui reçoivent un protocole et en lancent un autre, avec des comportements étroitement liés en volume et en temps ; comparez l’intention du point de terminaison au protocole réellement transporté.

### Activation passive sur des appareils de périphérie

Au lieu d’émettre des balises, un implant surveille le trafic qui atteint déjà un routeur/VPN et ne s’active qu’en présence d’une valeur magique, d’un motif de port source ou d’un jeton authentifié. Le trafic normal continue vers le véritable service. ATT&CK appelle cela Traffic Signaling (T1205), avec des exemples documentés concernant des appareils réseau et des APT.<sup>[[12]](#references)</sup>

**Détection :** vérifiez l’intégrité du firmware/des fichiers, capturez les paquets bruts lors d’une investigation autorisée, recherchez les filtres de socket inattendus et comparez le comportement du service. L’absence de balise périodique ne prouve pas qu’un appareil de périphérie est sain.

### Rotation d’origines serverless et éphémères

Un front conserve une identité logique stable tandis que des fonctions/conteneurs de courte durée prennent en charge chaque étape dans plusieurs régions/comptes. Cela réduit la durée de vie des données sur disque et le nombre d’IP d’origine fixes, mais les données de télémétrie liées à la création dans le plan de contrôle, à l’image/aux couches, au rôle, au secret, à l’ID de requête et à la facturation deviennent le graphe durable.

**Détection :** conservez les journaux d’audit cloud et d’invocation en dehors de la charge de travail ; regroupez les modèles de déploiement, les rôles, les clés d’environnement et les relations entre fronts et origines.

### Diversité des couches de confidentialité

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relais loué, le tasking utilise un objet public, une sortie provient d’une liaison cellulaire de laboratoire détenue par l’organisation et l’administration utilise un réseau distinct de l’organisation. Cela réduit l’intérêt de compromettre un seul fournisseur, mais augmente les risques liés au minutage inter-couches et aux erreurs opérationnelles.

**Détection :** établissez des chronologies de campagne à partir des capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez les transitions d’état synchronisées plutôt que des indicateurs identiques.

### Dead drops décentralisés ou dans des journaux de transparence

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable en ajout seulement, magasin adressé par contenu ou flux de type journal de transparence. L’objet public est résilient, mais son index/hash de contenu exact et le comportement d’interrogation du client deviennent des identifiants stables.

**Détection :** consignez les identifiants complets des API/objets et les hash des réponses ; déclenchez des alertes lorsqu’un processus inhabituel interroge des objets immuables, puis effectue un décodage ou établit de nouvelles connexions.

### Opérations différées de type store-and-forward

Le C2 interactif crée une forte corrélation temporelle. Une conception store-and-forward regroupe les tâches chiffrées et renvoie les résultats plusieurs minutes ou heures plus tard par une autre file ou un transfert physique. Elle sacrifie la réactivité pour réduire la corrélation temporelle de bout en bout.

**Détection :** élargissez les fenêtres de corrélation, modélisez les accès périodiques aux files et examinez la préparation des données sur les points de terminaison. Le regroupement déplace le signal du minutage des paquets vers le comportement planifié des processus et des fichiers ; il ne le fait pas disparaître.

## Revue de conception : pensez en termes d’observateurs

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Responsable de la conservation/des aspects juridiques |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de transit | | | | | |
| sortie/redirector/CDN | | | | | |
| DNS faisant autorité/registrar | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur ordinaire peut remplir toutes les colonnes, l’architecture dissimule l’activité à la cible, mais n’assure pas une séparation robuste. Si aucun responsable interne ne peut relier l’activité à un exercice, l’architecture ne convient pas à une red team professionnelle.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584) et Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Démantèlement du plus grand réseau de proxy résidentiel au monde](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Les campagnes de l’ombre : révélation d’un espionnage mondial](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagne Blinder Tunnel cible l’infrastructure irakienne](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl : l’IA a créé les superpositions. Les victimes perdent leurs PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
