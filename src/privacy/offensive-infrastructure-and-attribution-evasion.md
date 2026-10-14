# Infrastructure offensive et évasion de l’attribution

{{#include ../banners/hacktricks-training.md}}

Un opérateur obtient rarement un anonymat significatif à l’aide d’un seul proxy. Les véritables campagnes construisent un **graphe de séparation** : l’opérateur atteint un nœud d’accès, des nœuds de transit masquent ce nœud à la sortie, des redirectors protègent le véritable C2, et des noms jetables pointent vers le point d’entrée public.

Consultez le [catalogue des techniques d’accès anonyme à Internet](anonymous-internet-access-techniques.md) pour obtenir une vue normalisée des avantages, inconvénients, méthodes de déploiement et détections de chaque chemin. Cette page approfondit la composition d’infrastructures adversariales.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La dernière adresse vue par une cible est donc un indice sur le chemin emprunté, pas une preuve de l’identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d’infrastructure

| Classe | Pourquoi un acteur l’utilise | Exposition durable | Meilleur pivot pour le défenseur |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable, facile à reconstruire | Historique du locataire, de la facturation, de la console, des connexions sources et des images | Événements du compte/plan de contrôle et empreinte serveur récurrente |
| VPN commercial/Tor | Grand ensemble de sorties partagées ; aucune administration de serveur | Visibilité du fournisseur et des gardes ; chronologie de bout en bout | Comportement de destination, preuves sur les endpoints et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | Données du courtier/client ; comportement de proxyware ou d’hôte infecté | Déplacements impossibles, protocoles proxy et rotation des adresses par session |
| Serveur/routeur/objet connecté compromis | Tire parti de la réputation et de la juridiction de la victime | Implant, flux de gestion et contrôleur amont récurrent | Télémétrie des appareils et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l’edge public du C2 back-end | Artefacts TLS/HTTP, certificat, routage et compte cloud | Corrélation edge-origine et regroupement par forme des requêtes |
| Service web légitime | Se fond dans le trafic autorisé vers GitHub/cloud/réseaux sociaux | Jeton API, identifiants de locataire/objet et filiation inhabituelle des processus | Processus sur l’endpoint et sémantique du service/de l’API |
| Liaison physique/cellulaire/satellite | Modifie l’origine physique apparente | Données RF, opérateur, abonné, appareil et localisation | Éléments radio/physiques et réseau combinés |

## Réseaux opérationnels de relais ORB

Un **réseau ORB** est une flotte de proxy gérée, utilisée comme service intermédiaire. Mandiant les répartit en réseaux provisionnés, constitués de serveurs loués, en réseaux non provisionnés, constitués de routeurs/objets connectés compromis, et en réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d’administration (ACOS) :** gère l’inventaire, les identifiants, l’état de santé et les règles de routage.
2. **Nœud d’accès/relais :** authentifie les clients ou les opérateurs ; c’est le point d’entrée stable vers un maillage changeant.
3. **Nœuds de transit :** un ou plusieurs systèmes loués ou compromis relaient des connexions opaques.
4. **Nœud de sortie/de staging :** présente l’adresse source finale aux cibles de reconnaissance, d’exploitation ou de C2.

Le maillage peut choisir les sorties selon le pays, l’ASN, la latence ou la disponibilité, et remplacer les nœuds défaillants. Plusieurs groupes de menace peuvent louer le même réseau. Mandiant a observé qu’une adresse IPv4 restait associée à certains ORB pendant seulement 31 jours ; il recommande donc de traiter le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d’IP.<sup>[[2]](#references)</sup>

### Ce que cela apporte — et ce que cela divulgue

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le saut précédent, mais pas nécessairement l’opérateur.
- Le service d’accès voit le client et la demande de routage. Un maillage géré indépendamment peut séparer le client des sorties, mais crée une trace importante chez un tiers.
- Les ports récurrents, l’ordre des handshakes, les bannières de serveur, les certificats, les plages de disponibilité et les relations entre contrôleurs peuvent révéler la flotte même lorsque les IP changent.
- Un routeur compromis manque souvent de télémétrie d’endpoint, mais son FAI dispose toujours des données d’abonné et de flux ; une saisie révèle les artefacts de l’implant/de la configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l’organisation et conservez la carte d’attribution du contrôleur. Ne recrutez pas de proxy ouverts ni d’appareils tiers. Le [guide de labo](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de sauts visible par les défenseurs sans victimiser un intermédiaire.
{% endhint %}

## Réseaux de proxy résidentiels et mobiles

Les services de proxy résidentiel attribuent aux sessions des adresses de connexions haut débit grand public ; les proxies mobiles sortent par des pools de NAT d’opérateurs. L’offre peut provenir d’appareils inscrits explicitement, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malwares. Ces origines ne sont pas équivalentes : l’absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influent sur la détection :

- la **rotation par requête** entraîne des discontinuités rapides d’IP, d’ASN et de géolocalisation, tandis que l’identité de couche supérieure reste stable ;
- les **sessions persistantes** conservent une sortie pendant quelques minutes ou plusieurs heures, ce qui ressemble à un abonné ordinaire ;
- les **passerelles backconnect** exposent un seul endpoint de courtier au client et choisissent les sorties en interne ;
- les **pools mobiles** placent de nombreux vrais abonnés derrière un petit nombre d’adresses NAT d’opérateur, ce qui rend coûteux le blocage d’une IP.

Les défenseurs devraient corréler l’IP avec la session authentifiée, l’empreinte TLS/client, l’ordre HTTP, le cookie de l’appareil et le comportement. Une connexion prétendument locale via une adresse résidentielle, suivie d’une connexion depuis un autre pays alors que toutes les caractéristiques de couche supérieure restent identiques, constitue un indice plus solide que la seule réputation. À l’inverse, le partage d’adresses et les changements de relais mobiles entraînent une rotation légitime ; ne considérez donc jamais la classification résidentielle/proxy comme un verdict.

### Plans de contrôle du proxyware et chevauchement des revendeurs

Ne modélisez pas un pool résidentiel comme une simple liste de sorties. L’analyse de l’écosystème IPIDEA a révélé un **plan de contrôle à deux niveaux** réutilisable : un SDK intégré signale d’abord les métadonnées de l’appareil/de l’inscription à un domaine Tier One et reçoit la planification ainsi que des paires IP:port `connect`/`proxy` de Tier Two. Le nœud interroge périodiquement le port connect de Tier Two pour obtenir une tâche encodée, ouvre une deuxième connexion au port proxy associé et relaie les octets fournis vers la destination demandée. Des SDK et des marques de proxy présentés comme distincts avaient des domaines de découverte séparés, mais convergeaient vers une infrastructure Tier Two partagée et des pools de sortie qui se chevauchaient, en raison de propriétaires et de relations de revente communs.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Cela produit des pivots de chasse plus durables qu’un bloc d’adresses IP résidentielles :<sup>[[13]](#references)</sup>

- un processus inattendu d’utilitaire, de VPN, de jeu ou d’appareil embarqué envoie un identifiant stable de l’appareil ou une clé client, puis reçoit une liste de serveurs changeante ;
- le point de terminaison interroge une adresse IP directe sur un port inhabituel, puis se connecte immédiatement à un autre port sur la même adresse avant d’ouvrir un socket vers une nouvelle destination ;
- plusieurs marques apparentes partagent des adresses Tier Two, une grammaire de protocole, du code SDK ou des nœuds de sortie communs ;
- des applications distinctes qui contactent différents domaines Tier One reçoivent des adresses issues du même pool Tier Two.

Ce chevauchement limite également l’attribution : voir une adresse IP dans le pool annoncé par un fournisseur ne permet pas d’établir quel revendeur, client ou acteur de la menace l’a utilisée au moment concerné. Conservez les horodatages des flux, la filiation des processus, les corps des réponses Tier One et les identifiants de tâches Tier Two.<sup>[[13]](#references)</sup> Dans le cadre d’un exercice autorisé, émulez cette hiérarchie uniquement avec des points de terminaison appartenant à l’organisation ; n’inscrivez jamais d’appareils grand public ni de proxyware tiers.

## Chaînes de proxy multi-hop

MITRE distingue les proxys externes des **proxys multi-hop (T1090.003)**. La propriété importante n’est pas le nombre de sauts, mais la séparation des connaissances et de l’administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si une même partie exploite A et B, les journaux partagés ou le minutage des flux peuvent permettre de reconstituer le circuit. Ajouter des VPN commerciaux en chaîne depuis le même endpoint/compte peut accroître la latence tout en laissant des indices communs liés à l’identité, au paiement et au minutage. Tor réduit ce problème grâce à des relais sélectionnés indépendamment et à une conception client partagée, mais un réseau interactif à faible latence ne peut pas garantir une résistance à un observateur qui mesure les deux extrémités.

Les erreurs fréquentes sont les fuites DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic d’administration qui atteint directement les relais, les activités synchronisées, la réutilisation de clés SSH et la connexion à des comptes identifiants. La bonne méthode de vérification est un test de panne : arrêter chaque relais à tour de rôle et vérifier que la charge de travail ne peut pas basculer vers une voie en clair.

### Effondrement du tunnel et fuite en amont

Une architecture de relais est souvent la plus attribuable lorsqu’elle tombe en panne. Unit 42 a documenté un chemin d’espionnage à plusieurs niveaux utilisant des VPS exposés aux victimes, des VPS relais, des proxys résidentiels, Tor et d’autres services proxy ; lorsqu’un tunnel était omis ou s’effondrait, une infrastructure amont dissimulée se connectait directement aux systèmes relais et exposés aux victimes. La même enquête a également utilisé un certificat X.509 brièvement exposé sur une infrastructure amont comme pivot entre les niveaux.<sup>[[14]](#references)</sup>

Séparez le **plan de données** (`victim <-> exit`) du **plan de contrôle** (`operator/upstream -> relay administration`). Conservez les journaux d’entrée et d’authentification à chaque niveau que vous exploitez, l’historique des certificats et les connexions échouées de courte durée — pas seulement les sessions C2 réussies. Une source qui n’apparaît que lors des pannes de relais ou qui administre directement plusieurs nœuds exposés aux victimes est une meilleure candidate pour l’amont qu’une sortie ordinaire, mais son ASN et sa géolocalisation restent des hypothèses, pas des preuves de l’identité d’un opérateur.

Dans un laboratoire autorisé, la charge de travail doit échouer de manière sécurisée. Pour une charge de travail isolée dans un espace de noms réseau Linux, la première route doit emprunter le tunnel ; après sa suppression, la requête et la recherche de route doivent toutes deux échouer au lieu de sélectionner la liaison montante physique :

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Refaites le test pour DNS et IPv6, ainsi qu’à chaque frontière de relais. Si une sonde réussit, consignez l’interface et l’adresse source réelles avant de corriger le routage par politique ou le firewall ; cette observation constitue la fuite d’attribution qu’un enquêteur verrait.

## Couches de redirectors et façonnage du trafic

Un **redirector** public accepte le trafic conforme à une grammaire propre à l’opération et le transmet à un team server protégé. Tout le reste peut être rejeté ou recevoir un contenu anodin.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Plusieurs niveaux limitent l’exposition : brûler un domaine public n’implique pas de révéler le serveur d’équipe. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux edge deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins distinctifs, l’ordre des en-têtes, la taille des réponses, le comportement des redirections et les listes d’autorisation des origines peuvent regrouper des fronts supposément sans lien.

Pour la détection, consignez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, inspectez les combinaisons rares d’en-têtes, regroupez les corps de réponse et les empreintes TLS, et recherchez les chevauchements de configuration dans les journaux d’audit du cloud/CDN. Pour les red teams autorisées, évitez de copier une vraie marque ou de placer la collecte d’identifiants derrière un tiers sans lien avec l’opération.

## Domain fronting and domainless fronting

Avec le **domain fronting classique (T1090.004)**, la connexion TLS annonce un domaine frontal autorisé dans SNI, tandis que le `Host` HTTP ou le `:authority` HTTP/2 chiffré demande un autre domaine back-end. Un CDN coopératif achemine la requête selon la valeur interne. Un observateur réseau sans déchiffrement TLS voit le domaine frontal ; le CDN voit les deux valeurs et l’origine. Dans les variantes sans domaine, SNI peut être vide, tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Ce n’est pas une usurpation magique : cela ne fonctionne que si l’intermédiaire autorise intentionnellement ou accidentellement cette discordance et sait acheminer le nom interne. Les principaux fournisseurs ont restreint le fronting entre comptes. L’Encrypted ClientHello (ECH) modifie ce qu’un observateur sur le chemin peut voir, mais n’efface pas les journaux du CDN, du point de terminaison ou de l’application.

Les points de détection comprennent :

- l’ascendance des processus du point de terminaison et une destination inattendue pour l’application ;
- une discordance entre SNI et l’autorité HTTP, lorsque l’inspection TLS est légale et disponible ;
- des journaux CDN montrant qu’un tenant/front achemine vers une autre autorité/origine ;
- des sessions inhabituellement longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence stables de flux chiffrés malgré le changement de domaines frontaux.

Le laboratoire sécurisé simule la discordance de routage sur un reverse proxy détenu par l’équipe ; il n’abuse pas d’un CDN public.

## Dynamic resolution: DDNS, DGA and fast flux

La résolution dynamique dissocie un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable lorsque son adresse change.
- **DGA :** le point de terminaison et le contrôleur dérivent tous deux des noms de domaine candidats à partir d’une graine temporelle/clé ; l’opérateur en enregistre un petit sous-ensemble.
- **Fast flux :** un nom renvoie un ensemble d’adresses compromises/de proxy qui change rapidement, souvent avec de faibles TTL.
- **Double flux :** les adresses des services et celles des serveurs de noms faisant autorité tournent toutes deux, masquant également la couche de contrôle.

Le fast flux est un modèle de répartition de charge utilisé à des fins adverses, pas simplement « beaucoup de réponses DNS ». Des éléments plus probants associent un faible TTL, un grand nombre d’adresses uniques, une forte dispersion entre ASN et zones géographiques, une courte durée de vie des nœuds, un comportement applicatif répété et un historique d’enregistrement suspect. Les CDN partagent légitimement plusieurs de ces caractéristiques. MITRE recommande de corréler le comportement DNS avec le processus et les connexions qui suivent.<sup>[[5]](#references)</sup>

Un DGA peut être détecté grâce à l’entropie lexicale, aux motifs de consonnes/chiffres, aux rafales de NXDOMAIN, aux domaines synchronisés observés pour la première fois et au contexte du processus. Les DGA fondés sur des listes de mots et les modèles génératifs déjouent les règles simples d’entropie ; le regroupement temporel à l’échelle de la flotte et la filiation des points de terminaison deviennent donc plus importants.

## Compromised domains and domain shadowing

Un acteur peut détourner un compte de bureau d’enregistrement/DNS, prendre le contrôle d’un sous-domaine abandonné ou ajouter des enregistrements sous un domaine par ailleurs réputé. Le **domain shadowing** conserve le domaine apex légitime, tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de distribution ou C2 changeants. Il emprunte l’ancienneté et la réputation du domaine et peut échapper au blocage à l’échelle du domaine.<sup>[[6]](#references)</sup>

Les défenseurs ont besoin des journaux d’audit du bureau d’enregistrement et du DNS faisant autorité, du MFA, de verrous au niveau du registre et du bureau d’enregistrement, d’alertes sur les nouvelles délégations/jetons API/serveurs de noms, d’une surveillance de la transparence des certificats et d’un inventaire des ressources cloud référencées par le DNS. Examinez la résolution et l’historique des certificats d’un sous-domaine indépendamment de la réputation du domaine apex.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans une publication, un profil, un document, un dépôt, un objet cloud ou un champ de blockchain légitime. Le malware récupère l’objet public, décode un domaine/IP et contacte l’étape suivante. Les variantes bidirectionnelles échangent des commandes ou des fichiers via les API du service.<sup>[[7]](#references)</sup>

Une variante propre à GitHub utilise l’API Issues Search uniquement lorsqu’un canal de dépôt authentifié échoue. Le client recherche les issues correspondant à la date du jour, au dépôt et au type d’issue, suit l’URL des commentaires de chaque issue et extrait le texte chiffré entre les marqueurs `<!--` et `-->`. Après déchiffrement par hôte, dérivé de la date, des champs tels que `Owner`, `LicRepo` et `LicToken` remplacent le propriétaire, le chemin et le jeton du dépôt principal. L’opérateur peut ainsi faire tourner les identifiants et les points de terminaison sans remplacer le client ; le commentaire de l’issue sert de resolver, tandis que les fichiers du dépôt restent le canal de tasking.<sup>[[15]](#references)</sup>

Cette méthode renforce la résilience et masque le C2 back-end à l’analyse statique du binaire. Elle crée aussi des identifiants stables liés aux objets, tenants, dépôts, API et modèles d’accès. Les défenseurs devraient relier :

1. le processus ayant contacté le service ;
2. le chemin API/objet exact et le hash de la réponse ;
3. l’activité de décodage ou de traitement des chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. un comportement identique ailleurs dans la flotte.

Bloquer tout GitHub, stockage cloud ou réseau social est rarement viable. Une politique de sortie tenant compte des services et la corrélation au niveau des processus sont plus efficaces que le blocage fondé uniquement sur les domaines.

## Personas, accounts and procurement compartments

L’anonymat de l’infrastructure échoue lorsqu’un persona, une adresse e-mail de récupération, un numéro de téléphone, un paiement, un navigateur ou une IP d’administration relie des compartiments. Les opérations liées à des États ont créé des profils sociaux, des identités e-mail et des comptes cloud bien avant leur utilisation ; ATT&CK recense cela sous Establish Accounts (T1585), notamment les sous-techniques liées aux réseaux sociaux, aux e-mails et au cloud.<sup>[[8]](#references)</sup>

Un défenseur ou un enquêteur construit un graphe à partir de :

- la date de création et de première connexion, la langue, le fuseau horaire et les horaires d’activité ;
- les champs de récupération, les appareils MFA, les documents d’identité et les moyens de paiement ;
- les empreintes du navigateur/TLS et l’historique des réseaux sources ;
- la réutilisation d’avatars, la provenance des images, le style d’écriture et la croissance du graphe social ;
- un titulaire de domaine, un serveur de noms, un certificat, un identifiant d’analytics ou un commit de dépôt partagés ;
- les actions du plan de gestion qui contournent l’architecture de relais public.

Pour une red team autorisée, les personas synthétiques doivent être documentés auprès du contrôleur de l’exercice, utiliser des canaux de récupération/paiement appartenant à l’organisation, éviter d’usurper l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester dans l’ignorance ; l’opération ne doit pas devenir impossible à attribuer.

## Emerging compound patterns to threat-model

Les compositions suivantes sont **des scénarios élaborés du point de vue du défenseur**, et non des affirmations selon lesquelles un acteur nommé aurait déployé chacune de ces conceptions exactes. Elles combinent des primitives déjà observées et constituent des hypothèses utiles pour les purple teams.

### Asymmetric one-way tasking

Les commandes arrivent par une source publique, diffusée ou en ajout seulement, tandis que les résultats repartent par un canal sans lien après un délai. Parmi les primitives figurent la communication unidirectionnelle via un service web et les dead drops. Cette séparation empêche un flux unique de paraître bidirectionnel et complique la corrélation simple des requêtes/réponses.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus et les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez les processus rares qui lisent le même objet public, même si aucune réponse immédiate ne suit.

### Multi-stage channel promotion

Une première étape discrète effectue un inventaire et ne fait passer que certains systèmes à un canal de seconde étape sans lien. Le second point de terminaison, le protocole et le processus peuvent ne partager aucune infrastructure avec le premier. Cela limite l’exposition de l’infrastructure sensible et est explicitement modélisé par ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** reliez `premier processus réseau -> état téléchargé/configuré -> nouveau processus ou injection -> destination sans lien` ; ne clôturez pas l’incident après le blocage du premier domaine.

### Cross-protocol relay translation

Différents sauts traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de file de messages au lieu de transférer les paquets de manière transparente. La traduction élimine une empreinte de protocole unique de bout en bout, mais crée des passerelles aux caractéristiques distinctives de temporisation, de mise en tampon et de conversion sémantique. Le tunneling de protocole (T1572) peut être combiné avec des proxys et l’usurpation de services.<sup>[[11]](#references)</sup>

**Détection :** recherchez les hôtes passerelles qui reçoivent un protocole et en initient un autre avec des comportements étroitement liés en volume d’octets et en temps ; comparez l’intention du point de terminaison au protocole réellement transporté.

### Passive activation on edge devices

Au lieu d’émettre des beacons, un implant surveille le trafic déjà reçu par un routeur/VPN et ne s’active que sur une valeur magique, un motif de port source ou un jeton authentifié. Le trafic normal continue vers le véritable service. ATT&CK appelle cela Traffic Signaling (T1205) et fournit des exemples documentés sur des équipements réseau et liés à des APT.<sup>[[12]](#references)</sup>

**Détection :** intégrité du firmware/des fichiers, capture brute de paquets pendant une chasse autorisée, filtres de socket inattendus et comportement différentiel du service. L’absence de beacon périodique ne prouve pas qu’un équipement edge est sain.

### Serverless and ephemeral origin rotation

Un front conserve une identité logique stable, tandis que des fonctions/conteneurs éphémères gèrent des étapes individuelles dans plusieurs régions/comptes. Cela réduit la durée de présence sur disque et le recours à des IP d’origine fixes, mais les créations dans le plan de contrôle, les images/couches, les rôles, les secrets, les identifiants de requête et les données de facturation deviennent le graphe durable.

**Détection :** conservez les journaux d’audit et d’invocation du cloud hors de la charge de travail ; regroupez les modèles de déploiement, les rôles, les clés d’environnement et les relations entre fronts et origines.

### Privacy-layer diversity

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relais loué, le tasking un objet public, une sortie une liaison cellulaire de laboratoire détenue par l’équipe et l’administration un réseau organisationnel distinct. Cela réduit l’intérêt de compromettre un seul fournisseur, mais augmente les risques de corrélation temporelle entre couches et d’erreurs opérationnelles.

**Détection :** établissez des chronologies de campagne à travers les capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez les transitions d’état synchronisées plutôt que des indicateurs identiques.

### Decentralized or transparency-log dead drops

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable en ajout seulement, magasin adressé par contenu ou flux de type journal de transparence. L’objet public est résilient, mais son index/hash de contenu exact et le comportement de polling du client deviennent des identifiants stables.

**Détection :** consignez les identifiants complets des API/objets et les hashes des réponses ; déclenchez des alertes sur les processus non standard qui interrogent des objets immuables, puis effectuent un décodage ou établissent de nouvelles connexions.

### Delayed store-and-forward operations

Le C2 interactif crée de fortes corrélations temporelles. Une conception store-and-forward regroupe les tâches chiffrées et renvoie les résultats quelques minutes ou quelques heures plus tard par une file différente ou un transfert physique. Elle sacrifie la réactivité au profit d’une corrélation temporelle de bout en bout plus faible.

**Détection :** élargissez les fenêtres de corrélation, modélisez les accès périodiques aux files et examinez la préparation des données sur les points de terminaison. Le regroupement déplace le signal de la temporalité des paquets vers le comportement planifié des processus/fichiers ; il ne l’efface pas.

## Design review: think in observers

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Responsable de la conservation/du cadre légal |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de transit | | | | | |
| sortie/redirector/CDN | | | | | |
| DNS faisant autorité/bureau d’enregistrement | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur ordinaire peut remplir toutes les colonnes, l’architecture dissimule l’opération à la cible, mais n’assure pas une séparation robuste. Si aucun contrôleur interne ne peut relier l’activité à un engagement, cette architecture ne convient pas aux red teams professionnelles.

## References

- [1] [MITRE ATT&CK — Acquisition d’infrastructure (T1583), compromission d’infrastructure (T1584) et proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy à plusieurs sauts (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — DNS Fast Flux (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromission d’infrastructure : domaines (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Service web : Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Création de comptes (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Service web : communication unidirectionnelle (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canaux à plusieurs étapes (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunneling de protocole (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Signalisation du trafic (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Démantèlement du plus grand réseau de proxy résidentiel au monde](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Les campagnes de l’ombre : révélation d’un espionnage mondial](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagne Blinder Tunnel cible les infrastructures irakiennes](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
