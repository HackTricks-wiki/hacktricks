# Infrastructure offensive et évasion de l’attribution

{{#include ../banners/hacktricks-training.md}}

Un opérateur obtient rarement un anonymat significatif en utilisant un seul proxy. Les campagnes réelles construisent un **graphe de séparation** : l’opérateur accède à un nœud d’accès, des nœuds de transit dissimulent ce nœud au nœud de sortie, des redirectors protègent le véritable C2, et des noms éphémères pointent vers le périmètre public.

Consultez le [catalogue des techniques d’accès anonyme à Internet](anonymous-internet-access-techniques.md) pour une vue normalisée des avantages et inconvénients, du déploiement et de la détection de chaque méthode. Cette page approfondit la composition d’infrastructures adverses.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La dernière adresse vue par une cible constitue donc la preuve d’un chemin, et non la preuve de l’identité de la personne qui contrôlait le clavier. MITRE associe les principaux composants à Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) et Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes d’infrastructure

| Classe | Pourquoi un acteur l’utilise | Exposition durable | Meilleur pivot pour les défenseurs |
|---|---|---|---|
| VPS/cloud loué | Rapide, prévisible, routable et facile à reconstruire | Historique du locataire, de la facturation, de la console, des connexions sources et des images | Événements du compte/plan de contrôle et empreinte récurrente du serveur |
| VPN commercial/Tor | Grand ensemble d’adresses de sortie partagées ; aucune administration serveur | Visibilité du fournisseur/de l’opérateur et corrélation temporelle de bout en bout | Comportement de destination, preuves sur les endpoints et corrélation des flux |
| Proxy résidentiel/mobile | ASN grand public et plausibilité géographique | Dossiers du courtier/client ; comportement de proxyware ou d’hôte infecté | Déplacements impossibles, protocoles proxy et rotation des adresses par session |
| Serveur/routeur/IoT compromis | Tire parti de la réputation et de la juridiction de la victime | Implant, flux de gestion et contrôleur amont récurrent | Télémétrie de l’appareil et topologie ORB, pas une seule IP de sortie |
| CDN/redirector | Sépare l’edge public du C2 back-end | Grammaire TLS/HTTP, certificat, routage et artefacts de compte cloud | Corrélation edge-origine et regroupement par forme des requêtes |
| Service web légitime | Se fond dans le trafic autorisé vers GitHub/cloud/réseaux sociaux | Jeton API, identifiants de locataire/objet et lignée inhabituelle des processus | Processus sur l’endpoint et sémantique du service/de l’API |
| Chemin physique/cellulaire/satellite | Modifie l’origine physique apparente | Données RF, opérateur, abonné, appareil et localisation | Combinaison des preuves radio/physiques et réseau |

## Réseaux opérationnels de boîtiers relais

Un **réseau ORB** est une flotte de proxy gérée, utilisée comme service intermédiaire. Mandiant les répartit en réseaux provisionnés de serveurs loués, réseaux non provisionnés de routeurs/IoT compromis et réseaux hybrides. Une topologie mature comporte quatre rôles logiques :<sup>[[2]](#references)</sup>

1. **Serveur d’administration (ACOS) :** gère l’inventaire, les identifiants, l’état de santé et les règles de routage.
2. **Nœud d’accès/relais :** authentifie les clients ou les opérateurs ; c’est le point d’entrée stable vers un maillage changeant.
3. **Nœuds de transit :** un ou plusieurs systèmes loués ou compromis relaient des connexions opaques.
4. **Nœud de sortie/de staging :** présente l’adresse source finale aux cibles de reconnaissance, d’exploitation ou de C2.

Le maillage peut choisir les sorties selon le pays, l’ASN, la latence ou la disponibilité, et faire tourner les nœuds défaillants. Plusieurs groupes de menace peuvent louer le même réseau. Mandiant a observé qu’une adresse IPv4 restait associée à certains ORB pendant seulement 31 jours ; il recommande donc de traiter le **réseau comme une entité évolutive semblable à un acteur**, plutôt que de bloquer une liste obsolète d’IP.<sup>[[2]](#references)</sup>

### Ce que cela apporte — et ce que cela leak

- La cible voit une sortie qui peut être géographiquement proche et apparemment résidentielle.
- La sortie voit la cible et le saut précédent, pas nécessairement l’opérateur.
- Le service d’accès voit le client et la demande de routage. Un maillage géré indépendamment peut séparer le client des sorties, mais crée un registre puissant chez le tiers.
- La répétition des ports, l’ordre des handshakes, les bannières serveur, les certificats, les périodes de disponibilité et les relations entre contrôleurs peuvent révéler la flotte même si les IP tournent.
- Un routeur compromis manque souvent de télémétrie d’endpoint, mais son FAI dispose toujours des données d’abonné et de flux ; une saisie révèle les artefacts de l’implant/de configuration.

{% hint style="info" %}
Pour un exercice autorisé, reproduisez la topologie avec des VM ou des routeurs appartenant à l’organisation et conservez la carte d’attribution du contrôleur. Ne recrutez pas de proxies ouverts ni d’appareils tiers. Le [guide du lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crée la même structure de sauts visible par les défenseurs sans prendre un intermédiaire pour cible.
{% endhint %}

## Réseaux de proxies résidentiels et mobiles

Les services de proxy résidentiel attribuent aux sessions des adresses haut débit grand public ; les proxies mobiles sortent via des pools de NAT d’opérateurs. L’approvisionnement peut provenir d’appareils inscrits explicitement, de SDK/proxyware intégrés à des applications grand public, de revendeurs ou de malware. Ces origines ne sont pas équivalentes : l’absence de consentement éclairé transforme un service de confidentialité en infrastructure compromise.

Les modes de rotation influent sur la détection :

- la **rotation par requête** entraîne des discontinuités rapides d’IP et d’ASN/de géographie, tandis que l’identité des couches supérieures reste stable ;
- les **sessions persistantes** conservent une sortie pendant quelques minutes ou quelques heures, à la manière d’un abonné ordinaire ;
- les **passerelles backconnect** exposent au client un seul endpoint de courtier et choisissent les sorties en interne ;
- les **pools mobiles** placent de nombreux abonnés réels derrière un petit nombre d’adresses NAT d’opérateur, ce qui rend le blocage d’une IP coûteux.

Les défenseurs doivent corréler l’IP à la session authentifiée, à l’empreinte TLS/client, à l’ordre HTTP, au cookie de l’appareil et au comportement. Une connexion prétendument locale via un proxy résidentiel, suivie d’une connexion depuis un autre pays alors que toutes les caractéristiques de couche supérieure restent identiques, constitue un indice plus fort que la seule réputation. À l’inverse, le partage d’adresses et le transfert mobile entraînent une rotation légitime ; ne considérez donc jamais la classification résidentielle/proxy comme un verdict.

### Plans de contrôle du proxyware et chevauchement des revendeurs

Ne modélisez pas un pool résidentiel comme une simple liste de sorties. L’analyse de l’écosystème IPIDEA a révélé un **plan de contrôle réutilisable à deux niveaux** : un SDK intégré signale d’abord les métadonnées de l’appareil/de l’inscription à un domaine Tier One, puis reçoit la planification ainsi que les paires IP:port `connect`/`proxy` du Tier Two. Le nœud interroge périodiquement le port de connexion Tier Two pour obtenir une tâche encodée, ouvre une seconde connexion au port proxy associé et relaie les octets fournis vers la destination demandée. Des SDK et marques de proxy nominalement distincts utilisaient des domaines de découverte séparés, mais convergeaient vers une infrastructure Tier Two commune et des pools de sorties qui se chevauchaient, du fait de propriétaires et de relations de revente partagés.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Cela produit des pivots de chasse plus durables qu’un bloc d’IP résidentielles :<sup>[[13]](#references)</sup>

- un processus inattendu d’utilitaire, de VPN, de jeu ou d’appareil embarqué envoie un identifiant d’appareil ou une clé client stable, puis reçoit une liste de serveurs changeante ;
- le terminal interroge une IP directe sur un port inhabituel, puis se connecte à un autre port sur la même adresse juste avant d’ouvrir un socket vers une nouvelle destination ;
- plusieurs marques apparentes partagent des adresses Tier Two, une grammaire de protocole, du code SDK ou un chevauchement de nœuds de sortie ;
- des applications distinctes qui contactent différents domaines Tier One reçoivent des adresses provenant du même pool Tier Two.

Ce chevauchement limite aussi l’attribution : voir une IP dans le pool annoncé d’un fournisseur ne permet pas d’établir quel revendeur, client ou acteur malveillant l’a utilisée au moment pertinent. Conservez les horodatages des flux, la filiation des processus, les corps des réponses Tier One et les identifiants de tâche Tier Two.<sup>[[13]](#references)</sup> Dans le cadre d’un exercice autorisé, émulez cette hiérarchie uniquement avec des terminaux appartenant à l’organisation ; n’inscrivez jamais d’appareils grand public ni de proxyware tiers.

## Chaînes de proxy multi-hop

MITRE distingue les proxies externes des **multi-hop proxies (T1090.003)**. La propriété importante n’est pas le nombre de sauts, mais la séparation des connaissances et de l’administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si une même partie exploite A et B, les journaux partagés ou la synchronisation des flux peuvent permettre de reconstituer le circuit. Ajouter des VPN commerciaux successifs depuis le même point de terminaison/compte peut augmenter la latence tout en laissant des indices communs liés à l’identité, au paiement et à la synchronisation. Tor réduit ce problème grâce à des relais sélectionnés indépendamment et à une conception commune du client, mais un réseau interactif à faible latence ne peut pas garantir une résistance face à un observateur qui mesure les deux extrémités.

Les défaillances courantes comprennent les contournements DNS ou IPv6, les applications qui ouvrent leurs propres sockets, le trafic de gestion qui atteint directement les relais, les activités synchronisées, les clés SSH réutilisées et les connexions à des comptes identifiants. La bonne méthode de vérification consiste à tester les défaillances : arrêter chaque relais à tour de rôle et vérifier que la charge de travail ne peut pas basculer vers une voie en clair.

### Effondrement du tunnel et fuite en amont

Une architecture de relais est souvent la plus facile à attribuer lorsqu'elle tombe en panne. Unit 42 a documenté un chemin d'espionnage à plusieurs niveaux utilisant des VPS exposés aux victimes, des VPS relais, des proxys résidentiels, Tor et d'autres services proxy ; lorsqu'un tunnel était omis ou s'effondrait, l'infrastructure amont cachée se connectait directement aux systèmes relais et aux systèmes exposés aux victimes. La même enquête a également utilisé un certificat X.509 brièvement exposé sur l'infrastructure amont comme pivot entre les niveaux.<sup>[[14]](#references)</sup>

Séparez le **plan de données** (`victim <-> exit`) du **plan de contrôle** (`operator/upstream -> relay administration`). Conservez les journaux d'entrée et d'authentification à chaque niveau que vous contrôlez, ainsi que l'historique des certificats et les connexions échouées de courte durée — pas seulement les sessions C2 réussies. Une source qui n'apparaît que lors des pannes de relais ou qui administre directement plusieurs nœuds exposés aux victimes est une meilleure candidate comme système amont qu'une sortie ordinaire, mais son ASN/sa géolocalisation reste une hypothèse, et non une preuve de l'identité d'un opérateur.

Un lab autorisé doit faire échouer la charge de travail de manière fermée. Pour une charge de travail isolée dans un espace de noms réseau Linux, la première route doit passer par le tunnel ; après son retrait, la requête et la recherche de route doivent échouer, plutôt que de sélectionner la liaison physique vers l'extérieur :

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Répétez le test pour le DNS et IPv6, ainsi qu’à chaque frontière de relais. Si une sonde aboutit, consignez l’interface et l’adresse source réellement utilisées avant de réparer le routage par politique ou le firewall ; cette observation constitue le leak d’attribution qu’un enquêteur pourrait constater.

## Couches de redirectors et mise en forme du trafic

Un **redirector** public accepte le trafic qui respecte une grammaire propre à l’opération et le transmet à un serveur d’équipe protégé. Tout le reste peut être rejeté ou recevoir un contenu anodin.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Plusieurs niveaux limitent l’exposition : brûler un domaine public ne doit pas nécessairement exposer le team server. Les CDN ajoutent une capacité anycast et un domaine externe réputé, mais le compte CDN et les journaux edge deviennent des points d’attribution. Les empreintes TLS, l’historique des certificats, les chemins distinctifs, l’ordre des en-têtes, la taille des réponses, le comportement des redirections et les listes d’autorisation des origines peuvent regrouper des fronts supposément sans lien.

Pour la détection, enregistrez les champs du reverse proxy avant normalisation, comparez SNI/Host/authority, inspectez les combinaisons rares d’en-têtes, regroupez les corps de réponse et les empreintes TLS, et recherchez les chevauchements de configuration dans les journaux d’audit cloud/CDN. Pour les red teams autorisées, évitez de copier une vraie marque ou de placer la collecte d’identifiants derrière un tiers sans rapport.

## Domain fronting et domainless fronting

Avec le **domain fronting classique (T1090.004)**, la connexion TLS annonce un domaine front autorisé dans SNI, tandis que le `Host` HTTP chiffré ou `:authority` en HTTP/2 demande un autre domaine back-end. Un CDN coopératif effectue le routage à partir de la valeur interne. Un observateur réseau sans déchiffrement TLS voit le front ; le CDN voit les deux valeurs et l’origine. Dans les variantes domainless, SNI peut être vide tandis qu’un autre champ de routage sélectionne la destination.<sup>[[4]](#references)</sup>

Ce n’est pas une usurpation magique : cela ne fonctionne que si l’intermédiaire autorise intentionnellement ou accidentellement cette divergence et sait router le nom interne. Les principaux fournisseurs ont limité le fronting entre comptes. Encrypted ClientHello (ECH) modifie ce qu’un observateur sur le chemin peut voir, mais n’efface pas les enregistrements du CDN, du point de terminaison ou de l’application.

Les points de détection comprennent :

- la filiation des processus sur le point de terminaison et une destination inattendue pour cette application ;
- une divergence entre SNI et l’autorité HTTP lorsque l’inspection TLS est légale et disponible ;
- les journaux CDN indiquant qu’un tenant/front route vers une autre autorité/origine ;
- des sessions inhabituellement longues ou périodiques vers un service normalement interactif ;
- des tailles et une cadence stables de flux chiffrés malgré le changement des domaines front.

Le lab sécurisé simule la divergence de routage sur un reverse proxy détenu par l’équipe ; il n’exploite pas un CDN public.

## Résolution dynamique : DDNS, DGA et fast flux

La résolution dynamique dissocie un service logique d’une infrastructure fixe :

- **DDNS :** un client authentifié met à jour un nom stable après le changement de son adresse.
- **DGA :** le point de terminaison dérive des noms de domaine à partir d’une graine, souvent temporelle ou liée à une clé, mais parfois issue de contenu public mutable ; l’opérateur configure le DNS pour le nom actif.<sup>[[17]](#references)</sup>
- **Fast flux :** un nom renvoie un ensemble d’adresses compromises ou de proxy qui change rapidement, souvent avec des TTL faibles.
- **Double flux :** les adresses de service et celles des serveurs de noms faisant autorité tournent toutes deux, masquant également la couche de contrôle.

Le fast flux est un modèle de répartition de charge utilisé à des fins adverses, et non simplement « de nombreuses réponses DNS ». Des éléments plus probants associent un TTL faible, un nombre élevé d’adresses uniques, une large dispersion géographique et entre ASN, une courte durée de vie des nœuds, un comportement applicatif répétitif et un historique d’enregistrement suspect. Les CDN présentent légitimement plusieurs de ces caractéristiques. MITRE recommande de corréler le comportement DNS avec le processus et les connexions ultérieures.<sup>[[5]](#references)</sup>

Un DGA peut être détecté grâce à l’entropie lexicale, aux motifs de consonnes/chiffres, aux rafales de NXDOMAIN, aux domaines détectés pour la première fois de manière synchronisée et au contexte du processus. Les DGA fondés sur des listes de mots et les modèles génératifs déjouent les règles simples d’entropie ; le regroupement temporel à l’échelle de la flotte et la filiation des points de terminaison deviennent donc plus importants.

### Graine d’image mutable pour un DGA fondé sur une liste de mots

Un DGA n’a pas nécessairement besoin de dépendre du temps. Un chargeur récupère la page publique d’une chaîne Telegram, lit le `src` de son élément `tgme_page_photo_image`, télécharge cette image de profil et hache ses **50 derniers octets de fichier** plutôt que ses pixels décodés. Quatre graines de hachage sélectionnent un adjectif, un nom, un verbe et un nombre. Modifier l’image change le nom DNS dérivé sans qu’il soit nécessaire de distribuer un nouveau client. Conservez exactement les octets de l’image téléchargée et le même ordre des listes de mots des deux côtés ; réencoder l’image ou réordonner une liste produit des noms différents.<sup>[[17]](#references)</sup>

Avec les listes de mots récupérées du client, cette méthode reproduit l’étape de sélection du nom. Le hachage octet par octet de la source utilise un accumulateur de 64 bits, le multiplicateur `0x1000193` et des graines distinctes pour chaque composant :<sup>[[17]](#references)</sup>

<details>
<summary>Reproduire la sélection du nom par liste de mots avec une graine d’image</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

Contrairement à un [dead-drop resolver](#web-services-and-dead-drop-resolvers) qui publie directement le point de terminaison, l’objet public ne fournit ici qu’une seed modifiable ; le client dérive localement le point de terminaison.

Le nom généré est ensuite utilisé pour rechercher un enregistrement DNS TXT via `https://dns.google/resolve?name=<domain>&type=TXT`. Le client décode en Base64 le champ `data` de la réponse JSON, vérifie une signature Ed25519 avec sa clé publique intégrée, puis déchiffre la commande avec AES-ECB. Le texte en clair observé commence par un sélecteur de méthode et une URL vers une charge utile chiffrée. La vérification de signature signifie qu’un enregistrement TXT résolvable ne peut pas, à lui seul, fournir des instructions acceptées.<sup>[[17]](#references)</sup>

## Domaines compromis et domain shadowing

Un acteur peut détourner un compte de bureau d’enregistrement/DNS, prendre le contrôle d’un sous-domaine abandonné ou ajouter des enregistrements sous un domaine autrement réputé. Le **domain shadowing** préserve le domaine racine légitime tandis qu’un grand nombre de sous-domaines contrôlés par l’attaquant pointent vers des hôtes de livraison ou C2 qui changent. Cette technique tire parti de l’ancienneté et de la réputation du domaine et peut échapper aux blocages à l’échelle du domaine.<sup>[[6]](#references)</sup>

Les défenseurs ont besoin de journaux d’audit du bureau d’enregistrement et du DNS faisant autorité, de MFA, de verrous au niveau du registre et du bureau d’enregistrement, d’alertes en cas de nouvelles délégations, de nouveaux jetons API ou serveurs de noms, de surveillance de la transparence des certificats et d’un inventaire des ressources cloud référencées par le DNS. Examinez séparément la résolution et l’historique des certificats d’un sous-domaine, sans vous fier à la réputation du domaine racine.

## Services Web et dead-drop resolvers

Un **dead-drop resolver (T1102.001)** stocke un pointeur encodé vers le C2 actuel dans une publication, un profil, un document, un dépôt, un objet cloud ou un champ de blockchain légitime. Le malware récupère l’objet public, en extrait un domaine/IP et contacte l’étape suivante. Les variantes bidirectionnelles échangent des commandes ou des fichiers via les API des services.<sup>[[7]](#references)</sup>

Une variante de resolver propre à GitHub utilise l’API de recherche Issues uniquement lorsqu’un canal de dépôt authentifié échoue. Le client recherche les issues correspondant à la date du jour, au dépôt et au type d’issue, suit l’URL des commentaires de chaque issue et extrait le texte chiffré situé entre les marqueurs `<!--` et `-->`. Après un déchiffrement par hôte dérivé de la date, des champs comme `Owner`, `LicRepo` et `LicToken` remplacent le propriétaire, le chemin et le jeton du dépôt principal. L’opérateur peut ainsi renouveler les identifiants et les points de terminaison sans remplacer le client ; le commentaire de l’issue sert de resolver, tandis que les fichiers du dépôt restent le canal de commandes.<sup>[[15]](#references)</sup>

Une variante Android sélectionne au démarrage l’une de deux pages Telegram publiques et extrait le texte chiffré situé entre deux occurrences d’un marqueur intégré à l’APK. Elle décode la valeur en Base64URL et la déchiffre avec AES-128-CBC : les 16 premiers octets de `SHA-256(marker)` forment la clé et les 16 suivants, l’IV. Le texte en clair est l’URL de base C2 réelle, et non l’URL de la page Telegram. Pour reproduire la résolution, préservez le contenu de la page et le marqueur exact ; modifier la page publique permet de renouveler le point de terminaison sans reconstruire l’APK.<sup>[[16]](#references)</sup>

Cette technique renforce la résilience et masque le C2 back-end à l’analyse statique des binaires. Elle crée aussi des identifiants stables liés aux objets, tenants, dépôts, API et habitudes d’accès. Les défenseurs devraient corréler :

1. le processus qui a contacté le service ;
2. le chemin API/l’objet exact et le hash de la réponse ;
3. l’activité de décodage ou de traitement de chaînes ;
4. la nouvelle connexion sortante peu après ; et
5. le même comportement ailleurs dans le parc.

Bloquer tout GitHub, tout stockage cloud ou tous les réseaux sociaux est rarement viable. Les politiques de sortie tenant compte des services et la corrélation au niveau des processus sont plus efficaces que le blocage fondé uniquement sur les domaines.

## Personas, comptes et compartimentation des achats

L’anonymat de l’infrastructure échoue lorsqu’une persona, une adresse e-mail de récupération, un numéro de téléphone, un paiement, un navigateur ou une IP d’administration relie plusieurs compartiments. Les opérations liées à des États ont créé des profils sociaux, des identités e-mail et des comptes cloud bien avant leur utilisation ; ATT&CK classe cette activité dans Establish Accounts (T1585), avec des sous-techniques liées aux réseaux sociaux, aux e-mails et au cloud.<sup>[[8]](#references)</sup>

Un défenseur ou un enquêteur établit un graphe à partir des éléments suivants :

- date de création et de première connexion, paramètres régionaux, fuseau horaire et horaires de travail ;
- champs de récupération, appareils MFA, documents d’identité et moyens de paiement ;
- empreintes navigateur/TLS et historique des réseaux sources ;
- réutilisation d’avatars, provenance des images, style d’écriture et évolution du graphe social ;
- bureau d’enregistrement, serveur de noms, certificat, identifiant d’analytics ou commit de dépôt communs ;
- actions du plan de gestion qui contournent l’architecture de relais public.

Pour une red team autorisée, les personas synthétiques doivent être documentées auprès du responsable de l’exercice, utiliser des canaux de récupération et de paiement appartenant à l’organisation, éviter l’usurpation de l’identité de personnes réelles non impliquées et prévoir une procédure de retrait. Le SOC peut rester dans l’ignorance ; l’opération ne doit pas devenir irresponsable.

## Tendances émergentes composites à modéliser

Les éléments suivants sont des **combinaisons conçues pour les défenseurs**, et non l’affirmation qu’un acteur nommé a déployé chacune de ces conceptions exactes. Ils associent des primitives déjà observées et constituent des hypothèses utiles pour les exercices purple team.

### Commandes unidirectionnelles asymétriques

Les commandes arrivent par une source publique, diffusée ou en ajout seulement, tandis que les résultats repartent par un canal sans lien, après un délai. Les primitives correspondantes comprennent la communication unidirectionnelle via un service Web et les dead drops. Cette séparation évite qu’un seul flux semble bidirectionnel et complique la corrélation simple des requêtes et réponses.<sup>[[9]](#references)</sup>

**Détection :** conservez les lectures au niveau des objets, puis corrélez les changements d’état des processus et les transferts sortants ultérieurs sur une fenêtre plus large. Recherchez les processus rares qui lisent le même objet public, même sans réponse immédiate.

### Promotion des canaux en plusieurs étapes

Une première étape discrète effectue un inventaire et ne fait passer qu’une sélection de systèmes vers un canal de deuxième étape sans lien avec le premier. Le deuxième point de terminaison, le protocole et le processus peuvent ne partager aucune infrastructure avec la première étape. Cette approche limite l’exposition de l’infrastructure avancée et est explicitement modélisée sous ATT&CK T1104.<sup>[[10]](#references)</sup>

**Détection :** corrélez `processus réseau initial -> état téléchargé/configuré -> nouveau processus ou injection -> destination sans lien` ; ne clôturez pas l’incident après le blocage du premier domaine.

### Traduction de relais entre protocoles

Différents sauts traduisent HTTPS, QUIC, WebSocket, DNS, SSH ou une API de file de messages au lieu de transférer les paquets de manière transparente. La traduction supprime une empreinte de protocole unique de bout en bout, mais crée des passerelles aux délais, tampons et conversions sémantiques caractéristiques. Le tunneling de protocoles (T1572) peut être combiné à des proxies et à l’usurpation de services.<sup>[[11]](#references)</sup>

**Détection :** recherchez des hôtes passerelles qui reçoivent un protocole et en initient un autre avec des volumes d’octets et des délais étroitement corrélés ; comparez l’intention du point de terminaison au protocole réellement transporté.

### Activation passive sur des appareils edge

Au lieu d’émettre des beacons, un implant surveille le trafic qui atteint déjà un routeur/VPN et ne s’active qu’à la réception d’une valeur magique, d’un motif de port source ou d’un jeton authentifié. Le trafic normal continue vers le véritable service. ATT&CK appelle cela Traffic Signaling (T1205), avec des exemples documentés concernant des appareils réseau et des groupes APT.<sup>[[12]](#references)</sup>

**Détection :** vérifiez l’intégrité du firmware et des fichiers, capturez les paquets bruts pendant une investigation autorisée, recherchez les filtres de socket inattendus et les différences de comportement du service. L’absence de beacon périodique ne prouve pas qu’un appareil edge est sain.

### Rotation des origines serverless et éphémères

Une façade conserve une identité logique stable, tandis que des fonctions/conteneurs de courte durée gèrent différentes étapes dans plusieurs régions/comptes. Cela réduit la durée de présence sur disque et le recours à des IP d’origine fixes, mais les données du plan de contrôle — création, image/couche, rôle, secret, identifiant de requête et facturation — deviennent le graphe durable.

**Détection :** conservez les journaux d’audit cloud et d’invocation en dehors de la charge de travail ; regroupez les modèles de déploiement, les rôles, les clés d’environnement et les relations entre façade et origine.

### Diversité des couches de confidentialité

Une opération peut délibérément éviter une chaîne homogène : par exemple, un canal utilise un relais loué, les commandes passent par un objet public, la sortie utilise une liaison cellulaire de laboratoire contrôlée et l’administration un réseau distinct de l’organisation. Cela réduit l’intérêt de compromettre un fournisseur unique, mais accroît les risques liés à la corrélation temporelle entre couches et aux erreurs opérationnelles.

**Détection :** établissez des chronologies de campagne à partir des capteurs d’identité, DNS, SaaS, réseau et cloud. Recherchez des transitions d’état synchronisées plutôt que des indicateurs identiques.

### Dead drops décentralisés ou reposant sur des journaux de transparence

Un acteur peut placer un petit pointeur chiffré dans n’importe quel système public durable en ajout seulement, stockage adressé par contenu ou flux de type journal de transparence. L’objet public est résilient, mais son index/hash de contenu exact et le comportement d’interrogation du client deviennent des identifiants stables.

**Détection :** consignez les identifiants complets des API/objets et les hashes des réponses ; déclenchez une alerte lorsqu’un processus inhabituel interroge des objets immuables, puis les décode ou établit de nouvelles connexions.

### Opérations différées de type store-and-forward

Le C2 interactif crée de fortes corrélations temporelles. Une architecture store-and-forward regroupe des tâches chiffrées et renvoie les résultats quelques minutes ou quelques heures plus tard par une autre file ou un transfert physique. Elle sacrifie la réactivité au profit d’une corrélation temporelle de bout en bout plus faible.

**Détection :** élargissez les fenêtres de corrélation, modélisez les accès périodiques aux files et examinez la préparation des points de terminaison. Le regroupement déplace le signal des délais entre paquets vers le comportement planifié des processus/fichiers ; il ne l’efface pas.

## Revue de conception : raisonner en observateurs

Pour chaque chemin, remplissez ce tableau avant le déploiement et après la collecte :

| Couche | Voit la source ? | Voit la destination ? | Voit le contenu ? | Identifiants stables | Conservation/propriétaire légal |
|---|---:|---:|---:|---|---|
| réseau local/opérateur | | | | | |
| service d’entrée/d’accès | | | | | |
| opérateur(s) de transit | | | | | |
| sortie/redirector/CDN | | | | | |
| DNS faisant autorité/bureau d’enregistrement | | | | | |
| cible | | | | | |
| fournisseur de compte/paiement | | | | | |

Si un fournisseur ordinaire peut remplir toutes les colonnes, l’architecture masque l’activité à la cible, mais ne garantit pas une séparation robuste. Si aucun responsable interne ne peut relier l’activité à une mission, l’architecture ne convient pas à une red team professionnelle.

## References

- [1] [MITRE ATT&CK — Acquisition d’infrastructure (T1583), compromission d’infrastructure (T1584) et proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-sauts (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromission d’infrastructure : domaines (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Service Web : Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Création de comptes (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Service Web : communication unidirectionnelle (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canaux en plusieurs étapes (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunneling de protocoles (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Démantèlement du plus grand réseau mondial de proxies résidentiels](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Les campagnes Shadow : révélation d’un espionnage mondial](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagne Blinder Tunnel cible des infrastructures irakiennes](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl : l’IA a créé les superpositions. Les victimes perdent leurs PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Des astuces du passé déployées via des binaires signés de ChatGPT et Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
