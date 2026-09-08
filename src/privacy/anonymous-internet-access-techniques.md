# Catalogue des techniques d'accès anonyme à Internet

Ceci est l'inventaire de référence des chemins d'accès. Il couvre les **familles** de protocoles et de procédures opérationnelles, et non chaque nom de fournisseur. Aucun chemin Internet ne garantit l'anonymat : les preuves liées aux comptes, au navigateur, au endpoint, au timing, au paiement, au cloud-control-plane et aux éléments physiques peuvent compromettre un itinéraire apparemment parfait.

Chaque entrée utilise les mêmes champs. « Procedure » désigne un déploiement licite ou une émulation en laboratoire contrôlé. Lorsque la technique réelle dépend de la compromission d'un routeur, du vol d'un accès ou de l'abus d'un intermédiaire non consentant, la reproduction utilise des systèmes appartenant à l'exercice.

## Matrice de couverture

| Famille | Ce que voit la destination | Propriété la plus forte | Vitesse | Traitement |
|---|---|---|---|---|
| Shared NAT/CGNAT | adresse publique partagée | ambiguïté entre abonnés | élevée | déployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | adresse du relay | séparation rapide de l'adresse source | élevée | déployable |
| Multi-hop/split relay, MASQUE | proxy final | séparation des connaissances ou tunnel IP complet | élevée/modérée | déployable avec des relays de confiance |
| Tor, bridge, onion service | exit ou identité onion | chemin multipartite et navigateur commun | modérée | déployable |
| I2P, GNUnet, mixnet | pair/gateway de l'overlay | résistance de l'overlay ou au timing | faible/variable | spécifique à l'application |
| OHTTP/ODoH, Private Relay | gateway/egress | partitionnement source/requête | élevée | applications prises en charge uniquement |
| Wi-Fi public, travel router | adresse du lieu/tunnel | changement de lieu/chemin d'accès | élevée | autorisation requise |
| Cellulaire/eSIM, satellite | adresse de l'opérateur/fournisseur | liaison physique indépendante | élevée/variable | abonnement/fournisseur observateur |
| Remote browser/jump host | workspace distant | séparation du endpoint et de l'egress | élevée | déployable |
| Residential/mobile proxy | adresse grand public/opérateur | apparence d'un réseau grand public | élevée | consentement/provenance essentiels |
| ORB/relay compromis | adresse d'une autre victime | dissimulation de l'origine et réputation empruntée | élevée | reproduction en laboratoire contrôlé uniquement |
| CDN/fronting/redirector | adresse front du CDN | protection de l'infrastructure backend | élevée | accord du fournisseur/propriétaire requis |
| Fast flux/DGA/dead drop | nœud/service tournant | résistance à la découverte de l'infrastructure | variable | reproduction en laboratoire contrôlé uniquement |
| Drop/nearest-neighbor | adresse proche de la cible | franchissement d'une frontière géographique/réseau | élevée | laboratoire sur site possédé uniquement |
| Store-and-forward/offline | gateway ou récepteur physique | réduction du lien temporel interactif | faible | spécifique à l'application |
| Pluggable/refraction transport | entrée Tor ou proxy de diversion coopérant | accessibilité résistante à la censure | variable | client pris en charge ou laboratoire de recherche |
| IPFS gateway/PIR/remote fetcher | gateway ou service applicatif | partitionnement éditeur/requête/demande | variable | application limitée |
| Anycast/QUIC/MPTCP | broker stable ou plusieurs sous-flux | rendezvous et continuité de session | élevée | disponibilité, pas anonymat |
| CI/CD automation runner | adresse du runner hébergé | egress jetable et traçable | élevée | workflow possédé uniquement |
| Non-IP local first hop | gateway de l'organisation | suppression de la pile Internet du capteur | faible | déploiement approuvé par le propriétaire |

## NAT partagé direct et NAT de niveau opérateur

**Mechanics :** plusieurs utilisateurs partagent une adresse publique ; le fournisseur d'accès associe les adresses et ports côté abonné au tuple public.

**Pros :** rapide ; aucun client spécial ; l'IP côté destination peut seulement identifier un foyer, un lieu ou un pool d'opérateur.

**Cons :** le fournisseur peut conserver les associations abonné/port/heure ; les comptes et fingerprints subsistent ; d'autres utilisateurs peuvent dégrader la réputation de l'adresse.

**Procedure :** (1) confirmer que l'accès autorisé utilise NAT/CGNAT ; (2) enregistrer l'IP publique et le port source exacts sur un endpoint possédé ; (3) séparer les identités applicatives ; (4) ne pas considérer l'adressage partagé comme un contrôle de confidentialité ; (5) utiliser un chemin plus fort si l'ISP ne doit pas connaître les destinations.

**Detection :** les destinations doivent conserver le port source et l'heure précise, pas uniquement l'IP. Les fournisseurs corrèlent les journaux d'allocation NAT ; les enquêteurs rapprochent les preuves liées au compte, à l'appareil et au navigateur.

## VPN commercial

**Mechanics :** une connexion chiffrée full-tunnel se termine au niveau du VPN ; les destinations voient son egress. Le VPN peut normalement associer la source, le timing et les destinations.

**Pros :** rapide ; simple ; protège contre l'observation passive locale ; exits stables ou partagés ; adapté à l'egress contrôlée de red team.

**Cons :** confiance concentrée ; télémétrie de facturation/connexion ; défaillances du kill-switch/DNS/IPv6 ; les exits partagés sont souvent bloqués selon leur réputation.

**Procedure :** (1) identifier le fournisseur, le propriétaire, la juridiction, la rétention et la politique d'évaluation ; (2) installer le client officiel signé ; (3) activer full tunnel, always-on et fail-closed ; (4) acheminer DNS et IPv6 délibérément ; (5) vérifier IPv4/IPv6/DNS observés sur un endpoint possédé ; (6) arrêter/reconnecter le tunnel et confirmer l'absence de fallback en clair.<sup>[[1]](#references)</sup>

**Detection :** les réseaux locaux voient un long flux chiffré vers l'infrastructure VPN ; les fournisseurs disposent des journaux d'authentification/connexion ; les destinations utilisent ASN/réputation ainsi que la corrélation des comptes, TLS/browser et comportements.

## Egress VPN auto-hébergée ou VPS louée

**Mechanics :** l'opérateur contrôle une gateway WireGuard/OpenVPN ou transfère le trafic via un serveur loué.

**Pros :** débit élevé prévisible ; adresse fixe pouvant être autorisée ; logs/firewall personnalisés ; bon contrôle des incidents.

**Cons :** faible ensemble d'anonymat ; tenant cloud, paiement, connexion source, API et historique d'image relient l'opérateur ; un nouveau serveur distinctif est facile à regrouper.

**Procedure :** (1) créer un projet d'organisation dédié à l'engagement ; (2) provisionner une image prise en charge et une adresse fixe ; (3) limiter l'administration à MFA/clé ; (4) configurer l'egress full-tunnel et DNS ; (5) n'autoriser que les destinations nécessaires lorsque possible ; (6) tester les fuites et les défaillances ; (7) conserver les audits du controller ; (8) détruire les identifiants et ressources à la fin.

**Detection :** corréler l'ASN d'hébergement, l'adresse vue pour la première fois, le fingerprint du certificat/service et le comportement de scan ; les propriétaires cloud utilisent les logs du control-plane, de la console, de la facturation et des flux.

## HTTP CONNECT, SOCKS et transfert SSH

**Mechanics :** une application demande à un proxy d'ouvrir un flux TCP ; SOCKS peut aussi transmettre la résolution de noms et l'UDP selon la version ; SSH transfère les flux dans une session chiffrée.

**Pros :** léger ; par application ; rapide ; utile pour le chaining et l'accès à des réseaux segmentés.

**Cons :** les applications peuvent le contourner ; le DNS peut fuir ; le proxy voit les endpoints adjacents ; l'état du navigateur subsiste ; les open proxies peuvent être des pièges ou des systèmes compromis.

**Procedure :** (1) déployer le proxy sur un hôte possédé ; (2) exiger l'authentification et limiter source/destination ; (3) configurer un profil d'application jetable ; (4) assurer la résolution DNS distante si nécessaire ; (5) vérifier avec un endpoint DNS/HTTP possédé ; (6) bloquer l'egress directe du workload ; (7) inspecter et faire tourner les identifiants du proxy.

**Detection :** identifier les processus capables de tunneling, la négociation CONNECT/SOCKS, les sessions SSH longues et les destinations incohérentes avec l'application ; les logs du proxy reconstruisent les flux.

## URL-rewriting web proxy et extension proxy de navigateur

**Mechanics :** un site récupère une destination et réécrit les liens/formulaires via sa propre origine, ou une extension dirige les requêtes du navigateur vers un proxy. La destination voit le service, tandis que le service peut voir le plaintext après terminaison TLS et injecter ou conserver du contenu.

**Pros :** aucun client système global ; rapide pour la navigation simple ; fonctionne lorsque l'installation d'un VPN est impossible.

**Cons :** le proxy peut lire les identifiants/contenus, réécrire les téléchargements et fingerprint les utilisateurs ; scripts/WebSockets/téléchargements peuvent contourner le proxy ; l'extension dispose de privilèges étendus ; petit ensemble d'anonymat et blocages fréquents.

**Procedure :** (1) utiliser uniquement un proxy exploité par l'organisation pour des tests autorisés ; (2) l'isoler dans un navigateur jetable sans comptes personnels ; (3) interdire la saisie de mots de passe et les téléchargements sensibles ; (4) vérifier que chaque subresource d'une page possédée passe par le proxy ; (5) tester WebSocket, téléchargement et formulaires ; (6) supprimer l'extension et le profil après usage.

**Detection :** la destination journalise le proxy ; le proxy/DNS d'entreprise et l'inventaire des extensions identifient le service ; les subresources de test et les rapports de sécurité révèlent les contournements directs ; les logs du proxy relient la session utilisateur aux cibles.

## Proxy multi-hop ou VPN multi-hop de fournisseur

**Mechanics :** une entrée voit la source tandis qu'un ou plusieurs relays de traversal la séparent d'un exit qui voit la destination.

**Pros :** aucun relay ordinaire ne doit connaître les deux extrémités ; la défaillance ou la saisie d'un nœud révèle moins d'informations ; géographie flexible.

**Cons :** l'administration et les logs partagés annulent la séparation ; latence ; corrélation temporelle ; davantage de défaillances et de routes DNS ; le même compte/paiement peut relier tous les hops.

**Procedure :** (1) définir quel observateur chaque hop doit éliminer ; (2) utiliser des relays possédés/approuvés et administrés indépendamment lorsque la séparation est importante ; (3) imposer un accès entry-only depuis le workload ; (4) faire en sorte que chaque relay ne puisse atteindre que le hop suivant ; (5) vérifier les logs de chaque couche ; (6) arrêter chaque hop et confirmer le fail-closed. Reproduire avec [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection :** corréler le timing/volume NetFlow adjacent, les handshakes de proxy répétés et l'infrastructure commune du controller ; ne pas déduire la géographie de l'opérateur à partir de l'exit.

## Split-knowledge application relay et OHTTP

**Mechanics :** le client chiffre un message HTTP stateless pour une gateway et l'envoie via un relay. Le relay voit l'IP du client mais pas la requête ; la gateway voit la requête mais normalement seulement l'IP du relay.

**Pros :** partition de confidentialité forte et vérifiable pour les requêtes prises en charge ; overhead inférieur à celui des réseaux d'anonymat généraux.

**Cons :** navigation arbitraire impossible ; cookies/authentification peuvent relier les requêtes ; la collusion relay/gateway et l'analyse du trafic subsistent ; l'application doit l'implémenter.

**Procedure :** (1) sélectionner une application prenant explicitement en charge RFC 9458 ; (2) vérifier les clés de la gateway via le chemin de configuration officiel ; (3) éviter les champs stables par utilisateur ; (4) envoyer uniquement la requête stateless prise en charge ; (5) comparer les logs du relay, de la gateway et de la cible ; (6) tester la rotation des clés et les défaillances sans fallback direct.<sup>[[2]](#references)</sup>

**Detection :** les endpoints d'entreprise exposent le processus initiateur et le relay OHTTP ; les gateways détectent les trafics malformés/rejoués ; le timing et les champs stables de payload/compte peuvent corréler les requêtes.

## MASQUE CONNECT-UDP/CONNECT-IP et HTTP privacy proxies

**Mechanics :** HTTP Extended CONNECT sur TLS/QUIC transporte des paquets UDP ou IP via un proxy. Il peut implémenter un tunnel moderne similaire à un VPN et mélanger le transport à HTTP/3, mais le proxy reste un observateur.<sup>[[3]](#references)</sup>

**Pros :** multiplexage/roaming efficaces ; prise en charge de l'UDP ou de l'IP complète ; déploiement via une infrastructure HTTP moderne.

**Cons :** ce n'est pas un réseau d'anonymat ; le proxy/compte voit la source et les destinations ; les fingerprints QUIC/HTTP et les chemins connus sont visibles par les endpoints/fournisseurs.

**Procedure :** (1) utiliser un client/service documentant la prise en charge de RFC 9298/9484 ; (2) authentifier le certificat/la configuration du proxy ; (3) définir les routes cibles autorisées ; (4) activer le DNS chiffré dans le chemin ; (5) vérifier UDP, TCP, IPv6 et le failover avec des endpoints possédés ; (6) inspecter les logs de requêtes et de flux du proxy.

**Detection :** les endpoints voient le processus client et l'interface virtuelle ; les réseaux peuvent classifier le QUIC/TLS soutenu vers un proxy ; les logs du proxy exposent la cible/le chemin CONNECT et les routes attribuées.

## Tor Browser

**Mechanics :** Tor sélectionne des relays guard, middle et exit ; le chiffrement en couches limite la visibilité de chaque relay. Tor Browser ajoute un navigateur standardisé destiné à résister au fingerprinting.

**Pros :** grand ensemble d'anonymat public ; aucun relay ordinaire ne connaît les deux extrémités ; unlinkability de la destination sans exploiter de serveurs.

**Cons :** plus lent ; principalement TCP ; réputation/blocages des exits ; les connexions et divulgations identifient l'utilisateur ; la corrélation temporelle low-latency subsiste.

**Procedure :** (1) télécharger et vérifier Tor Browser depuis le projet ; (2) conserver les paramètres par défaut et éviter les extensions ; (3) choisir un niveau de sécurité approprié ; (4) créer une identité/session distincte ; (5) éviter les comptes identifiants et les documents actifs externes ; (6) utiliser HTTPS ou des onion services authentifiés ; (7) vérifier l'exit uniquement avec un endpoint possédé.<sup>[[4]](#references)</sup>

**Detection :** les réseaux locaux peuvent identifier le trafic vers des guards connus sauf si un bridge/transport est utilisé ; les destinations voient les exits et le comportement de Tor Browser ; les observateurs de bout en bout corrèlent timing/volume.

## Tor bridges et pluggable transports

**Mechanics :** un bridge non public remplace le guard public ; obfs4, Snowflake ou WebTunnel modifie le transport du premier hop pour résister au blocage/probing simple.

**Pros :** contourne la censure et dissimule les destinations des relays publics évidents ; conserve le circuit Tor après l'entrée.

**Cons :** les patterns de transport et la découverte des bridges restent possibles ; performances variables ; aucune protection supplémentaire contre les comptes ou le timing global.

**Procedure :** (1) essayer d'abord Tor directement ; (2) dans les paramètres Connection de Tor Browser, sélectionner un transport pris en charge intégré ou demander un bridge officiel ; (3) ne pas utiliser de binaires/listes aléatoires ; (4) se connecter et effectuer un test bénin ; (5) tester la reconnexion et l'horloge ; (6) conserver tous les autres paramètres du navigateur standard.<sup>[[5]](#references)</sup>

**Detection :** les censeurs utilisent la découverte de destinations, la classification des protocoles/flux et le probing actif ; les défenseurs doivent distinguer l'utilisation de la circumvention d'une compromission et s'appuyer sur le processus/contexte du endpoint.

## VPN avant Tor et Tor avant VPN

**Mechanics :** VPN-before-Tor dissimule l'utilisation directe de Tor à l'ISP d'accès mais expose la source au VPN. Tor-before-VPN donne au VPN le trafic post-Tor et souvent une identité client/tunnel stable.

**Pros :** élimine un observateur précis lorsque la conception est correcte ; peut atteindre des réseaux qui bloquent une couche.

**Cons :** complexité, fingerprint inhabituel, fuites, ensemble d'anonymat réduit et fausse confiance ; Tor Project considère ces combinaisons comme avancées.<sup>[[6]](#references)</sup>

**Procedure :** (1) écrire l'observateur éliminé et le nouvel observateur introduit ; (2) utiliser un environnement jetable ; (3) établir uniquement le chemin externe prévu ; (4) imposer les routes du firewall ; (5) vérifier DNS/IPv4/IPv6 et chaque ordre de défaillance ; (6) comparer la visibilité des deux fournisseurs ; (7) abandonner la pile si elle n'offre aucun avantage mesurable.

**Detection :** les observateurs local/VPN/Tor voient des couches adjacentes différentes ; le timing reste de bout en bout ; les fingerprints de tunnels imbriqués et les comptes fournisseurs peuvent relier les sessions.

## Onion service

**Mechanics :** le client et le service construisent tous deux des circuits Tor vers un rendezvous, ce qui dissimule l'IP du service et évite un exit.

**Pros :** protection de la source et de la localisation du service ; authentification onion de bout en bout ; aucun port entrant public ; autorisation client optionnelle.

**Cons :** les mises à jour/analytics/erreurs peuvent divulguer l'origine ; la clé onion est critique ; l'identité applicative, le timing et la compromission de l'hôte subsistent.

**Procedure :** (1) isoler l'application et la lier uniquement à loopback/socket ; (2) installer Tor pris en charge ; (3) configurer un onion service v3 selon les instructions officielles ; (4) protéger/sauvegarder sa clé uniquement si une identité stable est nécessaire ; (5) ajouter l'autorisation client pour un usage fermé ; (6) supprimer les fetches tiers ; (7) vérifier extérieurement que l'origine n'est pas accessible.<sup>[[7]](#references)</sup>

**Detection :** les défenseurs hôte/réseau trouvent le processus/configuration Tor et les circuits sortants ; les erreurs applicatives, DNS, certificats ou ressources tierces peuvent exposer l'origine.

## Services internes I2P

**Mechanics :** I2P utilise des tunnels entrants/sortants unidirectionnels distincts pour les destinations internes à l'overlay ; les outproxies vers Internet public ajoutent un point de confiance.

**Pros :** publication interne décentralisée ; aucune dépendance à un exit officiel ; chemins entrants/sortants séparés.

**Cons :** ne remplace pas le Web général ; écosystème plus restreint ; comportement de pair de longue durée ; l'outproxy peut observer la navigation publique.

**Procedure :** (1) installer depuis la source officielle ; (2) utiliser un contexte dédié ; (3) autoriser l'intégration et la stabilisation de la bande passante ; (4) accéder à un service I2P natif possédé ; (5) éviter les outproxies sauf nécessité explicite ; (6) vérifier que l'arrêt ne crée aucun fallback direct ; (7) inspecter les logs locaux des pairs et services.<sup>[[8]](#references)</sup>

**Detection :** les réseaux locaux voient un trafic de pairs persistant et le bootstrap ; les endpoints exposent les processus router/application ; les outproxies journalisent les exits.

## Mixnets

**Mechanics :** les paquets de taille fixe, le batching, les délais, le réordonnancement et le cover traffic réduisent la corrélation temporelle ; les gateways relient les applications.

**Pros :** meilleure résistance à l'analyse temporelle que les proxies low-latency ; utile pour les messages/transactions asynchrones.

**Cons :** latence, overhead de bande passante, déploiement plus restreint et limites applicatives ; les métadonnées de gateway/compte peuvent subsister.

**Procedure :** (1) sélectionner un client maintenu et une application prise en charge ; (2) lire le threat model réel ; (3) installer dans un compartment séparé ; (4) envoyer des données bénignes vers un endpoint possédé ; (5) mesurer latence/fiabilité et chemin de réponse ; (6) tester la défaillance de la gateway ; (7) ne jamais désactiver les délais/cover traffic uniquement pour gagner en vitesse.<sup>[[9]](#references)</sup>

**Detection :** les endpoints identifient le client ; les réseaux d'accès peuvent classifier les gateways et la cadence des paquets ; les gateways et exits observent les rôles adjacents, tandis qu'une corrélation plus large nécessite des fenêtres statistiques plus longues.

## GNUnet anonymous file sharing

**Mechanics :** GNUnet peut router les requêtes de publication/recherche/téléchargement via des pairs et ajouter du cover traffic selon un niveau d'anonymat. Sa documentation avertit que le niveau par défaut 1 n'exige pas de cover traffic et qu'une analyse puissante du trafic peut identifier l'origine.<sup>[[10]](#references)</sup>

**Pros :** partage anonyme décentralisé et natif de l'application ; exigence de cover traffic réglable.

**Cons :** ne constitue pas un accès Web anonyme ordinaire ; coûts de performance/stockage ; limites liées aux pairs et à l'analyse du trafic ; la documentation GNUnet VPN indique que son overlay IP n'offre pas un bon anonymat.

**Procedure :** (1) installer une build officielle maintenue ; (2) isoler un pair de test ; (3) limiter bande passante/stockage ; (4) publier un fichier de test unique et inoffensif avec un niveau d'anonymat choisi ; (5) le récupérer depuis un autre pair possédé ; (6) enregistrer cover traffic et latence ; (7) ne pas prétendre que le composant IP VPN offre un anonymat équivalent.

**Detection :** bootstrap des pairs, trafic overlay, datastore/processus local et identifiants de fichiers ; un observateur large peut analyser le volume du trafic par rapport au cover traffic.

## DNS chiffré, ODoH et ECH

**Mechanics :** DoH/DoT/DoQ chiffrent vers un resolver ; ODoH sépare l'adresse client et la requête entre proxy et resolver ; ECH chiffre le ClientHello TLS interne/nom du serveur.

**Pros :** supprime le DNS/SNI en clair de certains observateurs locaux ; ODoH partitionne la connaissance de la source et de la requête.

**Cons :** ne constitue pas un chemin d'anonymat IP ; resolver/proxy/serveur conservent leurs rôles ; l'IP de destination, le timing, le volume et le endpoint subsistent ; le fallback peut fuir.

**Procedure :** (1) choisir si le système, l'application ou le tunnel contrôle le DNS ; (2) activer le mode chiffré strict ou ODoH pris en charge ; (3) tester un domaine possédé unique ; (4) capturer localement pour confirmer l'absence de requête en clair ; (5) interrompre le resolver et vérifier le comportement attendu ; (6) pour ECH, confirmer dans les diagnostics serveur l'acceptation du ClientHello interne.<sup>[[11]](#references)</sup>

**Detection :** les logs du endpoint/resolver exposent les requêtes ; les réseaux identifient les endpoints de resolvers chiffrés et les flux de destination ; l'état ECH est visible par les endpoints/CDN même s'il est caché sur le chemin.

## Split-provider privacy relay

**Mechanics :** des produits tels que iCloud Private Relay utilisent une ingress qui connaît le client et une egress exploitée indépendamment qui connaît la destination, avec une gestion par région approximative.

**Pros :** séparation des connaissances avec peu de friction ; rapide ; protection DNS/Web intégrée pour le trafic pris en charge.

**Cons :** portée limitée au produit/à l'application ; le fournisseur de plateforme identifie toujours le client ; pas d'anonymat système arbitraire ; risques de collusion/juridiques et temporels.

**Procedure :** (1) confirmer les applications et types de trafic exacts pris en charge ; (2) activer la fonctionnalité dans un contexte de plateforme dédié lorsque cela est approprié ; (3) sélectionner le comportement régional ; (4) tester séparément Safari/DNS et les applications non prises en charge ; (5) inspecter l'adresse observée par la destination ; (6) tester les changements et défaillances réseau.<sup>[[12]](#references)</sup>

**Detection :** l'accès voit l'ingress ; la destination voit l'egress ; les logs de plateforme/relay et les comptes couvrent leurs couches respectives ; les applications non prises en charge exposent les chemins normaux.

## Remote browser, VDI, RDP ou jump host d'organisation

**Mechanics :** la navigation/l'exécution d'outils se déroule sur un système distant ; la destination voit son egress tandis que le fournisseur du workspace voit la connexion de l'opérateur et le control-plane.

**Pros :** rapide ; isole les contenus risqués ; egress stable et contrôlée ; état jetable et audit organisationnel fort.

**Cons :** le fournisseur/administrateur peut observer la session/le compte ; les canaux écran/presse-papiers/fichiers fuient ; le fingerprint du navigateur distant peut être unique ; l'utilisateur n'est pas anonyme pour le propriétaire du workspace.

**Procedure :** (1) créer un workspace possédé par l'organisation par engagement ; (2) exiger MFA et limiter l'administration ; (3) désactiver ou restreindre presse-papiers/upload/download ; (4) acheminer via une egress fixe approuvée ; (5) n'utiliser aucun IdP/sync personnel ; (6) n'exporter que les preuves examinées ; (7) détruire workspace et identifiants selon le calendrier.

**Detection :** les logs du fournisseur et de l'IdP relient l'utilisateur à la session ; les destinations regroupent l'egress/le navigateur du workspace ; les défenseurs d'entreprise identifient les protocoles de contrôle distant et les sessions cloud anormales.

## Wi-Fi public ou invité

**Mechanics :** le trafic sort via le NAT du lieu ou un tunnel démarré depuis celui-ci.

**Pros :** débit élevé et adresse partagée non domestique ; aucune infrastructure dédiée.

**Cons :** association au lieu/DHCP/portail, caméras, achats et preuves de localisation ; pairs/AP hostiles ; conditions d'utilisation ; risques physiques.

**Procedure :** (1) obtenir l'accès proposé aux invités et vérifier le SSID auprès du personnel ; (2) utiliser un appareil corrigé à faible confiance ; (3) désactiver le partage/auto-join et activer la MAC privée ; (4) compléter le portail sans identité réutilisée ; (5) démarrer un chemin VPN/Tor fail-closed ; (6) vérifier le trafic tethered ; (7) oublier le réseau.

**Detection :** le lieu corrèle AP, MAC, DHCP, portail et heure ; la destination voit le lieu/tunnel ; les enquêteurs combinent les preuves physiques et celles de l'appareil. Ne jamais contourner le contrôle d'accès.

## Travel router

**Mechanics :** un routeur possédé par l'opérateur rejoint le Wi-Fi/Ethernet du lieu et fournit un réseau interne isolé avec une politique de tunnel imposée.

**Pros :** isole les workstations ; kill switch/DNS centralisés ; réseau client cohérent ; protège les endpoints privilégiés des broadcasts locaux.

**Cons :** le routeur devient un fingerprint radio/DHCP stable ; surface d'attaque supplémentaire ; les portails captifs et le tethering peuvent contourner le tunnel.

**Procedure :** (1) mettre à jour le firmware pris en charge ; (2) définir des identifiants de gestion uniques et désactiver WAN admin/WPS/UPnP ; (3) configurer la MAC upstream privée lorsque c'est autorisé ; (4) créer un SSID interne séparé ; (5) imposer la politique firewall full-tunnel DNS/IPv6 ; (6) tester portail, reconnexion et défaillance du tunnel.

**Detection :** le lieu voit l'association du routeur et la forme du trafic ; le fingerprint RF/DHCP local l'identifie ; le fournisseur VPN voit la source du lieu.

## Cellulaire, SIM prépayée et eSIM

**Mechanics :** un modem utilise l'accès radio de l'opérateur et généralement son NAT ; une couche VPN/Tor peut modifier l'exit visible par la destination.

**Pros :** indépendant du réseau local filaire/Wi-Fi ; mobile ; débit élevé ; utile comme backhaul pour des drops autorisés.

**Cons :** l'opérateur connaît l'abonné/eSIM, l'IMSI, l'IMEI, les cellules, l'heure et les ports attribués ; les lois d'enregistrement varient ; la co-localisation avec un téléphone personnel relie les appareils.

**Procedure :** (1) obtenir le service licitement avec les informations requises exactes ; (2) utiliser un modem/appareil séparé appartenant à l'organisation ; (3) l'enregistrer auprès du controller de l'exercice ; (4) désactiver les radios/comptes sans rapport ; (5) établir le tunnel approuvé ; (6) vérifier que les clients tethered le suivent réellement ; (7) vérifier les hypothèses du fournisseur et de rétention avant le déplacement.<sup>[[13]](#references)</sup>

**Detection :** journaux opérateur et localisation RF ; inventaire USB/PCI/MDM d'entreprise et sondes de hotspots malveillants ; timing destination/tunnel.

## Satellite Internet et abus de downlink satellite

**Mechanics :** le service normal utilise un terminal/fournisseur enregistré. L'ancien abus DVB-S one-way permettait à un récepteur situé dans un faisceau d'observer du trafic downlink non chiffré destiné à un abonné légitime, tout en utilisant un autre chemin pour les requêtes sortantes.

**Pros :** couverture étendue ; dernier kilomètre indépendant ; l'abus historique one-way pouvait attribuer à tort le C2 à la géographie d'un abonné.

**Cons :** équipements/RF/journaux fournisseur ; latence et couverture ; les systèmes bidirectionnels modernes diffèrent ; le chemin sortant et le routage asymétrique restent des preuves.

**Procedure :** pour un accès licite, enregistrer un terminal possédé et tunneler le trafic selon les besoins. Pour émuler le comportement historique de Turla, rejouer des captures synthétiques one-way dans un laboratoire sans RF et vérifier si les analystes détectent une réponse vers un hôte n'ayant effectué aucune requête ; ne pas intercepter le trafic satellite réel.<sup>[[14]](#references)</sup>

**Detection :** télémétrie fournisseur/terminal, radiogoniométrie RF, flux impossibles/asymétriques, incohérence RTT/routage et configuration du malware.

## Residential/mobile proxy ou proxyware avec consentement

**Mechanics :** une gateway backconnect attribue des exits broadband/mobile grand public, persistants ou tournants. La fourniture peut être consentie, incluse de manière trompeuse ou malveillante.

**Pros :** débit élevé ; choix géographique ; ASN grand public évitant certains blocages d'hébergement ; pools importants.

**Cons :** risques de provenance/consentement et juridiques ; le broker voit le client ; les exits infectés nuisent aux victimes ; la rotation crée des anomalies ; solution coûteuse et peu fiable.

**Procedure :** utiliser uniquement des agents possédés par l'organisation et fondés sur un consentement documenté pour l'émulation : (1) inscrire les endpoints de test ; (2) inventorier propriétaires/IP ; (3) configurer une gateway ; (4) faire tourner les modes sticky/par-request ; (5) envoyer uniquement vers une cible possédée ; (6) comparer les logs gateway/exit/cible ; (7) supprimer chaque agent.

**Detection :** déplacements impossibles, navigateur/compte stable malgré des changements rapides d'IP/ASN, protocoles backconnect, artefacts processus/réseau proxyware et relations broker/controller.

## ORB, botnet et relays edge-device compromis

**Mechanics :** des routeurs/IoT/serveurs loués ou compromis forment des rôles d'accès, de traversal et d'exit administrés comme une flotte. Plusieurs clients APT peuvent la partager.

**Pros :** réputation/géographie empruntées ; exits de courte durée ; mesh multi-hop résilient ; lien direct acteur-IP faible.

**Cons :** victimisation criminelle ; patterns implant/controller et flotte ; saisie d'intermédiaires ; performances incohérentes ; journaux de l'opérateur/client.

**Procedure :** ne jamais compromettre de vrais appareils. Utiliser [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) : (1) créer des réseaux isolés d'entrée/transit/cible ; (2) ajouter des containers relay dual-homed possédés ; (3) transférer un seul port de test ; (4) envoyer une requête bénigne ; (5) vérifier que la cible ne voit que l'exit ; (6) faire tourner l'exit ; (7) supprimer tous les assets nommés.<sup>[[15]](#references)</sup>

**Detection :** suivre la topologie, les ports/services, les relations controller, les fingerprints d'implant et le cycle de vie des nœuds ; centraliser la télémétrie de configuration/flux/intégrité edge ; ne pas assimiler l'IP d'exit à l'acteur.

## CDN redirector, domain fronting et domainless fronting

**Mechanics :** un edge public ne transfère que le trafic correspondant à une grammaire ; le fronting place un SNI externe bénin et une autorité HTTP interne différente, ou un SNI vide, lorsque l'intermédiaire l'autorise.

**Pros :** dissimule/protège le backend ; edge mondial rapide ; mélange la destination à un service partagé ; basculement rapide.

**Cons :** le CDN voit tout le routage et le tenant ; de nombreux fournisseurs interdisent le fronting cross-tenant ; artefacts SNI/Host/processus/flux et de compte ; la réutilisation de configuration regroupe les campagnes.

**Procedure :** reproduire uniquement sur un reverse proxy possédé avec [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) : créer un certificat/edge local, router un Host incohérent vers une cible possédée, journaliser SNI et Host, envoyer des requêtes normales/incohérentes, puis supprimer les containers.<sup>[[16]](#references)</sup>

**Detection :** comparer SNI/ECH/Host/`:authority` au niveau de l'endpoint ou de l'edge terminant ; joindre le processus initiateur, le tenant/origin, la grammaire des requêtes et la cadence des flux.

## DNS dynamique, DGA, fast flux et double flux

**Mechanics :** DDNS met à jour un nom stable ; DGA produit des noms candidats changeants ; fast flux fait tourner les adresses de service avec un TTL faible ; double flux fait aussi tourner les name servers.

**Pros :** découverte résiliente ; remplacement rapide de l'infrastructure ; controller dissimulé derrière de nombreux nœuds.

**Cons :** le DNS crée une télémétrie centralisée ; entropie/NXDOMAIN/churn ; TTL faible et patterns ASN larges ; l'enregistrement et l'infrastructure autoritative subsistent.

**Procedure :** utiliser [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) : servir une zone possédée renvoyant des adresses RFC 5737 avec un TTL de cinq secondes, l'interroger de manière répétée, modifier l'époque synthétique et valider les analytics. Ne jamais diriger les enregistrements de test vers des tiers.<sup>[[17]](#references)</sup>

**Detection :** réponses/ASN uniques sur une fenêtre glissante, TTL médian, géographie, churn autoritatif, clusters NXDOMAIN/lexicaux/temporels DGA et processus de suivi ; exclure les CDN légitimes avec le contexte.

## Service Web légitime, dead-drop resolver et tasking one-way

**Mechanics :** un post public, repository, document, objet ou feed contient un endpoint ou une tâche courante encodée. Le client peut retourner les résultats par un autre canal.

**Pros :** service à forte réputation autorisé ; TLS ; rotation d'endpoint sans changer le binaire ; le tasking asymétrique gêne la corrélation simple des flux.

**Cons :** identifiants stables d'objet/compte/API ; journaux du fournisseur ; séquence décodage/follow-on ; le contenu peut être saisi ou modifié.

**Procedure :** utiliser [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) : héberger un pointeur encodé dans un container possédé, le récupérer/décoder depuis un client de courte durée, contacter un second service possédé, conserver les deux logs, puis supprimer l'environnement.

**Detection :** corréler le processus inhabituel → lecture de l'objet stable → décodage → nouvelle destination ; hacher/conserver le contenu et garder les chemins complets des objets, pas seulement le domaine.

## Egress serverless, container éphémère et cloud-NAT

**Mechanics :** des fonctions/jobs de courte durée s'exécutent derrière le NAT d'un fournisseur ou un front ; le service logique reste stable tandis que les instances et adresses tournent.

**Pros :** déploiement/destruction rapides ; egress partagée à l'échelle du fournisseur ; peu de disque local ; routage régional élastique.

**Cons :** tenant, rôle, API, image, secret, invocation, facturation et logs front-origin sont persistants ; fingerprints de cold-start et de plateforme ; politique du fournisseur.

**Procedure :** (1) utiliser un tenant d'exercice possédé par l'organisation ; (2) déployer une fonction bénigne ne sollicitant qu'un endpoint possédé ; (3) enregistrer projet/rôle/image/configuration ; (4) invoquer plusieurs instances ; (5) comparer les IP cibles aux audit/request IDs ; (6) tester la rétention des logs ; (7) supprimer fonction, rôles et secrets.

**Detection :** logs cloud d'audit/invocation, création inhabituelle de rôles, egress partagée avec grammaire stable, réutilisation d'image/layer/secret et corrélation front-origin.

## Drop autorisé sur site

**Mechanics :** un petit ordinateur inventorié utilise le réseau filaire/Wi-Fi local et un rendezvous VPN/cellulaire sortant, en présentant une source locale.

**Pros :** test réaliste d'une origine interne ; débit élevé ; permet de tester NAC, inventaire physique et contrôles d'egress.

**Cons :** découverte/vol physique ; preuves serial/MAC/USB/DHCP/PoE/RF et caméra ; la perte peut exposer les identifiants.

**Procedure :** suivre [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) : (1) obtenir une autorisation écrite précise de placement ; (2) enregistrer serial, MAC, photo, emplacement et heure de récupération ; (3) utiliser une image minimale signée et des identifiants mutuels de courte durée ; (4) limiter destinations/capacités sortantes ; (5) ajouter quarantaine côté serveur et limites de bande passante ; (6) tester la visibilité SOC et la réponse à la perte ; (7) récupérer, préserver les preuves requises, puis assainir selon la politique convenue. Ne jamais en cacher un dans un lieu sans consentement.

**Detection :** NAC/802.1X, switchport/PoE/DHCP, inventaire USB, sondes RF, tunnel récurrent, réception/caméras et inspection physique.

## Pivot wireless nearest-neighbor

**Mechanics :** un acteur contrôle un hôte à portée radio de la cible, puis utilise les identifiants Wi-Fi de la cible pour franchir à distance la frontière. APT28 a utilisé cette méthode via des organisations compromises voisines.<sup>[[18]](#references)</sup>

**Pros :** aucun déplacement de l'opérateur ; la cible voit une source radio locale ; contourne les contrôles appliqués uniquement à l'entrée Internet.

**Cons :** nécessite un hôte dual-radio proche, compromis/possédé, et un accès valide ; preuves RADIUS/NAC/AP et endpoint voisin ; anomalies de signal/appareil.

**Procedure :** reproduire uniquement avec le [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) : joindre un pivot possédé aux SSID du voisin et de la cible dans le laboratoire, transférer un seul service, collecter les logs des deux AP et du pivot, puis activer EAP-TLS/device posture et confirmer l'échec de la seconde tentative.

**Detection :** corréler identité RADIUS, certificat/posture géré, appareil vu pour la première fois, bord/signal AP, connexion simultanée et présence physique ; rechercher sur les endpoints proches les radios simultanées, le forwarding et les tunnels.

## Community mesh, delay-tolerant et store-and-forward offline

**Mechanics :** le trafic traverse des pairs locaux, des gateways asynchrones, des supports amovibles ou des files planifiées plutôt qu'une session Internet interactive unique.

**Pros :** fonctionne pendant les perturbations/censures ; la livraison retardée/par lots affaiblit le timing simple ; aucun dernier kilomètre central pour les communications locales.

**Cons :** latence élevée ; petit ensemble d'anonymat ; métadonnées de garde/physiques ; pairs malveillants ; les données atteignent finalement une gateway qui les observe.

**Procedure :** (1) construire un mesh ou une file isolée à trois nœuds possédés ; (2) chiffrer/authentifier le contenu de bout en bout ; (3) supprimer les routes Internet directes de l'origine ; (4) relayer un fichier bénin après un délai contrôlé ; (5) vérifier que seule la gateway contacte la destination possédée ; (6) comparer garde et timestamps ; (7) préserver les preuves requises, puis assainir les supports/files temporaires lors de la clôture approuvée.

**Detection :** activité fichier/processus endpoint, liaisons radio de pairs, audit des supports amovibles, périodicité queue/gateway et identifiants de contenu. Des fenêtres de corrélation plus longues remplacent l'analyse des flux interactifs.

## Relay TURN et WebRTC forced-relay

**Mechanics :** Traversal Using Relays around NAT (TURN) alloue une adresse publique de relay et transporte du trafic UDP, TCP ou TLS entre un client et des pairs. Une politique ICE peut imposer l'utilisation du relay au lieu d'exposer un candidat direct. TURN résout l'accessibilité, pas l'anonymat général : le serveur authentifie le client et observe les allocations, pairs, heures et volumes.<sup>[[19]](#references)</sup>

**Pros :** largement implémenté ; gère les NAT restrictifs ; prend en charge WebRTC mobile ; le pair ne reçoit pas l'adresse de transport directe du client lorsque la politique relay-only est correctement imposée.

**Cons :** l'opérateur TURN voit les deux côtés adjacents ; l'identité applicative, le fingerprint média et la signalisation subsistent ; relay-only coûte en bande passante et latence ; une mauvaise configuration peut encore collecter les candidats host ou server-reflexive.

**Procedure :** (1) déployer un service TURN possédé par l'organisation avec TLS et des identifiants de courte durée ; (2) limiter realms, pairs, ports, quotas et expiration ; (3) configurer l'application de test en ICE relay-only ; (4) appeler un pair possédé ; (5) inspecter `getStats()` et la capture de paquets pour confirmer que seuls les candidats relay transportent le média ; (6) interrompre le relay et confirmer l'absence de fallback direct ; (7) conserver les logs d'allocation pour l'engagement.

**Detection :** signalisation, processus navigateur et allocations TURN relient la session au relay ; les réseaux observent les flux soutenus vers les ports TURN ou les endpoints TLS ; le pair voit le relay alloué. **Captured node :** l'état de l'application et les identifiants TURN éphémères peuvent révéler le realm et le service de rendezvous. Minimiser l'exposition avec des identifiants courts par appareil et conserver l'authentification opérateur uniquement au controller.

## Rendezvous outbound-only ou reverse overlay

**Mechanics :** un nœud derrière NAT initie une connexion authentifiée vers un broker contrôlé par l'organisation. L'opérateur s'authentifie séparément auprès du broker, qui autorise un canal de gestion étroit ; aucun port forwarding entrant ni route directe opérateur-nœud n'est requis.

**Pros :** stable derrière NAT et derniers kilomètres captifs ; révocation et audit centralisés ; les changements d'adresse du field node ne nécessitent pas de découverte par l'opérateur ; séparation nette entre identité opérateur et identifiant du nœud.

**Cons :** le broker devient un point de corrélation à forte valeur ; les keepalives périodiques sont reconnaissables ; un tunnel large peut devenir un pivot dangereux ; la perte du broker arrête la gestion.

**Procedure :** suivre [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) : émettre une identité d'appareil limitée, n'autoriser que le broker possédé et le service de gestion approuvé, utiliser un keepalive authentifié, imposer le routage fail-closed, tester les changements d'adresse et la récupération après reboot, puis révoquer l'identité pendant l'exercice de perte. WireGuard documente un keepalive persistant de 25 secondes comme intervalle NAT généralement utile lorsqu'il est réellement nécessaire.<sup>[[20]](#references)</sup>

**Detection :** les logs du broker et de l'IdP relient les deux côtés ; le réseau d'accès voit une destination/cadence chiffrée répétée ; l'inventaire du endpoint montre l'agent overlay. **Captured node :** considérer comme exposés sa clé d'appareil, le nom du broker, les adresses du tunnel et les tâches en cache. Il ne doit contenir aucune clé privée d'opérateur, compte personnel ou token réutilisable du controller.

## Pull mailbox, message queue ou object-store rendezvous

**Mechanics :** un workload de terrain interroge une mailbox authentifiée pour des jobs signés et préapprouvés, puis publie des résultats limités. L'opérateur écrit dans la queue via un control-plane séparé ; aucune socket interactive ne les relie.

**Pros :** tolère les liens intermittents ; découple timing et adressage ; quotas et schemas peuvent limiter les capacités ; audit et révocation centralisés faciles.

**Cons :** cadence de polling et noms stables d'objet/queue fingerprintent le système ; les logs du fournisseur relient producteur et consommateur ; contrôle retardé ; les données en queue capturées peuvent exposer l'exercice.

**Procedure :** (1) créer une queue d'engagement et une identité d'appareil ; (2) définir un schema signé de jobs bénins et explicitement limités ; (3) fixer le TTL des messages, la taille maximale des résultats et le débit ; (4) permettre au nœud de tirer uniquement sa queue et d'écrire uniquement son préfixe de résultats ; (5) tester l'accumulation offline, la livraison en double et la révocation ; (6) centraliser les logs d'accès immuables ; (7) supprimer la queue après satisfaction des exigences de rétention.

**Detection :** rechercher les appels API périodiques d'un processus inhabituel, les chemins stables bucket/object/queue, le même user-agent ou comportement TLS, et la séquence fetch-then-new-connection. **Captured node :** le cache local peut révéler les tâches en attente et les noms d'objets ; conserver le cache chiffré, limité et jetable, tout en préservant les logs faisant autorité du controller.

## Double uplink failover et connection migration

**Mechanics :** un field node approuvé possède deux uplinks indépendantes — par exemple Ethernet/Wi-Fi du lieu et cellulaire de l'organisation — et conserve sa session de contrôle via un overlay ou message broker lorsque les routes changent. Il s'agit d'ingénierie de disponibilité, pas d'anonymat.

**Pros :** survit à la défaillance d'un fournisseur, AP ou portail captif ; permet la maintenance planifiée ; autorise l'isolement rapide d'un chemin suspect.

**Cons :** deux fournisseurs créent deux enregistrements de localisation/compte ; l'utilisation simultanée facilite la corrélation ; fuites de route et DNS pendant le failover ; les preuves de co-localisation cellulaire subsistent.

**Procedure :** (1) enregistrer les deux interfaces et fournisseurs appartenant à l'organisation ; (2) attribuer des priorités de route et health checks déterministes vers des endpoints possédés ; (3) lier DNS et gestion à l'overlay ; (4) empêcher le chemin secondaire d'accepter du trafic entrant ; (5) débrancher chaque chemin et vérifier la récupération de session, la politique de source et l'absence d'accès direct à la destination ; (6) alerter lors des changements non planifiés ; (7) documenter l'utilisation des données et les limites de roaming.

**Detection :** corréler le même certificat d'appareil, la grammaire des requêtes et le timing entre les ASN ; l'inventaire local voit les deux radios ; opérateurs et lieux conservent leurs propres logs. **Captured node :** les deux identifiants SIM/appareil et les SSID connus peuvent être visibles ; utiliser des assets de l'organisation et ne jamais associer le nœud à des appareils personnels.

## APN privé d'organisation ou tunnel cellulaire géré

**Mechanics :** un APN privé opérateur place les SIM inscrites dans un domaine routé privé ou tunnelise le trafic vers une gateway d'entreprise. Il sépare l'appareil de l'Internet mobile public, mais ne le dissimule ni à l'opérateur ni à l'organisation contractante.

**Pros :** adressage privé stable ; inscription et politique du trafic au niveau opérateur ; évite l'exposition entrante publique ; utile pour les appliances distantes autorisées.

**Cons :** attribution forte par abonné, IMSI/IMEI, cellule et facturation ; délai et coût de procurement ; panne opérateur/gateway ; pas d'anonymat vis-à-vis de l'opérateur.

**Procedure :** (1) contracter l'APN au nom de l'organisation d'évaluation ; (2) autoriser uniquement les SIM enregistrées et préfixes de gateway ; (3) ajouter une authentification mutuelle au niveau applicatif ; (4) limiter la route APN au rendezvous et aux services de mise à jour ; (5) tester retrait SIM, roaming, sortie Internet publique et révocation ; (6) surveiller les logs opérateur et gateway ; (7) annuler ou mettre en quarantaine chaque SIM à la clôture.

**Detection :** inventaire opérateur et télémétrie cellule, flux gateway APN, mismatch SIM/IMEI et assets d'entreprise. **Captured node :** la SIM et le modem identifient le contrat même si le stockage est chiffré ; la résilience à la capture implique donc une suspension rapide et une autorisation étroite, pas la dénégation.

## Pont radio point à point longue portée

**Mechanics :** un Wi-Fi directionnel ou une autre radio point à point autorisée/non autorisée relie deux sites approuvés par les propriétaires, avec l'egress Internet sur le site distant. Il peut déplacer la localisation IP apparente sans proxy commercial.

**Pros :** débit élevé ; indépendance vis-à-vis des opérateurs filaires intermédiaires ; RF et routage contrôlables ; utile pour tester la segmentation et la surveillance des sites distants.

**Cons :** visibilité directe, spectre, contraintes du bailleur et réglementaires ; émissions RF et matériel distinctifs ; les deux endpoints sont des preuves physiques ; météo/alimentation/alignement affectent la stabilité.

**Procedure :** (1) obtenir l'autorisation écrite des deux sites et vérifier les règles de spectre/puissance ; (2) sonder le chemin sans transmettre hors des paramètres approuvés ; (3) utiliser le chiffrement authentifié et un VLAN de gestion ; (4) limiter le bridge à un rendezvous ou subnet de test possédé ; (5) tester failover, alignement, récupération après coupure et confinement RF ; (6) étiqueter/inventorier les deux radios ; (7) les retirer et vérifier la réinitialisation de configuration après l'exercice.

**Detection :** sondes RF, analyse du spectre, inspection des toits/sites, MAC/OUI du bridge, trafic de gestion et logs d'egress du site distant. **Captured node :** la configuration révèle son pair et son domaine de gestion ; utiliser des identifiants d'exercice uniques, aucun compte de gestion personnel et une révocation rapide de la clé du pair.

## Sortie coopérative ou communautaire avec consentement

**Mechanics :** des volontaires ou organisations partenaires exploitent volontairement des relays selon une politique publiée. Le trafic sort d'un pool communautaire partagé tandis que la couche de coordination gère les abus et la révocation.

**Pros :** réseaux divers hors cloud ; le consentement explicite est plus sûr que le proxyware ; la gouvernance partagée peut distribuer la confiance ; utile pour la recherche et les études de résistance à la censure.

**Cons :** petits pools et registres de membres réduisent l'anonymat ; les opérateurs d'exit reçoivent les plaintes et observent les métadonnées ; participants malveillants, disponibilité variable et juridictions différentes.

**Procedure :** (1) publier une politique d'utilisation acceptable et de logging ; (2) obtenir l'opt-in éclairé de chaque opérateur ; (3) fournir une identité de relay unique et limiter destinations/débits ; (4) prévoir la gestion des abus et la révocation en une action ; (5) envoyer uniquement du trafic autorisé vers des endpoints possédés pendant les tests ; (6) mesurer le churn et l'exposition à la corrélation ; (7) retirer proprement le relay lorsque le consentement cesse.

**Detection :** les enregistrements de membres/control-plane, certificats de relay, fingerprint logiciel commun et comportement de l'exit identifient le pool. **Captured node :** la configuration du relay peut identifier la coopération mais ne doit pas contenir les identités des clients ; conserver la responsabilité client-session au controller autorisé sous contrôle d'accès.

## Adresses temporaires IPv6 et rotation de préfixe

**Mechanics :** les extensions de confidentialité IPv6 créent des identifiants d'interface temporaires afin qu'une adresse stable ne soit pas réutilisée pour chaque connexion sortante. Les changements de préfixe fournisseur peuvent ajouter une rotation, mais le préfixe délégué, l'abonné et le fingerprint de couche supérieure subsistent.<sup>[[21]](#references)</sup>

**Pros :** réduit le suivi passif à long terme par un identifiant d'interface stable ; intégré aux systèmes courants ; aucun overhead de relay.

**Cons :** pas d'anonymat de source ; l'ISP et le réseau local connaissent toujours le préfixe/appareil ; DNS, comptes et état du navigateur relient les sessions ; le churn d'adresses complique les allowlists et les logs.

**Procedure :** (1) inspecter les adresses stables et temporaires actuelles sur un client possédé ; (2) activer le défaut d'adresse privée pris en charge par l'OS plutôt qu'un spoofing tiers ; (3) demander de manière répétée un endpoint IPv6 possédé durant plusieurs durées de vie ; (4) confirmer que les services entrants ne se lient qu'aux adresses stables prévues ; (5) conserver les logs DHCPv6/RA/neighbor et les logs précis des endpoints ; (6) tester le comportement VPN/firewall pour chaque adresse IPv6.

**Detection :** corréler préfixe délégué, identité couche 2, neighbor discovery, compte et télémétrie endpoint plutôt que traiter une adresse comme un appareil. **Captured node :** les profils réseau et identifiants d'interface subsistent ; l'adressage temporaire empêche un identifiant passif unique, pas l'attribution forensique.

## Tor pluggable transports : Snowflake, WebTunnel, obfs4 et meek

**Mechanics :** un pluggable transport modifie l'apparence de la première connexion Tor ou son accès à un bridge. Snowflake utilise des proxies WebRTC bénévoles de courte durée, WebTunnel ressemble à un HTTPS ordinaire, obfs4 résiste à l'identification simple du protocole et au probing actif, et meek relaie via une infrastructure Web prise en charge. Ce sont des transports de circumvention vers Tor, pas des couches d'anonymat supplémentaires de bout en bout.<sup>[[22]](#references)</sup>

**Pros :** utile lorsque Tor direct ou les relays connus sont bloqués ; Snowflake évite une adresse de bridge publique stable ; intégré aux clients Tor maintenus ; la destination reçoit toujours les propriétés ordinaires de Tor.

**Cons :** performances faibles ou variables ; broker/front/bridge et réseau local observent des métadonnées différentes ; les fingerprints de transport et le blocage restent possibles ; le proxy bénévole ne remplace pas Tor et ne doit pas être considéré comme fiable pour le plaintext applicatif.

**Procedure :** (1) installer et vérifier Tor Browser officiel ou un client Tor pris en charge ; (2) sélectionner le transport intégré dans Connection/Bridges ; (3) se connecter uniquement à une page de diagnostic possédée ; (4) confirmer que la page voit un exit Tor, et non le pair Snowflake/WebTunnel ; (5) comparer bootstrap et performances ; (6) interrompre le transport et confirmer que le client ne se connecte pas directement en silence ; (7) revenir à la configuration standard prise en charge après le test.

**Detection :** un censeur peut combiner allowlists de destinations, comportement TLS/WebRTC, découverte du broker et analyse des flux ; les endpoints exposent Tor et la configuration du transport. **Capture-resilient OPSEC :** utiliser le client standard, ne jamais y copier l'état d'un navigateur personnel et supposer que l'historique bridge/broker est récupérable. **Monitoring :** surveiller les logs de bootstrap Tor, les tentatives DNS/connexion directes inattendues et les observations de pages possédées côté controller ; l'échec du transport ne prouve pas la découverte.

## Refraction networking ou decoy routing

**Mechanics :** un opérateur réseau coopérant détecte un signal covert dans un trafic apparemment destiné à un decoy autorisé et détourne le flux vers un proxy de circumvention. Le déploiement nécessite une infrastructure sur le chemin réseau ; un client ne peut pas le créer simplement en sélectionnant un site innocent.<sup>[[23]](#references)</sup>

**Pros :** la destination apparente peut être difficile à bloquer pour un censeur sans dommages collatéraux ; aucune adresse publique de bridge à distribuer ; modèle de recherche utile pour la circumvention assistée sur le chemin.

**Cons :** participation spécialisée d'un ISP/transit ; déployabilité et performances dépendantes du routage ; le flux client-decoy et l'activité côté proxy subsistent ; un observateur global ou coopérant peut corréler le timing.

**Procedure :** ne pas signaler via des réseaux non impliqués. Reproduire l'architecture dans un laboratoire isolé : (1) créer des namespaces client, router, decoy et proxy possédés ; (2) utiliser une requête de test bénigne marquée ; (3) laisser le router possédé rediriger uniquement cette marque vers le proxy ; (4) journaliser les tuples et request IDs avant/après routage ; (5) comparer les flux ordinaires et signalés ; (6) tester les faux positifs et le retrait ; (7) détruire les routes du laboratoire.

**Detection :** les opérateurs réseau autorisés peuvent inspecter la divergence de routage, le comportement inhabituel du ClientHello/de la marque et les différences de flux decoy/backend. **Capture-resilient OPSEC :** un client de recherche ne doit contenir que des clés de test et des adresses documentaires. **Monitoring :** comparer les décisions signées du router de laboratoire aux arrivées du proxy ; ne pas sonder les fournisseurs de transit de production pour déterminer s'ils ont détecté le signal.

## Gateway content-addressed ou récupération depuis un pair en cache

**Mechanics :** une gateway HTTP récupère un content identifier IPFS (CID), éventuellement depuis son cache ou des pairs, et renvoie le contenu vérifiable au client. L'éditeur original peut voir la gateway ou d'autres pairs plutôt que le lecteur final ; la gateway voit l'IP du lecteur et le CID demandé. La récupération native peer-to-peer expose le client aux pairs et aux participants DHT/routing.<sup>[[24]](#references)</sup>

**Pros :** éditeur et lecteur peuvent être séparés par les caches ; le contenu immuable est vérifiable par hash ; les données répliquées survivent à un hôte ; les clients HTTP n'ont pas besoin d'une pile native de pairs.

**Cons :** les CID publics et logs de gateway révèlent les intérêts ; le timing de la première récupération peut corréler éditeur et lecteur ; contenu Web malveillant et risques same-origin liés aux chemins ; les gateways publiques sont best-effort et interdisent les abus.

**Procedure :** (1) publier un fichier de test inoffensif dans un swarm IPFS privé possédé ou une gateway possédée ; (2) enregistrer son CID ; (3) le récupérer via une gateway HTTP possédée séparée avec isolation par sous-domaine ; (4) vérifier les octets contre le CID ; (5) répéter après mise en cache ; (6) comparer les logs éditeur, pair et gateway ; (7) unpin et supprimer le contenu de test à la fin de la rétention.

**Detection :** les gateways journalisent source/CID ; les connexions DHT et pair révèlent la récupération ; l'historique endpoint et les hashes de fichiers identifient le contenu. **Capture-resilient OPSEC :** ne stocker aucune clé privée de publication sur un client de terrain en lecture seule et chiffrer le contenu sensible avant l'adressage par contenu. **Monitoring :** alerter en cas de pinning inattendu, changement d'ensemble de pairs, requêtes CID hors allowlist ou notifications d'abus de gateway.

## Service Private Information Retrieval

**Mechanics :** Private Information Retrieval (PIR) permet à un client de récupérer un enregistrement d'une base tout en masquant cryptographiquement l'index sélectionné au serveur selon un threat model à un ou plusieurs serveurs. Il protège la sélection de requête pour un dataset limité ; ce n'est ni un accès Web général ni un anonymat IP.<sup>[[25]](#references)</sup>

**Pros :** confidentialité forte des requêtes applicatives ; modèle de fuite mesurable ; utile pour les annuaires de clés, blocklists ou petites bases publiques ; peut réduire la nécessité de révéler les termes exacts de recherche.

**Cons :** coût de calcul/bande passante ; le serveur connaît l'heure/IP de connexion sauf combinaison avec un relay ; version du dataset, taille de réponse et état applicatif peuvent partitionner les utilisateurs ; maturité d'implémentation variable.

**Procedure :** (1) déployer une implémentation PIR auditée contre une base synthétique possédée ; (2) publier la version et les paramètres du dataset ; (3) récupérer plusieurs index avec des tailles de requête identiques ; (4) vérifier localement la correction ; (5) comparer les logs serveur et confirmer l'absence de l'index ; (6) tester les réponses malveillantes/tronquées et les mismatches de version ; (7) documenter l'hypothèse exacte de confidentialité plutôt que parler de navigation anonyme.

**Detection :** les réseaux voient l'utilisation du service et le volume ; la télémétrie endpoint expose le client et l'utilisation de l'enregistrement final ; un serveur compromis peut manipuler les datasets ou le timing. **Capture-resilient OPSEC :** conserver uniquement les paramètres publics de la base et un cache limité sur le client. **Monitoring :** valider les racines de dataset signées, les formes de requête fixes, les variations du taux d'erreur et les rotations de clés serveur.

## Fetcher, preview ou service de rendu server-side limité

**Mechanics :** un service distant récupère ou rend une URL et renvoie une capture, des métadonnées ou du contenu nettoyé. La destination voit l'adresse du fetcher ; le service voit le demandeur, l'URL et le résultat. Abuser de bots de link-preview, scanners de sécurité ou fetchers URL tiers ne constitue pas un usage autorisé de proxy.

**Pros :** isole le contenu actif de la workstation ; la destination reçoit un fingerprint de fetcher contrôlé ; limites possibles sur type de fichier, taille, destination et rendu ; environnement d'exécution jetable.

**Cons :** le service connaît toute la requête ; traces de compte/API/facturation ; risques SSRF et exfiltration ; scripts, authentification et sites interactifs peuvent ne pas fonctionner ; les URL uniques corrèlent demandeur et fetch.

**Procedure :** (1) déployer un fetcher possédé par l'organisation avec une allowlist stricte de domaines de test possédés ; (2) bloquer les adresses privées, link-local, metadata et les redirections vers des adresses non approuvées ; (3) limiter méthodes, redirections, octets et durée de rendu ; (4) supprimer credentials/cookies ; (5) soumettre une URL possédée ; (6) comparer les logs demandeur/fetcher/cible ; (7) détruire l'instance de rendu et conserver l'audit central selon la politique.

**Detection :** la cible voit l'ASN/fingerprint du service ; les logs fournisseur/controller relient le demandeur à l'URL ; les appels processus/API endpoint montrent la soumission. **Capture-resilient OPSEC :** utiliser un token de projet court sans autorité de destination arbitraire. **Monitoring :** alerter lors des refus allowlist, violations de redirection, fetches sans controller job ID et notifications d'abus du fournisseur.

## Anycast rendezvous pool

**Mechanics :** plusieurs nœuds contrôlés par l'organisation annoncent ou frontent une adresse de service stable, et le routage sélectionne une instance proche. Anycast améliore la disponibilité et dissimule un backend individuel au client, mais l'opérateur contrôle toutes les instances et l'adresse du service reste stable.<sup>[[26]](#references)</sup>

**Pros :** ingress régionale résiliente ; aucune reconfiguration terrain lorsqu'une instance échoue ; distribution DDoS/charge ; la politique centrale peut déplacer les sessions entre des nœuds connus.

**Cons :** les enregistrements BGP/CDN et fournisseur identifient l'organisation ; les changements de chemin peuvent interrompre les sessions stateful ; le monitoring varie selon l'emplacement du client ; une adresse stable est facile à bloquer ou à regrouper par réputation.

**Procedure :** utiliser un projet d'organisation pris en charge par le fournisseur ou un laboratoire de routage isolé : (1) déployer deux endpoints health authentifiés identiques ; (2) exposer une adresse de service documentée ; (3) conserver l'état de session au broker plutôt qu'à l'edge ; (4) retirer un nœud et vérifier la reconnexion ; (5) tester la cohérence des certificats, politiques et logs ; (6) alerter en cas d'origin/région non autorisé ; (7) retirer les annonces et identifiants à la clôture.

**Detection :** BGP/RPKI/historique, tenancy fournisseur, certificats et comportement identique du service identifient le pool. **Capture-resilient OPSEC :** un edge ne contient que l'identité de service régionale et aucune clé d'opérateur ou d'inscription de flotte. **Monitoring :** sonder chaque région depuis des monitors autorisés, comparer l'origine de route et le digest de configuration, et traiter toute origine inattendue comme un incident.

## Migration QUIC et continuité Multipath TCP

**Mechanics :** les connection IDs QUIC peuvent maintenir une session client lors d'un rebinding NAT ou changement d'adresse ; Multipath TCP peut transporter un flux d'octets fiable sur plusieurs subflows. Ils améliorent la continuité lors des transitions Wi-Fi/cellulaire mais exposent les anciens et nouveaux chemins au même pair et peuvent faciliter leur corrélation.<sup>[[27]](#references)</sup>

**Pros :** récupération plus rapide lors des changements d'uplink ; la session applicative n'a pas besoin de redémarrer ; MPTCP peut combiner résilience et débit ; utile aux field nodes approuvés.

**Cons :** pas d'anonymat ; le pair voit migration/subflows ; connection IDs et trafic simultané relient les chemins ; support variable des middleboxes/opérateurs ; les enregistrements fournisseurs supplémentaires augmentent l'exposition.

**Procedure :** (1) activer le transport pris en charge uniquement entre un client terrain possédé et le rendezvous ; (2) authentifier l'application indépendamment de l'IP ; (3) commencer un transfert limité sur Wi-Fi approuvé ; (4) basculer vers le cellulaire de l'organisation ; (5) confirmer la validation du chemin, l'intégrité des données et l'absence de fallback direct/en clair ; (6) tester timeout idle et retour ; (7) conserver les enregistrements broker de chaque transition de chemin.

**Detection :** le pair observe directement la migration d'adresse ou les subflows MPTCP ; les fournisseurs d'accès voient leur partie ; connection IDs, identité TLS et timing relient les deux. **Capture-resilient OPSEC :** ne stocker que le matériel de session lié à l'appareil et faire expirer rapidement l'état reprenable. **Monitoring :** alerter en cas de changements de chemin impossibles, réseaux simultanés non approuvés, tempêtes de migration et reprise après quarantaine.

## Egress de runner CI/CD géré ou automation éphémère

**Mechanics :** un workflow possédé par l'organisation exécute un contrôle réseau limité sur un runner hébergé. La destination voit une adresse de runner cloud tandis que la plateforme conserve repository, acteur, workflow, token, logs et attribution de facturation. Il s'agit d'une exécution distante avec egress traçable, pas d'anonymat vis-à-vis du fournisseur.<sup>[[28]](#references)</sup>

**Pros :** environnement propre et jetable ; définition reproductible du job ; aucune connexion entrante ; utile aux contrôles de disponibilité distribués géographiquement ; audit fort du controller.

**Cons :** plateforme et organisation identifient l'initiateur ; les tokens de workflow larges et pull requests non fiables sont dangereux ; réputation IP partagée ; logs/artifacts peuvent conserver secrets ou données cibles.

**Procedure :** (1) créer un repository et un environment privés de l'organisation pour l'évaluation ; (2) autoriser uniquement des jobs bénins, fixes et approuvés manuellement vers des endpoints possédés ; (3) utiliser des permissions workflow minimales en lecture seule et aucun secret de production ; (4) exécuter le contrôle ; (5) comparer les traces workflow, fournisseur et cible ; (6) vérifier que les artifacts ne contiennent aucun identifiant ; (7) supprimer le token d'environnement et conserver l'audit requis.

**Detection :** les logs d'audit fournisseur et workflow fournissent une attribution directe ; les cibles identifient les plages/ASN de runners et la grammaire stable des requêtes. **Capture-resilient OPSEC :** ne jamais placer de secrets de field device, signature, wallet ou cloud administrator dans les variables du runner. **Monitoring :** exiger l'approbation branch/environment et alerter en cas de modification workflow, exécution fork, lecture de secrets ou destination inattendue.

## Premier hop local non-IP vers une gateway possédée

**Mechanics :** Bluetooth mesh, Wi-Fi Aware/Direct, radio basse consommation ou liaison série/optique transportent des messages limités d'un capteur proche vers une gateway Internet approuvée par le propriétaire. Le field device n'a aucune route Internet ; la gateway est la seule egress. La portée radio et les limites de protocole en font une conception telemetry/store-and-forward, pas un Internet interactif anonyme.

**Pros :** retire la pile Internet et les identifiants du plus petit appareil de terrain ; faible consommation ; la gateway centralise la politique ; peut franchir des zones mortes temporaires.

**Cons :** découverte RF/physique, appairage et identifiants d'appareil ; bande passante et portée faibles ; la gateway relie tous les messages ; restrictions de spectre et de chiffrement variables ; une capture peut exposer les données en queue.

**Procedure :** (1) obtenir l'approbation du site et du spectre ; (2) appairer un capteur possédé à une gateway possédée avec des clés uniques ; (3) définir des types de messages signés de taille fixe, TTL et débit ; (4) ne donner au capteur aucune route IP par défaut ; (5) laisser la gateway transférer uniquement vers un collector possédé ; (6) tester replay, perte de portée et panne de gateway ; (7) inventorier et récupérer les deux appareils.

**Detection :** sonde RF, base d'appairage, inspection physique et logs de processus/flux de la gateway révèlent le chemin. **Capture-resilient OPSEC :** le capteur ne contient que sa clé pairwise et une queue chiffrée limitée, jamais d'identifiants opérateur, Wi-Fi, cellulaire ou controller. **Monitoring :** alerter en cas de nouveaux pairs, rollback de séquence, échec de clé, débit RF inhabituel et messages arrivant via une gateway non enregistrée.

## Matrice d'exposition à la capture/compromission

Ce tableau applique un contrôle de résilience à la capture à chaque famille ci-dessus. « Minimize » signifie réduire les secrets et le blast radius sur les assets autorisés ; cela ne signifie jamais effacer des preuves ni se cacher d'une enquête.

| Famille de techniques | Ce qu'un endpoint/relay capturé peut révéler | Contrôle autorisé minimal |
|---|---|---|
| NAT/CGNAT, Wi-Fi public, travel router | réseaux connus, historique DHCP/portail, MAC, pair du tunnel | appareil d'organisation séparé ; MAC privée si prise en charge ; aucun compte personnel ; inventaire controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | fournisseurs/noms d'hôte, clés, routes, logs et hop adjacent | une identité par engagement ; TTL court ; routes étroites ; révocation côté broker ; aucune clé maître |
| OHTTP/ODoH, MASQUE, split-provider relay | configuration relay/gateway, identifiants applicatifs et requêtes en cache | minimiser les identifiants de payload ; pin de la configuration approuvée ; cache limité ; absence stricte de fallback direct |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | logiciel installé, matériel bridge/onion, état local et historique des pairs | client standard ; clés de service séparées ; état chiffré minimal ; rotation de l'identité de service compromise |
| Remote browser/VDI/jump host | token workspace, presse-papiers/fichiers et tenant distant | MFA resistant au phishing à la gateway ; canaux de transfert désactivés ; révocation rapide de session |
| Cellulaire, satellite, APN privé | SIM/eSIM, identité IMEI/terminal, fournisseur et localisation approximative | contrat d'organisation ; aucune co-localisation personnelle ; politique APN/overlay étroite ; procédure de suspension fournisseur |
| Proxy résidentiel/cooperatif, ORB lab | identité agent, controller/next hop, trafic en cache | uniquement nœuds consentis/possédés ; agent signé ; identifiant par nœud ; mapping participant conservé par le controller |
| CDN/fronting, fast flux, serverless | tenant/origin/configuration, tokens API, références de déploiement/facturation | projet dédié ; rôle least-privilege ; token de déploiement court ; audit fournisseur conservé centralement |
| Dead drop, pull mailbox, store-and-forward | noms d'objets, queue, jobs/résultats en cache et données de garde | jobs signés et limités ; TTL ; cache chiffré ; identité producteur séparée ; logs serveur immuables |
| Drop, nearest-neighbor, bridge longue portée | serial/radio/SSID/pair, clé d'appareil, éléments physiques de placement | placement écrit ; identité d'appareil unique ; aucun secret opérateur ; télémétrie état/tamper ; révocation et récupération |
| TURN, reverse overlay, dual-uplink | realm/broker, identifiant appareil, pair/route et profils uplink | service outbound-only étroit ; identifiant appareil court ; login opérateur indépendant ; chemins fail-closed |
| Adressage temporaire IPv6 | profils, historique du préfixe et état endpoint/applicatif | le traiter uniquement comme anti-tracking ; conserver les logs réseau ; associer à une compartmentation endpoint |
| Pluggable transport/refraction lab | paramètres bridge/broker/decoy, état Tor et clés de recherche | client standard ou laboratoire isolé ; aucun état navigateur personnel ; aucun signal de production |
| IPFS/PIR/fetcher | CID/requête demandée, contenu en cache, token gateway/service | cache chiffré limité ; paramètres publics uniquement ; token de service court et allowlisté |
| Anycast/QUIC/MPTCP | nœuds de service, connection IDs, état reprenable et chemins connus | identité régionale uniquement ; courte durée de reprise ; révocation centralisée route/session |
| Runner CI/CD géré | repository, workflow, token fournisseur, logs et artifacts | workflow least-privilege ; aucun secret production/terrain/wallet ; approbation d'environnement |
| Hop local non-IP | pair radio, clé pairwise, messages en queue et identité gateway | clé pairwise unique ; schema de messages fixe ; aucun identifiant Wi-Fi/cellulaire/opérateur |

## Monitoring de la découverte possible pour chaque famille d'accès

Aucun test côté client ne prouve qu'un enquêteur ou un défenseur observe. Surveiller les changements dans les systèmes détenus par l'engagement, les corroborer avec le controller/client et arrêter plutôt que sonder les observateurs. Les lignes ci-dessous couvrent toutes les techniques précédentes ; les combiner avec les [états d'alerte des field nodes et la procédure de réponse](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Techniques couvertes | Signaux sûrs côté controller | Condition de quarantaine/arrêt |
|---|---|---|
| NAT/CGNAT, Wi-Fi public/invité, travel router, cellulaire/eSIM, satellite, APN privé | session lease/portail/opérateur, tuple public, changement BSSID/cellule/chemin, notification fournisseur | réseau/SIM/appareil non approuvé, déplacement inexpliqué ou escalade fournisseur/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, proxy résidentiel/cooperatif | authentification pair, état tunnel, fuites route/DNS, nouvel événement admin/API, plainte | identifiant dupliqué/volé, administrateur inconnu, fallback direct ou egress hors périmètre |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | allocation relay/gateway, version clé/configuration, connexion directe non prise en charge, taux erreur/replay | mismatch de clé, fallback direct, realm/pair inconnu ou notification d'abus |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | état bootstrap, échec circuit, descriptor onion/état service et page canary possédée | crossover vers compte personnel, connexion non-Tor inattendue ou clé de service compromise |
| I2P, mixnet, GNUnet, mesh/store-forward, hop local non-IP | ensemble de pairs, âge/séquence queue, arrivée gateway, association radio et hash contenu | pair/gateway inconnu, rollback de séquence, contenu non autorisé ou trace de garde manquante |
| Remote browser/VDI/jump host, runner CI/CD, serverless | session IdP, changement workflow/image/config, utilisation token, export/artifact et audit cloud | login/édition workflow inconnus, lecture secret, destination inattendue ou escalade projet/rôle |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventaire nœuds possédés, accès DNS/edge/objet, graphe controller, signature job et TTL | nœud/origin/éditeur d'objet inconnu, job non signé/rejoué, sortie de topologie du lab |
| Drop/nearest-neighbor/bridge longue portée/overlay sortant/dual uplink | heartbeat signé, hash boot/config, état boîtier, contexte AP/switch, identité dupliquée | nœud déplacé/ouvert, boot/hash/chemin inattendu, utilisation sentinel ou rapport du site |
| Adresses temporaires IPv6, migration QUIC, MPTCP | préfixe délégué, connection ID/subflows, validation chemin et session broker | migration impossible, chemins simultanés non approuvés ou reprise de session après révocation |
| IPFS/cache, PIR, fetcher limité | CID/forme requête/version racine, changement pair/gateway, refus redirect/allowlist | pin/query/destination inattendu, racine dataset non signée ou notification d'abus fournisseur |
| Refraction/decoy-routing lab, rendezvous anycast | décision de diversion possédée, arrivée proxy, origine BGP/RPKI, digest configuration régional | signal sur chemin de production, origine de route inconnue, incohérence région/configuration |

## Choisir et tester un chemin

1. Nommer l'observateur à éliminer et les données à dissimuler.
2. Sélectionner la famille la moins complexe qui l'élimine.
3. Dessiner les observateurs source, entrée, traversal, sortie, DNS, compte et paiement.
4. Utiliser une identité endpoint/application séparée.
5. Vérifier IPv4, IPv6, DNS, WebRTC/bypass applicatif et vue de la destination.
6. Interrompre chaque hop et confirmer que la défaillance est fermée.
7. Comparer les logs de chaque composant contrôlé.
8. Documenter les liens résiduels de timing, fournisseur, endpoint et éléments physiques.

## References

- [1] [EFF — Choisir le VPN qui vous convient](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Protections de Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Débloquer Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Utiliser Tor Browser avec un VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Présentation des onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Partage de fichiers anonyme](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Sécurité d'iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Enregistrement obligatoire des SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Les acteurs d'espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: persistance pour le traversal NAT et firewall](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Extensions d'adresses temporaires pour l'autoconfiguration d'adresses stateless IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports et bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — Recherche sur le projet et le déploiement](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Concepts de HTTP Gateway et cycle de vie d'une requête](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Présentation de Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Fonctionnement des services Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — Migration de connexion QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Référence des runners hébergés par GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
