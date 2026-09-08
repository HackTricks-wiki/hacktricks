# Catalogue des techniques d’accès anonyme à Internet

{{#include ../banners/hacktricks-training.md}}

Voici l’inventaire canonique des chemins d’accès. Il couvre les **familles** de protocoles et de procédures, et non tous les noms de fournisseurs. Aucun chemin Internet ne garantit l’anonymat : les preuves liées au compte, au navigateur, au endpoint, au timing, au paiement, au cloud-control-plane et à la présence physique peuvent compromettre une route qui semble parfaite.

Chaque entrée utilise les mêmes champs. « Procédure » désigne un déploiement licite ou une émulation dans un lab possédé. Lorsque la technique réelle dépend de la compromission d’un routeur, du vol d’un accès ou de l’abus d’un intermédiaire non consentant, la reproduction utilise des systèmes appartenant à l’exercice.

## Matrice de couverture

| Famille | Ce que voit la destination | Propriété la plus forte | Vitesse | Traitement |
|---|---|---|---|---|
| Shared NAT/CGNAT | adresse publique partagée | ambiguïté entre abonnés | élevée | déployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | adresse du relay | séparation rapide de l’adresse source | élevée | déployable |
| Multi-hop/split relay, MASQUE | proxy final | séparation des connaissances ou tunnel IP complet | élevée/modérée | déployable avec des relays de confiance |
| Tor, bridge, onion service | exit ou identité onion | chemin multi-parties et navigateur commun | modérée | déployable |
| I2P, GNUnet, mixnet | pair/passerelle overlay | résistance overlay ou au timing | faible/variable | spécifique à l’application |
| OHTTP/ODoH, Private Relay | gateway/egress | partitionnement source/requête | élevée | applications compatibles uniquement |
| Public Wi-Fi, travel router | adresse du lieu/tunnel | changement de localisation/chemin d’accès | élevée | autorisation requise |
| Cellular/eSIM, satellite | adresse opérateur/fournisseur | uplink physique indépendant | élevée/variable | l’abonnement et le fournisseur observent |
| Remote browser/jump host | workspace distant | séparation du endpoint et de l’egress | élevée | déployable |
| Residential/mobile proxy | adresse grand public/opérateur | apparence d’un réseau grand public | élevée | consentement/provenance essentiels |
| ORB/compromised relay | adresse d’une autre victime | dissimulation de l’origine et réputation empruntée | élevée | reproduction en lab possédé uniquement |
| CDN/fronting/redirector | adresse du CDN/front | protection de l’infrastructure back-end | élevée | accord du fournisseur/propriétaire requis |
| Fast flux/DGA/dead drop | nœud/service rotatif | résistance à la découverte de l’infrastructure | variable | reproduction en lab possédé uniquement |
| Drop/nearest-neighbor | adresse adjacente à la cible | franchissement d’une frontière géographique/réseau | élevée | lab sur site possédé uniquement |
| Store-and-forward/offline | gateway ou récepteur physique | réduction du lien temporel interactif | faible | spécifique à l’application |
| Pluggable/refraction transport | entrée Tor ou proxy de diversion coopérant | accessibilité résistante à la censure | variable | client compatible ou lab de recherche |
| IPFS gateway/PIR/remote fetcher | gateway ou service applicatif | partitionnement éditeur/requête/requêteur | variable | application limitée |
| Anycast/QUIC/MPTCP | broker stable ou subflows multiples | rendezvous et continuité de session | élevée | disponibilité, pas anonymat |
| CI/CD automation runner | adresse du runner hébergé | egress jetable et traçable | élevée | workflow possédé uniquement |
| Non-IP local first hop | gateway de l’organisation | suppression de la stack Internet du sensor | faible | déploiement approuvé par le propriétaire |

## NAT partagé direct et NAT de niveau opérateur

**Mécanique :** plusieurs utilisateurs partagent une adresse publique ; le fournisseur d’accès mappe les adresses et ports côté abonné vers le tuple public.

**Avantages :** rapide ; aucun client spécial ; l’IP seule côté destination peut n’identifier qu’un foyer, un lieu ou un pool opérateur.

**Inconvénients :** le fournisseur peut conserver les correspondances abonné/port/heure ; les comptes et fingerprints subsistent ; d’autres utilisateurs peuvent dégrader la réputation de l’adresse.

**Procédure :** (1) confirmer si l’accès autorisé utilise NAT/CGNAT ; (2) enregistrer l’IP publique et le port source exacts sur un endpoint possédé ; (3) séparer les identités applicatives ; (4) ne pas considérer l’adressage partagé comme un contrôle de confidentialité ; (5) utiliser un chemin plus fort si l’ISP ne doit pas connaître les destinations.

**Détection :** les destinations devraient conserver le port source et l’heure précise, pas seulement l’IP. Les fournisseurs corrèlent les logs d’allocation NAT ; les enquêteurs relient les preuves liées au compte, à l’appareil et au navigateur.

## VPN commercial

**Mécanique :** une connexion full-tunnel chiffrée se termine au VPN ; les destinations voient son egress. Le VPN peut normalement associer la source, le timing et les destinations.

**Avantages :** rapide ; simple ; protège contre l’observation passive locale ; exits stables ou partagés ; adapté à l’egress contrôlée de red-team.

**Inconvénients :** confiance concentrée ; télémétrie de facturation/connexion ; défaillances kill-switch/DNS/IPv6 ; les exits partagés sont souvent bloqués par réputation.

**Procédure :** (1) identifier le fournisseur, le propriétaire, la juridiction, la rétention et la politique d’évaluation ; (2) installer le client officiel signé ; (3) activer le full tunnel, l’always-on et le comportement fail-closed ; (4) gérer volontairement le DNS et l’IPv6 ; (5) vérifier l’IPv4/IPv6/DNS observés sur un endpoint possédé ; (6) arrêter/reconnecter le tunnel et confirmer l’absence de fallback en clair.<sup>[[1]](#references)</sup>

**Détection :** les réseaux locaux voient un long flux chiffré vers l’infrastructure VPN ; les fournisseurs disposent des logs d’authentification/connexion ; les destinations utilisent l’ASN/la réputation ainsi que la corrélation des comptes, du TLS, du navigateur et du comportement.

## VPN auto-hébergé ou egress VPS loué

**Mécanique :** l’opérateur contrôle une gateway WireGuard/OpenVPN ou transfère le trafic via un serveur loué.

**Avantages :** débit élevé prévisible ; adresse fixe autorisable ; logs/firewall personnalisés ; bon contrôle des incidents.

**Inconvénients :** faible ensemble d’anonymat ; le tenant cloud, le paiement, la connexion source, l’API et l’historique de l’image relient l’opérateur ; un nouveau serveur distinctif est facile à regrouper.

**Procédure :** (1) créer un projet d’organisation dédié à l’engagement ; (2) provisionner une image compatible et une adresse fixe ; (3) limiter l’administration à MFA/clé ; (4) configurer l’egress full-tunnel et le DNS ; (5) n’autoriser que les destinations nécessaires lorsque c’est possible ; (6) tester les leaks et les défaillances ; (7) conserver les logs d’audit du controller ; (8) détruire les identifiants et ressources lors du teardown.

**Détection :** corréler l’ASN d’hébergement, l’adresse vue pour la première fois, le fingerprint certificat/service et le comportement de scan ; les propriétaires cloud utilisent les logs du control-plane, de la console, de la facturation et des flux.

## HTTP CONNECT, SOCKS et forwarding SSH

**Mécanique :** une application demande à un proxy d’ouvrir un flux TCP ; SOCKS peut aussi transmettre la résolution de noms et UDP selon la version ; SSH transfère des flux dans une session chiffrée.

**Avantages :** léger ; par application ; rapide ; utile pour le chaining et l’accès à des réseaux segmentés.

**Inconvénients :** les applications peuvent le contourner ; le DNS peut fuiter ; le proxy voit les endpoints adjacents ; l’état du navigateur subsiste ; les open proxies peuvent être des pièges ou des systèmes compromis.

**Procédure :** (1) déployer le proxy sur un hôte possédé ; (2) exiger l’authentification et limiter source/destination ; (3) configurer un profil applicatif jetable ; (4) imposer la résolution DNS distante lorsque nécessaire ; (5) vérifier avec un endpoint DNS/HTTP possédé ; (6) bloquer l’egress directe du workload ; (7) inspecter et faire tourner les identifiants du proxy.

**Détection :** identifier les processus capables de tunneling, la négociation CONNECT/SOCKS, les longues sessions SSH et les destinations incohérentes avec l’application ; les logs du proxy reconstruisent les flux.

## Web proxy réécrivant les URL et extension proxy du navigateur

**Mécanique :** un site récupère une destination et réécrit les liens/formulaires via sa propre origine, ou une extension dirige les requêtes du navigateur vers un proxy. La destination voit le service, tandis que le service peut voir le plaintext après terminaison TLS et injecter ou conserver le contenu.

**Avantages :** aucun client système global ; rapide pour une navigation simple ; fonctionne lorsque l’installation d’un VPN est impossible.

**Inconvénients :** le proxy peut lire les identifiants/le contenu, réécrire les téléchargements et fingerprint les utilisateurs ; scripts/WebSockets/téléchargements peuvent contourner le proxy ; l’extension possède de larges privilèges ; petit ensemble d’anonymat et blocages fréquents.

**Procédure :** (1) utiliser uniquement un proxy géré par l’organisation pour un test autorisé ; (2) l’isoler dans un navigateur jetable sans comptes personnels ; (3) interdire la saisie de mots de passe et les téléchargements sensibles ; (4) vérifier que chaque sous-ressource d’une page possédée passe par le proxy ; (5) tester WebSocket, téléchargement et formulaires ; (6) supprimer l’extension et le profil après utilisation.

**Détection :** la destination journalise le proxy ; le proxy/DNS d’entreprise et l’inventaire des extensions identifient le service ; des sous-ressources canary contrôlées ou la Content Security Policy révèlent les contournements directs ; les logs du proxy associent la session utilisateur aux cibles.

## Proxy multi-hop ou VPN multi-hop du fournisseur

**Mécanique :** une entrée voit la source tandis qu’un ou plusieurs relays de transit la séparent d’un exit qui voit la destination.

**Avantages :** aucun relay ordinaire ne doit connaître les deux extrémités ; la défaillance ou la saisie d’un nœud révèle moins d’informations ; géographie flexible.

**Inconvénients :** une administration ou des logs partagés annulent la séparation ; latence ; corrélation temporelle ; davantage de défaillances et de routes DNS ; le même compte/paiement peut relier tous les hops.

**Procédure :** (1) définir quel observateur chaque hop élimine ; (2) utiliser des relays possédés/approuvés et administrés indépendamment lorsque la séparation est importante ; (3) imposer un accès limité à l’entrée depuis le workload ; (4) faire en sorte que chaque relay ne puisse atteindre que le hop suivant ; (5) vérifier les logs à chaque couche ; (6) arrêter chaque hop et confirmer le comportement fail-closed. Reproduire avec [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Détection :** corréler le timing/volume NetFlow adjacent, les handshakes proxy répétés et l’infrastructure commune du controller ; ne pas déduire la géographie de l’opérateur à partir de l’exit.

## Relay applicatif à connaissances séparées et OHTTP

**Mécanique :** le client chiffre un message HTTP stateless vers un gateway et l’envoie via un relay. Le relay voit l’IP du client mais pas la requête ; le gateway voit la requête mais normalement seulement l’IP du relay.

**Avantages :** partitionnement de confidentialité fort et auditable pour les requêtes compatibles ; overhead inférieur à celui des réseaux d’anonymat généraux.

**Inconvénients :** navigation arbitraire impossible ; cookies/authentification peuvent rétablir le lien ; collusion relay/gateway et analyse du trafic subsistent ; l’application doit l’implémenter.

**Procédure :** (1) sélectionner une application prenant explicitement en charge RFC 9458 ; (2) vérifier les clés du gateway via le chemin officiel de configuration ; (3) éviter les champs stables par utilisateur ; (4) envoyer uniquement la requête stateless compatible ; (5) comparer les logs du relay, du gateway et de la cible ; (6) tester la rotation des clés et les défaillances sans fallback direct.<sup>[[2]](#references)</sup>

**Détection :** les endpoints exposent le processus initiateur et le relay OHTTP ; les gateways détectent le trafic malformé/rejoué ; le timing et les champs stables du payload/compte peuvent corréler les requêtes.

## MASQUE CONNECT-UDP/CONNECT-IP et HTTP privacy proxies

**Mécanique :** HTTP Extended CONNECT sur TLS/QUIC transporte des paquets UDP ou IP via un proxy. Il peut implémenter un tunnel moderne comparable à un VPN et se fondre dans HTTP/3, mais le proxy reste un observateur.<sup>[[3]](#references)</sup>

**Avantages :** multiplexage/roaming efficaces ; prise en charge d’UDP ou de l’IP complète ; déploiement via une infrastructure HTTP moderne.

**Inconvénients :** ce n’est pas un réseau d’anonymat ; le proxy/compte voit la source et les destinations ; les fingerprints QUIC/HTTP et les chemins connus sont visibles par les endpoints/fournisseurs.

**Procédure :** (1) utiliser un client/service documentant la prise en charge de RFC 9298/9484 ; (2) authentifier le certificat/la configuration du proxy ; (3) définir les routes cibles autorisées ; (4) activer le DNS chiffré dans le chemin ; (5) vérifier UDP, TCP, IPv6 et le failover avec des endpoints possédés ; (6) inspecter les logs de requêtes et de flux du proxy.

**Détection :** les endpoints voient le processus client et l’interface virtuelle ; les réseaux peuvent classifier un QUIC/TLS soutenu vers un proxy ; les logs du proxy exposent la cible/le chemin CONNECT et les routes attribuées.

## Tor Browser

**Mécanique :** Tor sélectionne des relays guard, middle et exit ; le chiffrement en couches limite la vue de chaque relay. Tor Browser ajoute un navigateur standardisé destiné à résister au fingerprinting.

**Avantages :** grand ensemble public d’anonymat ; aucun relay ordinaire ne connaît les deux extrémités ; unlinkability de la destination sans héberger de serveur.

**Inconvénients :** plus lent ; principalement TCP ; réputation/blocages des exits ; les connexions et divulgations identifient l’utilisateur ; la corrélation temporelle low-latency subsiste.

**Procédure :** (1) télécharger et vérifier Tor Browser depuis le projet ; (2) conserver les valeurs par défaut et éviter les extensions ; (3) choisir un niveau de sécurité approprié ; (4) créer une identité/session séparée ; (5) éviter les comptes identifiants et les documents actifs externes ; (6) utiliser HTTPS ou des onion services authentifiés ; (7) vérifier l’exit uniquement avec un endpoint possédé.<sup>[[4]](#references)</sup>

**Détection :** les réseaux locaux peuvent identifier le trafic vers des guards connus lorsqu’aucun bridge/transport n’est utilisé ; les destinations voient les exits et le comportement de Tor Browser ; les observateurs de bout en bout corrèlent timing/volume.

## Tor bridges et pluggable transports

**Mécanique :** un bridge non public remplace le guard public ; obfs4, Snowflake ou WebTunnel modifie le transport du premier hop afin de résister au blocage et au probing simple.

**Avantages :** contourne la censure et masque les destinations évidentes de relays publics ; conserve le circuit Tor après l’entrée.

**Inconvénients :** les patterns de transport et la découverte des bridges restent possibles ; performances variables ; aucune protection supplémentaire contre les comptes ou le timing global.

**Procédure :** (1) essayer d’abord Tor directement ; (2) dans les paramètres Connection de Tor Browser, sélectionner un transport intégré compatible ou demander un bridge officiel ; (3) ne pas utiliser de binaires/listes aléatoires ; (4) se connecter et exécuter un test bénin ; (5) tester la reconnexion et l’horloge ; (6) conserver tous les autres paramètres du navigateur.<sup>[[5]](#references)</sup>

**Détection :** les censeurs utilisent la découverte des destinations, la classification du protocole/flux et le probing actif ; les défenseurs doivent distinguer l’usage de la circumvention d’une compromission et s’appuyer sur le processus/contexte du endpoint.

## VPN avant Tor et Tor avant VPN

**Mécanique :** VPN-before-Tor masque l’utilisation directe de Tor à l’ISP d’accès mais expose la source au VPN. Tor-before-VPN donne au VPN le trafic post-Tor et souvent une identité client/tunnel stable.

**Avantages :** élimine un observateur spécifique lorsqu’il est correctement conçu ; peut atteindre des réseaux qui bloquent une couche.

**Inconvénients :** complexité, fingerprint inhabituel, leaks, ensemble d’anonymat réduit et fausse confiance ; Tor Project considère ces combinaisons comme avancées.<sup>[[6]](#references)</sup>

**Procédure :** (1) écrire l’observateur éliminé et le nouvel observateur introduit ; (2) utiliser un environnement jetable ; (3) établir uniquement le chemin externe prévu ; (4) imposer les routes firewall ; (5) vérifier DNS/IPv4/IPv6 et l’ordre de chaque défaillance ; (6) comparer la visibilité des deux fournisseurs ; (7) abandonner la pile si elle n’offre aucun avantage mesurable.

**Détection :** les observateurs local/VPN/Tor voient différentes couches adjacentes ; le timing reste de bout en bout ; les fingerprints de tunnels imbriqués et les comptes fournisseurs peuvent relier les sessions.

## Onion service

**Mécanique :** le client et le service construisent tous deux des circuits Tor vers un rendezvous, masquant l’IP du service et évitant un exit.

**Avantages :** protection de la source et de la localisation du service ; authentification onion de bout en bout ; aucun port entrant public ; autorisation client facultative.

**Inconvénients :** les mises à jour, analytics et erreurs peuvent révéler l’origine ; la clé onion est critique ; l’identité applicative, le timing et la compromission de l’hôte subsistent.

**Procédure :** (1) isoler l’application et la lier uniquement à loopback/socket ; (2) installer Tor compatible ; (3) configurer un onion service v3 selon les instructions officielles ; (4) protéger/sauvegarder sa clé uniquement si une identité stable est nécessaire ; (5) ajouter l’autorisation client pour un usage fermé ; (6) supprimer les fetches tiers ; (7) vérifier extérieurement que l’origine n’est pas accessible.<sup>[[7]](#references)</sup>

**Détection :** les défenseurs de l’hôte/réseau trouvent le processus/configuration Tor et les circuits sortants ; les erreurs applicatives, le DNS, les certificats ou les ressources tierces peuvent révéler l’origine.

## Services internes I2P

**Mécanique :** I2P utilise des tunnels unidirectionnels d’entrée/sortie séparés pour les destinations de l’overlay ; les outproxies vers l’Internet public ajoutent un point de confiance.

**Avantages :** publication interne décentralisée ; aucune dépendance à un exit officiel ; chemins entrants/sortants séparés.

**Inconvénients :** ne remplace pas le Web général ; écosystème plus petit ; comportement des pairs sur longue durée ; l’outproxy peut observer la navigation publique.

**Procédure :** (1) installer depuis la source officielle ; (2) utiliser un contexte dédié ; (3) laisser stabiliser l’intégration et la bande passante ; (4) accéder à un service I2P natif possédé ; (5) éviter les outproxies sauf nécessité explicite ; (6) vérifier qu’un arrêt ne produit aucun fallback direct ; (7) inspecter les logs locaux de pairs et de service.<sup>[[8]](#references)</sup>

**Détection :** les réseaux locaux voient le trafic pair-à-pair persistant et le bootstrap ; les endpoints exposent les processus router/application ; les outproxies journalisent les exits.

## Mixnets

**Mécanique :** les paquets de taille fixe, le batching, les délais, le réordonnancement et le cover traffic réduisent la corrélation temporelle ; les gateways relient les applications.

**Avantages :** meilleure résistance à l’analyse temporelle que les proxies low-latency ; utile pour les messages/transactions asynchrones.

**Inconvénients :** latence, overhead de bande passante, déploiement plus limité et contraintes applicatives ; les métadonnées du gateway/compte peuvent persister.

**Procédure :** (1) sélectionner un client maintenu et une application compatible ; (2) lire le threat model réel ; (3) installer dans un compartiment séparé ; (4) envoyer des données bénignes vers un endpoint possédé ; (5) mesurer latence/fiabilité et chemin de réponse ; (6) tester la défaillance du gateway ; (7) ne jamais désactiver les délais/le cover traffic uniquement pour gagner en vitesse.<sup>[[9]](#references)</sup>

**Détection :** les endpoints identifient le client ; les réseaux d’accès peuvent classifier les gateways et la cadence des paquets ; les gateways et exits voient leurs rôles adjacents, tandis qu’une corrélation plus large exige des fenêtres statistiques plus longues.

## GNUnet anonymous file sharing

**Mécanique :** GNUnet peut router les requêtes de publication/recherche/téléchargement via des pairs et ajouter du cover traffic selon le niveau d’anonymat. Sa documentation indique que le niveau 1 par défaut n’exige pas de cover traffic et qu’une analyse puissante du trafic peut identifier l’origine.<sup>[[10]](#references)</sup>

**Avantages :** partage anonyme décentralisé et natif de l’application ; exigence de cover traffic réglable.

**Inconvénients :** ne fournit pas une navigation Web anonyme ordinaire ; coûts de performance/stockage ; limites liées aux pairs et à l’analyse du trafic ; la documentation GNUnet VPN indique que son overlay IP ne fournit pas un bon anonymat.

**Procédure :** (1) installer une build officielle maintenue ; (2) isoler un peer de test ; (3) limiter bande passante/stockage ; (4) publier un fichier de test inoffensif et unique avec un niveau d’anonymat choisi ; (5) le récupérer depuis un autre peer possédé ; (6) enregistrer cover traffic et latence ; (7) ne pas prétendre que le composant IP VPN fournit un anonymat équivalent.

**Détection :** bootstrap pair, trafic overlay, datastore/processus local et identifiants de fichiers ; un observateur large peut analyser le volume par rapport au cover traffic.

## DNS chiffré, ODoH et ECH

**Mécanique :** DoH/DoT/DoQ chiffre vers un resolver ; ODoH sépare l’adresse client et la requête entre proxy et resolver ; ECH chiffre le ClientHello TLS interne et le nom du serveur.

**Avantages :** supprime le DNS/SNI en clair pour certains observateurs locaux ; ODoH sépare la connaissance de la source et de la requête.

**Inconvénients :** ce n’est pas un chemin d’anonymat IP ; resolver/proxy/serveur conservent leurs rôles ; IP de destination, timing, volume et endpoint subsistent ; le fallback peut fuiter.

**Procédure :** (1) choisir si le DNS est géré par l’OS, l’application ou le tunnel ; (2) activer le mode chiffré strict ou ODoH compatible ; (3) tester un domaine possédé unique ; (4) capturer localement pour confirmer l’absence de requête en clair ; (5) arrêter le resolver et vérifier le comportement attendu ; (6) pour ECH, confirmer dans les diagnostics serveur l’acceptation du ClientHello interne.<sup>[[11]](#references)</sup>

**Détection :** les logs du endpoint/resolver exposent les requêtes ; les réseaux identifient les endpoints de resolvers chiffrés et les flux de destination ; l’état ECH est visible aux endpoints/CDN même lorsqu’il est masqué sur le chemin.

## Relay de confidentialité à fournisseurs séparés

**Mécanique :** des produits comme iCloud Private Relay utilisent une ingress qui connaît le client et une egress opérée indépendamment qui connaît la destination, avec une région approximative.

**Avantages :** séparation des connaissances avec peu de friction ; rapide ; protection DNS/Web intégrée pour le trafic compatible.

**Inconvénients :** portée limitée au produit et aux applications ; le fournisseur de plateforme identifie toujours le client ; pas d’anonymat système arbitraire ; risques de collusion, juridiques et temporels.

**Procédure :** (1) confirmer les applications et types de trafic réellement pris en charge ; (2) activer la fonction dans un contexte de plateforme dédié si nécessaire ; (3) sélectionner le comportement régional ; (4) tester séparément Safari/DNS et les applications non compatibles ; (5) inspecter l’adresse de destination ; (6) tester le changement de réseau et la défaillance.<sup>[[12]](#references)</sup>

**Détection :** l’accès voit l’ingress ; la destination voit l’egress ; les logs de plateforme/relay et les comptes couvrent leurs couches respectives ; les applications non compatibles exposent les chemins normaux.

## Remote browser, VDI, RDP ou jump host d’organisation

**Mécanique :** la navigation et l’exécution des outils ont lieu sur un système distant ; la destination voit son egress tandis que le fournisseur du workspace voit la connexion de l’opérateur et le control-plane.

**Avantages :** rapide ; isole le contenu risqué ; egress stable et contrôlée ; état jetable et audit organisationnel fort.

**Inconvénients :** le fournisseur/admin peut observer la session/le compte ; écran, presse-papiers et fichiers peuvent fuiter ; le fingerprint du navigateur distant peut être unique ; ce n’est pas anonyme pour le propriétaire du workspace.

**Procédure :** (1) créer un workspace possédé par l’organisation pour chaque engagement ; (2) exiger MFA et limiter l’administration ; (3) désactiver ou limiter presse-papiers/upload/download ; (4) passer par une egress fixe approuvée ; (5) n’utiliser aucun IdP/sync personnel ; (6) n’exporter que les preuves vérifiées ; (7) détruire le workspace et les identifiants selon le calendrier.

**Détection :** les logs du fournisseur et de l’IdP relient l’utilisateur à la session ; les destinations regroupent l’egress/le navigateur du workspace ; les défenseurs identifient les protocoles de contrôle distant et les sessions cloud anormales.

## Public ou guest Wi-Fi

**Mécanique :** le trafic sort via le NAT du lieu ou un tunnel initié depuis celui-ci.

**Avantages :** débit élevé et adresse partagée non résidentielle ; aucune infrastructure dédiée.

**Inconvénients :** preuves liées au lieu/DHCP/portail, caméras, achats et localisation ; pairs/AP hostiles ; conditions d’utilisation ; risques physiques.

**Procédure :** (1) obtenir l’accès proposé aux visiteurs et vérifier le SSID auprès du personnel ; (2) utiliser un appareil corrigé et à faible confiance ; (3) désactiver partage/auto-join et activer la MAC privée ; (4) compléter le portail sans identité réutilisée ; (5) démarrer un chemin VPN/Tor fail-closed ; (6) vérifier le trafic tethered ; (7) oublier le réseau.

**Détection :** le lieu corrèle AP, MAC, DHCP, portail et heure ; la destination voit le lieu/tunnel ; les enquêteurs combinent preuves physiques et liées à l’appareil. Ne jamais contourner un contrôle d’accès.

## Travel router

**Mécanique :** un routeur possédé par l’opérateur rejoint le Wi-Fi/Ethernet du lieu et fournit un réseau interne isolé avec une politique de tunnel imposée.

**Avantages :** isole les workstations ; kill switch/DNS centralisés ; réseau client cohérent ; protège les endpoints privilégiés des broadcasts locaux.

**Inconvénients :** le routeur devient un fingerprint radio/DHCP stable ; surface d’attaque supplémentaire ; portails captifs et tethering peuvent contourner le tunnel.

**Procédure :** (1) mettre à jour le firmware compatible ; (2) définir des identifiants de gestion uniques et désactiver WAN admin/WPS/UPnP ; (3) configurer une MAC upstream privée si autorisé ; (4) créer un SSID interne séparé ; (5) imposer une politique firewall full-tunnel DNS/IPv6 ; (6) tester le portail, la reconnexion et la défaillance du tunnel.

**Détection :** le lieu voit l’association du routeur et la forme du trafic ; le fingerprint RF/DHCP local l’identifie ; le fournisseur VPN voit la source du lieu.

## Cellular, prepaid SIM et eSIM

**Mécanique :** un modem utilise l’accès radio opérateur et généralement le NAT opérateur ; une couche VPN/Tor peut modifier l’exit visible par la destination.

**Avantages :** indépendant du réseau filaire/Wi-Fi local ; mobile ; débit élevé ; backhaul utile pour des drops autorisés.

**Inconvénients :** l’opérateur connaît l’abonné/eSIM, IMSI, IMEI, cellules, heures et ports attribués ; les lois d’enregistrement varient ; la co-localisation avec un téléphone personnel relie les appareils.

**Procédure :** (1) obtenir le service légalement avec les informations requises exactes ; (2) utiliser un modem/appareil séparé appartenant à l’organisation ; (3) l’enregistrer auprès du controller de l’exercice ; (4) désactiver les radios/comptes sans rapport ; (5) établir le tunnel approuvé ; (6) tester si les clients tethered le suivent réellement ; (7) vérifier les hypothèses du fournisseur et de rétention avant le déplacement.<sup>[[13]](#references)</sup>

**Détection :** logs opérateur et localisation RF ; inventaire USB/PCI/MDM et recherches de hotspots non autorisés ; timing de destination/tunnel.

## Satellite Internet et abus de downlink satellite

**Mécanique :** le service normal utilise un terminal/fournisseur enregistré. L’ancien abus DVB-S unidirectionnel permettait à un récepteur dans un faisceau d’observer du trafic downlink non chiffré destiné à un abonné légitime tout en utilisant un autre chemin pour les requêtes sortantes.

**Avantages :** large couverture ; dernier kilomètre indépendant ; l’abus historique unidirectionnel pouvait attribuer à tort un C2 à la géographie d’un abonné.

**Inconvénients :** équipement/RF/logs fournisseur ; latence et couverture ; les systèmes bidirectionnels modernes diffèrent ; le chemin sortant et le routage asymétrique restent des preuves.

**Procédure :** pour un accès licite, enregistrer un terminal possédé et tunneliser le trafic si nécessaire. Pour émuler le comportement historique de Turla, rejouer des captures synthétiques de paquets unidirectionnels dans un lab sans RF et vérifier si les analystes détectent une réponse vers un hôte n’ayant effectué aucune requête ; ne pas intercepter de trafic satellite réel.<sup>[[14]](#references)</sup>

**Détection :** télémétrie fournisseur/terminal, radiogoniométrie RF, flux impossibles/asymétriques, incohérences RTT/routage et configuration du malware.

## Proxy residential/mobile ou proxyware consenti

**Mécanique :** une gateway backconnect attribue des exits broadband/mobile grand public, fixes ou rotatifs. L’offre peut être consentie, intégrée de manière trompeuse ou malveillante.

**Avantages :** débit élevé ; choix géographique ; ASN grand public évitant certains blocages d’hébergement ; pools importants.

**Inconvénients :** risques de provenance/consentement et juridiques ; le broker voit le client ; les exits infectés nuisent aux victimes ; la rotation crée des anomalies ; coût et fiabilité variables.

**Procédure :** utiliser uniquement des agents appartenant à l’organisation et fondés sur un consentement documenté pour l’émulation : (1) inscrire les endpoints de test ; (2) inventorier propriétaires/IP ; (3) configurer une gateway ; (4) alterner les modes sticky/par-requête ; (5) envoyer uniquement vers une cible possédée ; (6) comparer les logs gateway/exit/cible ; (7) supprimer tous les agents.

**Détection :** déplacements impossibles, navigateur/compte stable malgré des changements rapides d’IP/ASN, protocoles backconnect, artefacts de processus/réseau proxyware et relations broker/controller.

## ORB, botnet et relays d’edge devices compromis

**Mécanique :** des routeurs/IoT/serveurs loués ou compromis forment des rôles d’accès, de transit et de sortie administrés comme une flotte. Plusieurs clients APT peuvent la partager.

**Avantages :** réputation/géographie empruntées ; exits courts ; mesh multi-hop résilient ; lien direct acteur-IP affaibli.

**Inconvénients :** victimisation criminelle ; patterns implant/controller et de flotte ; saisie d’intermédiaire ; performances irrégulières ; traces opérateur/client.

**Procédure :** ne jamais compromettre de vrais appareils. Utiliser [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) : (1) créer des réseaux isolés d’entrée/transit/cible ; (2) attacher des containers relay dual-homed possédés ; (3) transférer un seul port de test ; (4) envoyer une requête bénigne ; (5) vérifier que la cible ne voit que l’exit ; (6) faire tourner l’exit ; (7) supprimer tous les assets nommés.<sup>[[15]](#references)</sup>

**Détection :** suivre topologie, ports/services, relations controller, fingerprints d’implant et cycle de vie des nœuds ; centraliser la télémétrie de configuration/flux/intégrité ; ne pas assimiler l’IP de sortie à l’acteur.

## CDN redirector, domain fronting et domainless fronting

**Mécanique :** une edge publique ne transfère que le trafic correspondant à une grammaire ; le fronting place un SNI externe bénin et une autorité HTTP interne différente, ou un SNI vide, lorsque l’intermédiaire l’autorise.

**Avantages :** masque/protège le back-end ; edge mondiale rapide ; mélange la destination à un service partagé ; bascule rapide.

**Inconvénients :** le CDN voit tout le routage et le tenant ; de nombreux fournisseurs interdisent le fronting inter-tenant ; artefacts SNI/Host/processus/flux/compte ; la réutilisation de configuration regroupe les campagnes.

**Procédure :** reproduire uniquement sur un reverse proxy possédé avec [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) : créer un certificat/edge local, router un Host différent vers une cible possédée, journaliser SNI et Host, envoyer des requêtes normales/différentes, puis supprimer les containers.<sup>[[16]](#references)</sup>

**Détection :** comparer SNI/ECH/Host/`:authority` sur l’endpoint ou l’edge terminatrice ; relier processus initiateur, tenant/origine, grammaire des requêtes et cadence des flux.

## Dynamic DNS, DGA, fast flux et double flux

**Mécanique :** DDNS met à jour un nom stable ; DGA produit des noms candidats variables ; fast flux fait tourner les adresses de service avec un TTL faible ; double flux fait aussi tourner les nameservers.

**Avantages :** découverte résiliente ; remplacement rapide de l’infrastructure ; controller masqué derrière de nombreux nœuds.

**Inconvénients :** le DNS crée une télémétrie centralisée ; entropie/NXDOMAIN/churn ; TTL faible et patterns ASN larges ; l’enregistrement et l’infrastructure authoritative subsistent.

**Procédure :** utiliser [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) : servir une zone possédée renvoyant des adresses RFC 5737 avec un TTL de cinq secondes, l’interroger plusieurs fois, modifier l’epoch synthétique et valider les analytics. Ne jamais pointer des enregistrements de test vers des tiers.<sup>[[17]](#references)</sup>

**Détection :** réponses/ASNs uniques par fenêtre glissante, TTL médian, géographie, churn authoritative, clusters DGA NXDOMAIN/lexicaux/temporels et activité des processus ; exclure les CDN légitimes avec le contexte.

## Service Web légitime, dead-drop resolver et tasking unidirectionnel

**Mécanique :** un post, repository, document, objet ou feed public contient un endpoint ou une tâche courante encodée. Le client peut retourner les résultats par un autre canal.

**Avantages :** service à réputation élevée ; TLS ; rotation d’endpoint sans modifier le binaire ; le tasking asymétrique complique une corrélation simple des flux.

**Inconvénients :** identifiants stables d’objet/compte/API ; logs du fournisseur ; séquence décodage/follow-on ; contenu saisissable ou modifiable.

**Procédure :** utiliser [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) : héberger un pointeur encodé sur un container possédé, le récupérer/décoder depuis un client à courte durée de vie, contacter un second service possédé, conserver les deux logs, puis supprimer l’environnement.

**Détection :** corréler processus inhabituel → lecture d’objet stable → décodage → nouvelle destination ; hasher/conserver le contenu et retenir les chemins d’objets complets, pas seulement le domaine.

## Serverless, containers éphémères et egress cloud-NAT

**Mécanique :** des functions/jobs courts s’exécutent derrière le NAT du fournisseur ou une front ; le service logique reste stable tandis que les instances et adresses tournent.

**Avantages :** déploiement/destruction rapides ; egress partagée à l’échelle du fournisseur ; peu de disque local ; routage régional élastique.

**Inconvénients :** tenant, rôle, API, image, secret, invocation, facturation et logs front-origin sont durables ; fingerprints de cold start et de plateforme ; règles du fournisseur.

**Procédure :** (1) utiliser un tenant d’exercice appartenant à l’organisation ; (2) déployer une function bénigne interrogeant uniquement un endpoint possédé ; (3) enregistrer projet/rôle/image/configuration ; (4) invoquer plusieurs instances ; (5) comparer les IP cibles aux audit/request IDs ; (6) tester la rétention des logs ; (7) supprimer function, rôles et secrets.

**Détection :** logs cloud d’audit/invocation, création inhabituelle de rôles, egress partagée avec grammaire stable, réutilisation image/layer/secret et corrélation front-origin.

## Authorized on-site drop

**Mécanique :** un petit ordinateur inventorié utilise le réseau filaire/Wi-Fi local et un rendezvous VPN/cellulaire sortant, en présentant une source locale.

**Avantages :** test réaliste d’une origine interne ; débit élevé ; test du NAC, de l’inventaire physique et des contrôles d’egress.

**Inconvénients :** découverte/vol physique ; preuves serial/MAC/USB/DHCP/PoE/RF et caméras ; perte susceptible d’exposer les identifiants.

**Procédure :** suivre [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) : (1) obtenir une autorisation écrite précise de placement ; (2) enregistrer serial, MAC, photo, emplacement et heure de récupération ; (3) utiliser une image minimale signée et des identifiants mutualisés courts ; (4) limiter les destinations/capacités sortantes ; (5) ajouter quarantaine côté serveur et limites de bande passante ; (6) tester la visibilité SOC et la réponse à la perte ; (7) récupérer, préserver les preuves requises, puis assainir selon la politique convenue. Ne jamais en cacher un dans un lieu non consentant.

**Détection :** NAC/802.1X, switchport/PoE/DHCP, inventaire USB, relevé RF, tunnel récurrent, réception/caméras et inspection physique.

## Nearest-neighbor wireless pivot

**Mécanique :** un acteur contrôle un hôte à portée radio de la cible, puis utilise les identifiants Wi-Fi de la cible pour franchir la frontière à distance. APT28 a utilisé cette méthode via des organisations compromises voisines.<sup>[[18]](#references)</sup>

**Avantages :** aucun déplacement de l’opérateur ; la cible voit une source radio locale ; contournement des contrôles appliqués uniquement à l’entrée Internet.

**Inconvénients :** nécessite un hôte dual-radio compromis/possédé à proximité et un accès valide ; preuves RADIUS/NAC/AP et endpoint voisin ; anomalies de signal/appareil.

**Procédure :** reproduire uniquement avec le [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) : connecter un pivot possédé aux SSID lab voisin et cible, transférer un seul service, collecter les logs des deux AP/pivot, puis activer EAP-TLS/device posture et confirmer l’échec de la seconde tentative.

**Détection :** corréler identité RADIUS, certificat/posture géré, appareil vu pour la première fois, bord/signal AP, connexion simultanée et présence physique ; rechercher les endpoints voisins ayant simultanément radios, forwarding et tunnels.

## Mesh communautaire, delay-tolerant et store-and-forward offline

**Mécanique :** le trafic traverse des pairs locaux, gateways asynchrones, supports amovibles ou files planifiées plutôt qu’une session Internet interactive unique.

**Avantages :** fonctionne pendant une perturbation/censure ; livraison différée/groupée affaiblissant le timing simple ; aucun dernier kilomètre central pour les communications locales.

**Inconvénients :** forte latence ; petit ensemble d’anonymat ; métadonnées de garde/physiques ; pairs malveillants ; les données finissent par atteindre une gateway qui les observe.

**Procédure :** (1) construire un mesh ou une file de fichiers isolée à trois nœuds possédés ; (2) chiffrer/authentifier le contenu de bout en bout ; (3) supprimer les routes Internet directes de l’origine ; (4) relayer un fichier bénin après un délai contrôlé ; (5) vérifier que seule la gateway contacte la destination possédée ; (6) comparer garde et timestamps ; (7) préserver les preuves nécessaires, puis assainir les médias/files temporaires lors de la clôture approuvée.

**Détection :** activité fichier/processus endpoint, liens radio pairs, audit des supports amovibles, périodicité queue/gateway et identifiants de contenu. Des fenêtres de corrélation plus longues remplacent l’analyse des flux interactifs.

## TURN relay et WebRTC forced-relay

**Mécanique :** Traversal Using Relays around NAT (TURN) attribue une adresse relay publique et transporte du trafic UDP, TCP ou TLS entre un client et des pairs. Une politique ICE peut imposer l’utilisation du relay au lieu d’exposer un candidat direct. TURN résout l’accessibilité, pas l’anonymat général : le serveur authentifie le client et observe les allocations, pairs, heures et volumes.<sup>[[19]](#references)</sup>

**Avantages :** largement implémenté ; gère les NAT restrictifs ; prend en charge WebRTC mobile ; le pair ne reçoit pas l’adresse de transport directe du client lorsque la politique relay-only est correctement imposée.

**Inconvénients :** l’opérateur TURN voit les deux côtés adjacents ; identité applicative, fingerprint média et signaling subsistent ; relay-only coûte en bande passante et latence ; une mauvaise configuration peut encore collecter les candidats host ou server-reflexive.

**Procédure :** (1) déployer un service TURN possédé par l’organisation avec TLS et identifiants courts ; (2) limiter realms, pairs, ports, quotas et expiration ; (3) configurer l’application de test en ICE relay-only ; (4) appeler un pair possédé ; (5) inspecter `getStats()` et la capture de paquets pour confirmer que seuls les candidats relay transportent le média ; (6) arrêter le relay et confirmer l’absence de fallback direct ; (7) conserver les logs d’allocation pour l’engagement.

**Détection :** signaling, processus navigateur et allocations TURN relient la session au relay ; les réseaux observent les flux persistants vers les ports TURN ou endpoints TLS ; le pair voit le relay attribué. **Nœud capturé :** l’état applicatif et les identifiants TURN éphémères peuvent révéler le realm et le service de rendezvous. Réduire l’exposition avec des identifiants courts par appareil et conserver l’authentification opérateur uniquement au controller.

## Rendezvous outbound-only ou reverse overlay

**Mécanique :** un nœud derrière NAT initie une connexion authentifiée vers un broker contrôlé par l’organisation. L’opérateur s’authentifie séparément auprès du broker, qui autorise un canal de gestion étroit ; aucun port entrant ni chemin direct opérateur-nœud n’est requis.

**Avantages :** stable derrière les NAT et derniers kilomètres captifs ; révocation et audit centralisés ; les changements d’adresse du field node n’exigent aucune découverte par l’opérateur ; séparation nette entre identité opérateur et credential du nœud.

**Inconvénients :** le broker devient un point de corrélation critique ; les keepalives périodiques sont reconnaissables ; un tunnel large peut devenir un pivot dangereux ; la perte du broker arrête la gestion.

**Procédure :** suivre [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) : attribuer une identité appareil limitée, n’autoriser que le broker possédé et le service de gestion approuvé, utiliser un keepalive authentifié, imposer le routage fail-closed, tester les changements d’adresse et la récupération après reboot, puis révoquer l’identité pendant l’exercice de perte. WireGuard documente un keepalive persistant de 25 secondes comme intervalle NAT largement utile lorsqu’il est réellement nécessaire.<sup>[[20]](#references)</sup>

**Détection :** les logs du broker et de l’IdP relient les deux côtés ; le réseau d’accès voit une destination/cadence chiffrée répétée ; l’inventaire endpoint montre l’agent overlay. **Nœud capturé :** considérer comme exposés sa clé appareil, le nom du broker, les adresses du tunnel et les tâches mises en cache. Il ne doit contenir aucune clé privée d’opérateur, aucun compte personnel ni token controller réutilisable.

## Pull mailbox, message queue ou rendezvous object-store

**Mécanique :** un workload terrain interroge une mailbox authentifiée pour des jobs signés et préapprouvés, puis publie des résultats limités. L’opérateur écrit dans la queue via un control-plane séparé ; aucun socket interactif ne les relie.

**Avantages :** tolère les liens intermittents ; découple timing et adressage ; quotas et schémas limitent les capacités ; audit et révocation centralisés simples.

**Inconvénients :** cadence de polling et noms stables d’objet/queue fingerprintent le système ; les logs fournisseur relient producteur et consommateur ; contrôle différé ; les données en queue capturées peuvent exposer l’exercice.

**Procédure :** (1) créer une queue d’engagement et une identité appareil ; (2) définir un schéma signé de jobs bénins et explicitement limités ; (3) définir TTL, taille maximale des résultats et débit ; (4) autoriser le nœud à lire uniquement sa queue et écrire uniquement dans son préfixe de résultats ; (5) tester accumulation offline, livraison dupliquée et révocation ; (6) centraliser des logs d’accès immuables ; (7) supprimer la queue après la durée de rétention requise.

**Détection :** rechercher les appels API périodiques d’un processus inhabituel, les chemins bucket/object/queue stables, un user-agent ou comportement TLS identique et la séquence fetch puis nouvelle connexion. **Nœud capturé :** le cache local peut révéler jobs en attente et noms d’objets ; garder le cache chiffré, limité et jetable, tout en préservant les logs d’autorité du controller.

## Dual-uplink failover et connection migration

**Mécanique :** un field node approuvé possède deux uplinks indépendants — par exemple Ethernet/Wi-Fi du lieu et réseau cellulaire de l’organisation — et conserve sa session de contrôle via un overlay ou message broker lors du changement de route. Il s’agit d’ingénierie de disponibilité, pas d’anonymat.

**Avantages :** survit à la défaillance d’un fournisseur, AP ou portail captif ; facilite la maintenance planifiée ; permet d’isoler rapidement un chemin suspect.

**Inconvénients :** deux fournisseurs créent deux dossiers de localisation/compte ; l’utilisation simultanée facilite la corrélation ; leaks de route et DNS lors du failover ; les preuves de co-localisation cellulaire subsistent.

**Procédure :** (1) enregistrer les deux interfaces et fournisseurs appartenant à l’organisation ; (2) attribuer des priorités de route et health checks déterministes vers des endpoints possédés ; (3) lier DNS et gestion à l’overlay ; (4) empêcher le chemin secondaire d’accepter du trafic entrant ; (5) débrancher chaque chemin et vérifier récupération de session, politique source et absence d’accès direct ; (6) alerter sur les changements imprévus ; (7) documenter l’usage des données et les limites de roaming.

**Détection :** corréler le même certificat appareil, la grammaire des requêtes et le timing entre ASNs ; l’inventaire local voit les deux radios ; opérateurs et lieux conservent leurs propres logs. **Nœud capturé :** les deux identifiants SIM/appareil et SSID connus peuvent être visibles ; utiliser des assets d’organisation et ne jamais associer le nœud à des appareils personnels.

## Private APN d’organisation ou tunnel cellulaire géré

**Mécanique :** un private APN opérateur place les SIM inscrites dans un domaine routé privé ou tunnelise le trafic vers une gateway d’entreprise. Il sépare l’appareil de l’Internet mobile public mais ne le masque ni à l’opérateur ni à l’organisation contractante.

**Avantages :** adressage privé stable ; inscription et politique de trafic au niveau opérateur ; aucune exposition entrante publique ; utile pour des appliances distantes autorisées.

**Inconvénients :** attribution abonné/IMSI/IMEI/cellule/facturation forte ; délai et coût d’approvisionnement ; panne opérateur/gateway ; aucun anonymat vis-à-vis de l’opérateur.

**Procédure :** (1) contracter l’APN au nom de l’organisation évaluée ; (2) autoriser uniquement les SIM enregistrées et préfixes de gateway ; (3) ajouter une authentification mutuelle au niveau applicatif ; (4) limiter la route APN au rendezvous et aux services de mise à jour ; (5) tester retrait de SIM, roaming, breakout Internet public et révocation ; (6) surveiller les logs opérateur/gateway ; (7) annuler ou mettre en quarantaine chaque SIM lors de la clôture.

**Détection :** inventaire opérateur et télémétrie cellulaire, flux gateway APN, mismatch SIM/IMEI et dossiers d’assets d’entreprise. **Nœud capturé :** la SIM et le modem identifient le contrat même si le stockage est chiffré ; la résilience à la capture signifie donc suspension rapide et autorisation étroite, pas déni plausible.

## Pont radio point-à-point longue portée

**Mécanique :** du Wi-Fi directionnel ou une autre radio point-à-point sous licence ou non relie deux sites approuvés, avec l’egress Internet sur le site distant. Cela peut déplacer la localisation IP apparente sans proxy commercial.

**Avantages :** débit élevé ; indépendance vis-à-vis des opérateurs filaires intermédiaires ; RF et routage contrôlables ; utile pour tester la segmentation et la supervision de sites distants.

**Inconvénients :** ligne de vue, spectre, propriétaire et contraintes réglementaires ; émissions RF et matériel distinctifs ; les deux endpoints sont des preuves physiques ; météo/alimentation/alignement influencent la stabilité.

**Procédure :** (1) obtenir l’autorisation écrite des deux sites et vérifier les règles de spectre/puissance ; (2) étudier le chemin sans transmettre hors paramètres approuvés ; (3) utiliser chiffrement authentifié et VLAN de gestion ; (4) limiter le pont à un rendezvous ou subnet de test possédé ; (5) tester failover, alignement, récupération d’alimentation et confinement RF ; (6) étiqueter/inventorier les deux radios ; (7) les retirer et vérifier la réinitialisation de configuration après l’exercice.

**Détection :** relevés RF, analyse du spectre, inspection des toits/sites, MAC/OUI du bridge, trafic de gestion et logs d’egress du site distant. **Nœud capturé :** la configuration révèle son pair et son domaine de gestion ; utiliser des identifiants d’exercice uniques, aucun compte personnel de gestion et une révocation rapide de la clé pair.

## Cooperative ou community exit consenti

**Mécanique :** des volontaires ou organisations partenaires exécutent consciemment des relays selon une politique publiée. Le trafic sort d’un pool communautaire partagé tandis que la couche de coordination gère les abus et la révocation.

**Avantages :** réseaux non cloud variés ; consentement explicite plus sûr que proxyware ; gouvernance partagée pouvant distribuer la confiance ; utile à la recherche et aux études de résistance à la censure.

**Inconvénients :** petits pools et registres de membres réduisant l’anonymat ; les opérateurs d’exit reçoivent les plaintes et observent les métadonnées ; participants malveillants, disponibilité variable et juridictions différentes.

**Procédure :** (1) publier une politique d’utilisation et de logs ; (2) obtenir l’opt-in éclairé de chaque opérateur ; (3) attribuer une identité relay unique et limiter destinations/débits ; (4) fournir gestion des abus et révocation immédiate ; (5) n’envoyer que du trafic autorisé vers des endpoints possédés pendant le test ; (6) mesurer churn et exposition à la corrélation ; (7) supprimer proprement le relay lorsque le consentement prend fin.

**Détection :** registres de membres/control-plane, certificats relay, fingerprint logiciel commun et comportement d’exit identifient le pool. **Nœud capturé :** la configuration du relay peut identifier la coopérative mais ne doit pas contenir les identités client ; conserver la correspondance client-session au controller autorisé sous contrôle d’accès.

## Adresses IPv6 temporaires et rotation de préfixe

**Mécanique :** les extensions de confidentialité IPv6 créent des identifiants d’interface temporaires afin qu’une adresse stable ne soit pas réutilisée pour chaque connexion sortante. Les changements de préfixe fournisseur peuvent ajouter une rotation, mais le préfixe délégué, le dossier abonné et le fingerprint des couches supérieures subsistent.<sup>[[21]](#references)</sup>

**Avantages :** réduit le suivi passif à long terme par identifiant d’interface stable ; intégré aux OS courants ; aucun overhead de relay.

**Inconvénients :** pas d’anonymat source ; ISP et réseau local connaissent toujours préfixe/appareil ; DNS, comptes et état du navigateur relient les sessions ; le churn complique les allowlists et logs.

**Procédure :** (1) inspecter les adresses stables et temporaires sur un client possédé ; (2) activer le comportement d’adresse privée supporté par l’OS plutôt qu’un spoofing tiers ; (3) interroger à plusieurs reprises un endpoint IPv6 possédé pendant les durées d’adresse ; (4) confirmer que les services entrants se lient uniquement aux adresses stables prévues ; (5) conserver les logs DHCPv6/RA/neighbor et endpoint précis ; (6) tester VPN/firewall pour chaque adresse IPv6.

**Détection :** corréler préfixe délégué, identité couche 2, neighbor discovery, compte et télémétrie endpoint plutôt que considérer une adresse comme un appareil. **Nœud capturé :** profils réseau et identifiants d’interface subsistent ; l’adressage temporaire empêche un identifiant passif unique, pas l’attribution forensic.

## Tor pluggable transports : Snowflake, WebTunnel, obfs4 et meek

**Mécanique :** un pluggable transport modifie l’apparence de la première connexion Tor ou son accès à un bridge. Snowflake utilise des proxies WebRTC bénévoles de courte durée, WebTunnel ressemble à HTTPS ordinaire, obfs4 résiste à l’identification simple du protocole et au probing actif, et meek passe par une infrastructure Web compatible. Ce sont des transports de circumvention vers Tor, pas des couches supplémentaires d’anonymat de bout en bout.<sup>[[22]](#references)</sup>

**Avantages :** utile lorsque Tor direct ou les relays connus sont bloqués ; Snowflake évite une adresse bridge publique stable ; intégré aux clients Tor maintenus ; la destination reçoit toujours les propriétés ordinaires de Tor.

**Inconvénients :** performances réduites/variables ; broker/front/bridge et réseau local voient des métadonnées différentes ; fingerprints et blocages restent possibles ; le proxy bénévole ne remplace pas Tor et ne doit pas être considéré comme fiable pour le plaintext applicatif.

**Procédure :** (1) installer et vérifier Tor Browser officiel ou un client Tor compatible ; (2) sélectionner le transport intégré dans Connection/Bridges ; (3) se connecter uniquement à une page de diagnostic possédée ; (4) confirmer que la page voit un exit Tor et non le pair Snowflake/WebTunnel ; (5) comparer bootstrap et performances ; (6) désactiver le transport et confirmer l’absence de connexion directe silencieuse ; (7) revenir à la configuration standard après le test.

**Détection :** un censeur peut combiner allowlists de destinations, comportement TLS/WebRTC, découverte du broker et analyse des flux ; les endpoints exposent Tor et la configuration du transport. **OPSEC résiliente à la capture :** utiliser le client standard, ne jamais y copier un état de navigateur personnel et supposer que l’historique bridge/broker est récupérable. **Monitoring :** surveiller les logs bootstrap Tor, les tentatives DNS/connexion directes inattendues et les observations de pages possédées côté controller ; l’échec du transport ne prouve pas une découverte.

## Refraction networking ou decoy routing

**Mécanique :** un opérateur réseau coopérant détecte un signal secret dans un trafic apparemment destiné à un leurre autorisé et détourne le flux vers un proxy de circumvention. Le déploiement exige une infrastructure sur le chemin réseau ; un client ne peut pas le créer simplement en sélectionnant un site innocent.<sup>[[23]](#references)</sup>

**Avantages :** la destination apparente peut être difficile à bloquer sans dommages collatéraux ; aucune adresse de bridge public à distribuer ; modèle de recherche utile pour la circumvention assistée par le chemin.

**Inconvénients :** participation spécialisée ISP/transit ; déployabilité et performances dépendant du routage ; le flux client-leurre et l’activité côté proxy subsistent ; un observateur global ou coopérant peut corréler le timing.

**Procédure :** ne pas signaler via des réseaux non impliqués. Reproduire l’architecture dans un lab isolé : (1) créer des namespaces client, router, decoy et proxy possédés ; (2) utiliser une requête de test bénigne marquée ; (3) laisser le router possédé rediriger uniquement cette marque vers le proxy ; (4) journaliser les tuples avant/après routage et les request IDs ; (5) comparer flux ordinaires et signalés ; (6) tester faux positifs et suppression ; (7) détruire les routes du lab.

**Détection :** les opérateurs réseau autorisés peuvent inspecter divergence de routage, comportement inhabituel du ClientHello/de la marque et écarts entre flux decoy et back-end. **OPSEC résiliente à la capture :** un client de recherche ne doit contenir que des clés de test et adresses de documentation. **Monitoring :** comparer les décisions signées du router de lab aux arrivées du proxy ; ne pas sonder les transit providers de production pour déterminer s’ils ont détecté le signal.

## Gateway content-addressed ou récupération depuis un peer en cache

**Mécanique :** une gateway HTTP récupère un CID IPFS, éventuellement depuis son cache ou des pairs, et renvoie le contenu vérifiable au client. L’éditeur original peut voir la gateway ou d’autres pairs plutôt que le lecteur final ; la gateway voit l’IP du lecteur et le CID demandé. La récupération native peer-to-peer expose le client aux pairs et participants DHT/routage.<sup>[[24]](#references)</sup>

**Avantages :** éditeur et lecteur séparables par des caches ; contenu immuable vérifiable par hash ; données répliquées survivant à un hôte ; les clients HTTP n’exigent aucune stack native pair-à-pair.

**Inconvénients :** CIDs publics et logs gateway révèlent les intérêts ; le timing de la première récupération peut corréler éditeur et lecteur ; contenu Web malveillant et risques same-origin liés aux paths ; les gateways publiques sont best-effort et interdisent les abus.

**Procédure :** (1) publier un fichier de test inoffensif dans un swarm IPFS privé possédé ou une gateway possédée ; (2) enregistrer son CID ; (3) le récupérer via une gateway HTTP possédée séparée avec isolation par sous-domaine ; (4) vérifier les octets contre le CID ; (5) répéter après mise en cache ; (6) comparer les logs éditeur/peer/gateway ; (7) désépingler et supprimer le contenu après expiration de la rétention.

**Détection :** les gateways journalisent source/CID ; DHT et connexions peer révèlent la récupération ; historique endpoint et hashes de fichiers identifient le contenu. **OPSEC résiliente à la capture :** ne stocker aucune clé privée de publication sur un client terrain en lecture seule et chiffrer le contenu sensible avant content addressing. **Monitoring :** alerter sur pinning inattendu, changement d’ensemble de pairs, requêtes CID hors allowlist ou notifications d’abus de gateway.

## Private Information Retrieval service

**Mécanique :** Private Information Retrieval (PIR) permet à un client de récupérer un enregistrement d’une base tout en masquant cryptographiquement l’index sélectionné au serveur, selon un threat model mono- ou multi-serveur défini. Il protège la sélection de requête pour un dataset limité ; ce n’est ni un accès Web général ni un anonymat IP.<sup>[[25]](#references)</sup>

**Avantages :** confidentialité forte et spécifique à l’application ; modèle de fuite mesurable ; utile pour répertoires de clés, blocklists ou petites bases publiques ; réduit la nécessité de révéler les termes exacts.

**Inconvénients :** overhead calcul/bande passante ; le serveur connaît IP/heure de connexion sauf relay ; version du dataset, taille de réponse et état applicatif peuvent partitionner les utilisateurs ; maturité variable.

**Procédure :** (1) déployer une implémentation PIR auditée contre une base synthétique possédée ; (2) publier version et paramètres du dataset ; (3) récupérer plusieurs index avec des requêtes de taille identique ; (4) vérifier localement la correction ; (5) comparer les logs serveur et confirmer l’absence de l’index ; (6) tester réponses malveillantes/tronquées et mismatch de version ; (7) documenter l’hypothèse exacte de confidentialité plutôt que parler de navigation anonyme.

**Détection :** les réseaux voient l’usage du service et le volume ; la télémétrie endpoint expose le client et l’usage de l’enregistrement final ; un serveur compromis peut modifier datasets ou timing. **OPSEC résiliente à la capture :** ne conserver sur le client que les paramètres publics et un cache borné. **Monitoring :** valider les racines signées du dataset, les formes de requête fixes, les changements de taux d’erreur et les rotations de clés serveur.

## Fetcher, preview ou rendering service côté serveur contraint

**Mécanique :** un service distant récupère ou rend une URL et renvoie une capture, des métadonnées ou du contenu assaini. La destination voit l’adresse du fetcher ; le service voit le requêteur, l’URL et le résultat. Abuser des bots de link preview, scanners de sécurité ou fetchers tiers n’est pas un usage de proxy autorisé.

**Avantages :** isole le contenu actif de la workstation ; fingerprint contrôlé du fetcher côté destination ; limites de fichier, taille, destination et rendu ; environnement d’exécution jetable.

**Inconvénients :** le service connaît toute la requête ; comptes/API/facturation ; risques SSRF et exfiltration ; scripts, authentification et sites interactifs peuvent ne pas fonctionner ; les URLs uniques corrèlent requêteur et fetch.

**Procédure :** (1) déployer un fetcher possédé par l’organisation avec allowlist stricte de domaines de test possédés ; (2) bloquer adresses privées, link-local, metadata et redirections vers des adresses non autorisées ; (3) limiter méthodes, redirections, octets et durée de rendu ; (4) supprimer credentials/cookies ; (5) soumettre une URL possédée ; (6) comparer logs requêteur/fetcher/cible ; (7) détruire l’instance de rendu et conserver l’audit central selon la politique.

**Détection :** la cible voit l’ASN/fingerprint du service ; les logs fournisseur/controller relient requêteur et URL ; processus endpoint et appels API montrent la soumission. **OPSEC résiliente à la capture :** utiliser un token de projet court sans autorité sur des destinations arbitraires. **Monitoring :** alerter sur refus d’allowlist, violations de redirection, fetches sans job ID controller et notifications d’abus.

## Anycast rendezvous pool

**Mécanique :** plusieurs nœuds contrôlés par l’organisation annoncent ou frontent une adresse stable, et le routage sélectionne une instance proche. Anycast améliore la disponibilité et masque un back-end individuel au client, mais l’opérateur contrôle toutes les instances et l’adresse du service reste stable.<sup>[[26]](#references)</sup>

**Avantages :** ingress régionale résiliente ; aucune reconfiguration terrain lorsqu’une instance tombe ; distribution DDoS/charge ; politique centrale pouvant déplacer les sessions entre nœuds connus.

**Inconvénients :** les traces BGP/CDN et fournisseur identifient l’organisation ; les changements de chemin peuvent casser les sessions stateful ; le monitoring varie selon la localisation client ; une adresse stable est facilement bloquée ou regroupée par réputation.

**Procédure :** utiliser un projet d’organisation supporté par le fournisseur ou un lab de routage isolé : (1) déployer deux endpoints health authentifiés identiques ; (2) exposer une adresse de service documentée ; (3) conserver l’état de session au broker plutôt qu’à l’edge ; (4) retirer un nœud et vérifier la reconnexion ; (5) tester cohérence certificat/politique/logs ; (6) alerter sur toute origine/région non autorisée ; (7) retirer annonces et credentials à la clôture.

**Détection :** historique BGP/RPKI, tenancy fournisseur, certificats et comportement identique du service identifient le pool. **OPSEC résiliente à la capture :** une edge ne contient que l’identité régionale du service et aucune clé opérateur ou d’enrôlement de flotte. **Monitoring :** sonder chaque région depuis des monitors autorisés, comparer origine de route et digest de configuration, et traiter toute origine inattendue comme un incident.

## QUIC migration et continuité Multipath TCP

**Mécanique :** les connection IDs QUIC peuvent conserver une session lors d’un rebinding NAT ou d’un changement d’adresse ; Multipath TCP peut transporter un même flux fiable sur plusieurs subflows. Ils améliorent la continuité lors des transitions Wi-Fi/cellular mais exposent les anciens et nouveaux chemins au même pair et peuvent faciliter la corrélation inter-chemins.<sup>[[27]](#references)</sup>

**Avantages :** récupération rapide pendant les changements d’uplink ; la session applicative n’a pas besoin de redémarrer ; MPTCP combine résilience et débit ; utile aux field nodes approuvés.

**Inconvénients :** pas d’anonymat ; le pair voit migration/subflows ; IDs de connexion et trafic simultané relient les chemins ; support variable des middleboxes/opérateurs ; les dossiers de plusieurs fournisseurs augmentent l’exposition.

**Procédure :** (1) activer le transport supporté uniquement entre un client terrain possédé et un rendezvous ; (2) authentifier l’application indépendamment de l’IP ; (3) commencer un transfert limité sur Wi-Fi approuvé ; (4) passer au réseau cellulaire de l’organisation ; (5) confirmer validation du chemin, intégrité et absence de fallback clair/direct ; (6) tester timeout idle et retour ; (7) conserver au broker les transitions de chaque chemin.

**Détection :** le pair observe directement la migration d’adresse ou les subflows MPTCP ; les fournisseurs d’accès voient leur partie ; IDs de connexion, identité TLS et timing relient les deux. **OPSEC résiliente à la capture :** stocker uniquement du matériel de session limité à l’appareil et expirer rapidement l’état reprenable. **Monitoring :** alerter sur migrations impossibles, réseaux simultanés non approuvés, tempêtes de migration et reprise après quarantaine.

## Egress de managed CI/CD ou ephemeral automation runner

**Mécanique :** un workflow appartenant à l’organisation exécute un contrôle réseau limité sur un runner hébergé. La destination voit une adresse de runner cloud tandis que la plateforme conserve repository, acteur, workflow, token, logs et attribution de facturation. Il s’agit d’une exécution distante avec egress traçable, pas d’anonymat vis-à-vis du fournisseur.<sup>[[28]](#references)</sup>

**Avantages :** environnement propre et jetable ; définition reproductible du job ; aucune connexion entrante ; utile aux contrôles de disponibilité géographiquement distribués ; audit controller fort.

**Inconvénients :** plateforme et organisation identifient l’initiateur ; tokens de workflow larges et pull requests non fiables dangereuses ; réputation IP partagée ; logs/artifacts peuvent conserver secrets ou données de cible.

**Procédure :** (1) créer un repository privé et un environment organisationnels pour l’évaluation ; (2) n’autoriser que des jobs bénins fixes et approuvés manuellement vers des endpoints possédés ; (3) utiliser des permissions workflow minimales en lecture seule et aucun secret de production ; (4) exécuter le contrôle ; (5) comparer traces workflow/fournisseur/cible ; (6) vérifier que les artifacts ne contiennent aucun credential ; (7) supprimer le token d’environment et conserver l’audit requis.

**Détection :** les logs d’audit fournisseur et workflow fournissent l’attribution directe ; les cibles identifient les ASNs/plages de runners et la grammaire stable des requêtes. **OPSEC résiliente à la capture :** ne jamais placer de secrets de field device, signature, wallet ou cloud administrator dans les variables du runner. **Monitoring :** exiger l’approbation de branche/environment et alerter sur modifications de workflow, exécution de fork, lecture de secrets et destinations inattendues.

## Premier hop local non-IP vers une gateway possédée

**Mécanique :** Bluetooth mesh, Wi-Fi Aware/Direct, radio basse consommation ou liaison série/optique transporte des messages limités d’un sensor proche vers une gateway Internet approuvée. L’appareil terrain n’a aucune route Internet ; la gateway est la seule egress. La portée radio et les limites du protocole en font une conception de télémétrie/store-and-forward, pas un accès Internet anonyme interactif.

**Avantages :** supprime stack Internet et credentials du plus petit appareil terrain ; faible consommation ; politique centralisée à la gateway ; pontage possible de zones temporairement mortes.

**Inconvénients :** découverte RF/physique, pairing et identifiants appareil ; bande passante/portée réduites ; la gateway relie tous les messages ; restrictions de spectre/chiffrement variables ; la capture peut exposer les données en queue.

**Procédure :** (1) obtenir l’accord du site et du spectre ; (2) appairer un sensor possédé à une gateway possédée avec des clés uniques ; (3) définir des types de messages signés de taille fixe, TTL et débit ; (4) ne donner aucune route IP par défaut au sensor ; (5) laisser la gateway transférer uniquement vers un collector possédé ; (6) tester replay, perte de portée et panne de gateway ; (7) inventorier et récupérer les deux appareils.

**Détection :** relevé RF, base de pairing, inspection physique et logs de processus/flux gateway révèlent le chemin. **OPSEC résiliente à la capture :** le sensor ne contient que sa clé pairwise et une queue chiffrée limitée, jamais de credentials opérateur, Wi-Fi, cellular ou controller. **Monitoring :** alerter sur nouveaux pairs, rollback de séquence, échec de clé, débit RF inhabituel et messages arrivant via une gateway non enregistrée.

## Matrice d’exposition à la capture/compromission

Cette table applique un contrôle de résilience à la capture à chaque famille ci-dessus. « Minimiser » signifie réduire les secrets et le blast radius sur les assets autorisés ; cela ne signifie jamais effacer des preuves ni se cacher d’une enquête.

| Famille de techniques | Ce qu’un endpoint/relay capturé peut révéler | Contrôle autorisé minimal |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | réseaux connus, historique DHCP/portail, MAC, pair du tunnel | appareil d’organisation séparé ; MAC privée si supportée ; aucun compte personnel ; inventaire controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | fournisseurs/hostnames, clés, routes, logs et hop adjacent | une identité par engagement ; TTL court ; routes étroites ; révocation côté broker ; aucune master key |
| OHTTP/ODoH, MASQUE, relay split-provider | configuration relay/gateway, identifiants applicatifs et requêtes en cache | minimiser les identifiants du payload ; pinner la configuration approuvée ; cache limité ; aucun fallback direct |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | logiciels installés, matériel bridge/onion, état local et historique des pairs | client standard ; clés de service séparées ; état minimal chiffré ; rotation de l’identité de service compromise |
| Remote browser/VDI/jump host | token workspace, presse-papiers/fichiers et tenant distant | MFA résistant au phishing à la gateway ; canaux de transfert désactivés ; révocation rapide de session |
| Cellular, satellite, private APN | SIM/eSIM, identité IMEI/terminal, fournisseur et localisation approximative | contrat organisationnel ; aucune co-localisation personnelle ; politique APN/overlay étroite ; procédure de suspension opérateur |
| Proxy residential/cooperative, ORB lab | identité agent, controller/prochain hop, trafic en cache | nœuds possédés/consentis uniquement ; agent signé ; credential par nœud ; mapping participant conservé au controller |
| CDN/fronting, fast flux, serverless | tenant/origine/configuration, tokens API, déploiement et facturation | projet dédié ; rôle least-privilege ; token de déploiement court ; audit fournisseur conservé centralement |
| Dead drop, pull mailbox, store-and-forward | noms d’objets, queue, jobs/résultats en cache et données de garde | jobs signés et bornés ; TTL ; cache chiffré ; identité producteur séparée ; logs serveur immuables |
| Drop, nearest-neighbor, bridge longue portée | serial/radio/SSID/pair, clé appareil, traces de placement physique | placement écrit ; identité appareil unique ; aucun secret opérateur ; télémétrie état/tamper ; révocation et récupération |
| TURN, reverse overlay, dual-uplink | realm/broker, credential appareil, pair/route et profils uplink | service outbound-only étroit ; credential appareil court ; login opérateur indépendant ; chemins fail-closed |
| IPv6 temporary addressing | profils, historique de préfixe et état endpoint/applicatif | traiter comme anti-tracking uniquement ; conserver les logs réseau ; associer à une compartimentation endpoint |
| Pluggable transport/refraction lab | paramètres bridge/broker/decoy, état Tor et clés de recherche | client standard ou lab isolé ; aucun état de navigateur personnel ; aucun signaling de production |
| IPFS/PIR/fetcher | CID/requête demandée, contenu en cache, token gateway/service | cache borné chiffré ; paramètres publics uniquement ; token service court et allowlisté |
| Anycast/QUIC/MPTCP | nœuds de service, connection IDs, état reprenable et chemins connus | identité régionale uniquement ; courte durée de reprise ; révocation centrale route/session |
| Managed CI/CD runner | repository, workflow, token fournisseur, logs et artifacts | workflow least-privilege ; aucun secret production/terrain/wallet ; approbation d’environment |
| Non-IP local hop | pair radio, clé pairwise, messages en queue et identité gateway | clé pairwise unique ; schéma de message fixe ; aucun credential Wi-Fi/cellular/opérateur |

## Monitoring d’une éventuelle découverte pour chaque famille d’accès

Aucun test côté client ne prouve qu’un enquêteur ou défenseur observe. Surveiller les systèmes possédés par l’engagement, corroborer avec le controller/client et arrêter plutôt que sonder les observateurs. Les lignes suivantes couvrent toutes les techniques ci-dessus ; les combiner avec les [états d’alerte des field nodes et la procédure de réponse](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Techniques couvertes | Signaux sûrs côté controller | Condition de quarantaine/arrêt |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | session lease/portail/opérateur, tuple public, changement BSSID/cellule/chemin, notification fournisseur | réseau/SIM/appareil non approuvé, déplacement inexpliqué ou escalade fournisseur/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, proxy residential/cooperative | authentification pair, état tunnel, leaks route/DNS, nouvel événement admin/API, plainte | credential dupliqué/volé, administrateur inconnu, fallback direct ou egress hors périmètre |
| OHTTP/ODoH/ECH, MASQUE, relay split-provider, TURN | allocation relay/gateway, version clé/config, connexion directe non supportée, taux erreur/replay | mismatch de clé, fallback direct, realm/pair inconnu ou notification d’abus |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | état bootstrap, échec circuit, descriptor onion/état service et page canary possédée | croisement avec compte personnel, connexion non-Tor inattendue ou clé service compromise |
| I2P, mixnet, GNUnet, mesh/store-forward, local non-IP | ensemble de pairs, âge/séquence queue, arrivée gateway, association radio et hash contenu | pair/gateway inconnu, rollback séquence, contenu non autorisé ou garde manquante |
| Remote browser/VDI/jump host, CI/CD runner, serverless | session IdP, changement workflow/image/config, nouvel usage token, artifact/export et audit cloud | login/édition workflow inconnu, lecture de secret, destination inattendue ou élévation projet/rôle |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventaire nœuds possédés, accès DNS/edge/objet, graphe controller, signature job et TTL | nœud/origine/éditeur objet inconnu, job non signé/rejoué, sortie de topologie du lab |
| Drop/nearest-neighbor/bridge longue portée/overlay sortant/dual uplink | heartbeat signé, hash boot/config, état boîtier, contexte AP/switch, identité dupliquée | nœud déplacé/ouvert, boot/hash/chemin inattendu, usage sentinel ou rapport du site |
| IPv6 temporaire, QUIC migration, MPTCP | préfixe délégué, connection ID/subflows, validation chemin et session broker | migration impossible, chemins simultanés non approuvés ou reprise après révocation |
| IPFS/cache, PIR, fetcher contraint | forme CID/requête/racine version, changement peer/gateway, refus redirect/allowlist | pin/query/destination inattendu, racine dataset non signée ou notification d’abus |
| Lab refraction/decoy-routing, anycast rendezvous | décision de diversion possédée, arrivée proxy, origine BGP/RPKI, digest config régionale | signal sur chemin de production, origine route inconnue, incohérence région/configuration |

## Choisir et tester un chemin

1. Nommer l’observateur à supprimer et les données à masquer.
2. Sélectionner la famille la moins complexe qui l’élimine.
3. Dessiner les observateurs source, entrée, transit, sortie, DNS, compte et paiement.
4. Utiliser une identité endpoint/application séparée.
5. Vérifier IPv4, IPv6, DNS, WebRTC/bypass applicatif et vue de la destination.
6. Casser chaque hop et confirmer que l’échec est fermé.
7. Comparer les logs de chaque composant contrôlé.
8. Documenter les liens temporels, fournisseur, endpoint et physiques résiduels.

## References

- [1] [EFF — Choisir le VPN qui vous convient](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Protections de Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Débloquer Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Utiliser Tor Browser avec un VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Vue d’ensemble des onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Partage anonyme de fichiers](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Sécurité d’iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Enregistrement obligatoire des SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Des acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: Persistance pour NAT et traversée de firewall](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Extensions d’adresses temporaires pour l’autoconfiguration d’adresses IPv6 sans état](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports et bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — Recherche sur le projet et le déploiement](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Concepts de HTTP Gateway et cycle de vie des requêtes](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Présentation de Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Fonctionnement des services Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Référence des runners hébergés par GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
