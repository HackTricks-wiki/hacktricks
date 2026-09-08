# Attribution, détection et contre-mesures

L’infrastructure d’évitement de l’attribution est conçue pour rendre les indicateurs individuels jetables. Les défenseurs doivent préserver les preuves brutes, modéliser les relations et rechercher les comportements qui persistent malgré un changement d’IP, de domaine ou de persona.

## Hiérarchie des preuves

| Preuve | Utile pour | Principale réserve |
|---|---|---|
| IP source/ASN/géolocalisation | localiser la sortie visible et le fournisseur | la sortie peut être un relais, un NAT ou une victime ; la géolocalisation est approximative |
| DNS passif/enregistrement | historique de l’infrastructure et co-hébergement | la confidentialité/la redaction et l’hébergement partagé créent des lacunes |
| Empreinte certificat/TLS/HTTP | regrouper les déploiements répétés | les logiciels courants et l’imitation créent des faux positifs |
| Temporalité des flux et forme des octets | relier les étapes des relais et les beacons récurrents | les CDN/NAT et une visibilité limitée réduisent la certitude |
| Processus/identité du endpoint | expliquer pourquoi une connexion a eu lieu | absent des équipements edge/IoT ; l’attaquant peut utiliser des outils natifs |
| Audit Cloud/CDN/API | identifier le tenant et le contrôle de l’infrastructure | la rétention et l’accès légal ou fournisseur varient |
| Paiement/compte/appareil | relier l’approvisionnement à une personne/entité | les prête-noms, la compromission et les appareils partagés doivent être pris en compte |
| Implant/configuration saisi(e) | révéler les clés, pairs, contrôleurs et liens de build | l’intégrité de la collecte et la date de la saisie sont importantes |
| Preuves humaines/physiques | relier l’événement numérique à un lieu/opérateur | intrusif, dépendant de la juridiction et nécessitant une manipulation stricte |

Aucune ligne ne devrait à elle seule justifier une attribution étatique à haut niveau de confiance. Utilisez des hypothèses concurrentes et indiquez quelle observation falsifierait chacune d’elles.

## Télémétrie minimale

1. **DNS :** client, question, type, réponses, TTL, code de réponse, resolver et timestamp.
2. **Flux réseau :** source/destination/port, début/fin, paquets/octets, flags TCP et emplacement du capteur.
3. **TLS/HTTP :** SNI lorsqu’il est visible, certificat, protocole négocié, empreinte client/serveur, méthode, catégorie authority/path, statut et nombre d’octets. Protégez les URL complètes sensibles.
4. **Identité :** résultat de l’authentification, facteur/certificat/appareil, source, application, ID de session et décision de risque.
5. **Endpoint :** processus initiateur, parent, utilisateur, signature/hash du binaire et destination.
6. **Équipement edge/réseau :** différence de configuration, connexion admin, intégrité des processus/fichiers/firmware, interface et logs de flux.
7. **Cloud/SaaS/CDN :** acteur, tenant/projet, action API, source, objet/ressource, token et résultat.
8. **Wireless/NAC :** station, indicateur de MAC randomisée, AP, signal, identité/certificat EAP, VLAN/IP attribué(e) et posture.

Synchronisez les horloges, conservez les fuseaux horaires d’origine, documentez les limites NAT/proxy et conservez suffisamment d’historique pour survivre à un nœud ORB de 31 jours.

## Construire un graphe d’attribution

Représentez les observations sous forme de nœuds et d’arêtes typés :
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Les nœuds utiles incluent les adresses IP, les préfixes, les ASN, les domaines, les comptes DNS, les certificats/clés, les fingerprints de type JA3/JA4, la grammaire HTTP, les hashes de fichiers/configurations, les tenants cloud, les tokens API, les adresses e-mail, les personas, les instruments de paiement et les appareils physiques. Chaque relation doit comporter `first_seen`, `last_seen`, le sensor/la source, le niveau de confiance et préciser si elle est observée ou inférée.

La densité du graphe est à elle seule trompeuse : un CDN ou une autorité de certification relie de nombreux acteurs sans lien entre eux. Accordez davantage de poids aux relations rares contrôlées par l’opérateur — même compte API, clé SSH, liste d’autorisation d’origine, corps de réponse unique ou protocole de contrôle — qu’à l’hébergement courant.

## ORB et chasse aux routeurs compromis

### À partir d’une sortie observée

1. Déterminez si l’adresse correspond à un hébergeur, une connexion résidentielle, mobile, éducative ou professionnelle ; ne rejetez pas les sources résidentielles.
2. Récupérez les données DNS historiques, les services/certificats, les ports ouverts ainsi que les comportements observés de scan/d’exploitation sur une période définie.
3. Recherchez les pairs partageant des fingerprints de services rares, des destinations de controller, du matériel de certificat ou un calendrier de rotation similaire.
4. Classez les rôles probables : accès, traversal, sortie/staging ou administration.
5. Vérifiez si plusieurs clusters d’intrusion sans lien ont utilisé le même pool ; la multi-tenancy affaiblit l’attribution directe à un acteur, mais renforce l’hypothèse d’un ORB.
6. Suivez les nouveaux nœuds correspondant au profil de rôle après la disparition des anciennes adresses IP.

### Chez le propriétaire du réseau

- Déclenchez une alerte lors de l’exposition de nouveaux services de gestion sur Internet et de l’utilisation d’une authentification par défaut/ancienne.
- Envoyez hors appareil les modifications de configuration des routeurs/firewalls/VPN et les authentifications administratives.
- Établissez une baseline des connexions sortantes depuis les infrastructures qui initient normalement peu de sessions.
- Détectez les nouveaux processus de proxy/listener, tunnels, tâches planifiées, modifications du firmware et résolutions DNS inattendues.
- Remplacez les appareils en fin de vie ; un redémarrage qui supprime un malware volatil ne corrige pas l’exposition.
- Limitez la gestion à un plan d’administration authentifié et à des sources connues.

Mandiant recommande de suivre l’infrastructure ORB comme une entité évolutive, car le blocage temporaire des adresses IP ne permet pas de rendre compte de la topologie et du cycle de vie.<sup>[[1]](#references)</sup>

## Analyse du fast-flux et du dynamic-DNS

Agrégerez par domaine enregistré et sur une fenêtre glissante. Un score pratique peut combiner :
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Examinez les domaines à l’aide de plusieurs caractéristiques indépendantes, et non d’un seul seuil. Comparez-les à un modèle d’autorisation de CDN/anti-DDoS et vérifiez la rotation des serveurs de noms faisant autorité afin de distinguer le single flux du double flux. Pour les DGA, ajoutez les pics de réponses NXDOMAIN par client, la longueur et la distribution des caractères, les requêtes synchronisées entre les hôtes ainsi que le processus qui les génère. Les recommandations actuelles de MITRE mettent également l’accent sur les changements à haute fréquence, les TTL faibles et la corrélation entre le processus et le réseau.<sup>[[2]](#references)</sup>

## Détection du Domain-fronting

Lorsque le endpoint d’entreprise ou un point d’inspection autorisé dispose des deux identités, comparez :
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Augmentez le niveau de confiance lorsque le SNI et l’autorité appartiennent à des tenants sans lien, que le processus n’est pas un client approuvé, que la session est périodique ou de longue durée, et que l’origine interne est rare. Un SNI vide est un élément à enregistrer, et non quelque chose de automatiquement malveillant. ECH peut masquer le SNI sur le réseau ; les logs des endpoints, du DNS et du fournisseur/CDN deviennent donc plus importants. MITRE documente à la fois les variantes avec SNI incohérent et celles avec SNI vide.<sup>[[3]](#references)</sup>

## Détection des séquences de résolveur dead-drop

Le comportement à fort signal est une séquence plutôt qu’un domaine bloqué :
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Recherchez à l’échelle de toute la flotte les chemins d’objets identiques, les empreintes de réponse, les identifiants API et les destinations ultérieures. Préservez le contenu récupéré, car l’acteur peut le modifier ou le supprimer. Restreignez les API de services inutiles et exigez que les applications approuvées utilisent des proxies d’entreprise, tout en tenant compte des outils de développement et de l’automatisation. MITRE répertorie GitHub, les forums, les documents et les services sociaux/web dans des procédures réelles.<sup>[[4]](#references)</sup>

## Regroupement des redirectors et des déploiements réutilisables

Même lorsque les domaines et les adresses changent, les opérateurs redéploient souvent la même automatisation. Regroupez-les selon des combinaisons de :

- champs de certificat/réutilisation de clés et calendrier d’émission ;
- version TLS/ordre des chiffrements et extensions, ainsi que comportement du serveur ;
- code d’état HTTP, ordre des en-têtes, comportement du cache, icône/corps et page d’erreur identiques ;
- paires de ports inhabituelles et chaînes de redirection ;
- modèle de fournisseur DNS/de serveur de noms et calendrier des TTL ;
- date de déploiement, disponibilité et fenêtre de maintenance ;
- exposition de l’origine back-end ou allowlists identiques.

Une simple page Nginx générique constitue un faible élément de preuve. Plusieurs correspondances rares et indépendantes, associées à une continuité temporelle, peuvent justifier l’hypothèse d’un cluster d’infrastructure.

## Détection des proxies résidentiels et des sessions impossibles

Conservez l’identité de session au-delà de la couche IP. Signalez les combinaisons telles que :

- l’empreinte d’une même session/appareil change de pays/ASN plus rapidement que ne le permet un déplacement ;
- une IP grand public change à chaque requête tandis que les cookies et l’identité TLS/navigateur restent fixes ;
- l’appareil local revendiqué présente une latence, un fuseau horaire ou une langue incompatibles avec la sortie ;
- une adresse alterne entre des populations de comptes sans lien ou présente un comportement de backconnect proxy ;
- une session privilégiée apparaît depuis un accès résidentiel sans le certificat d’appareil de l’organisation.

Le Carrier NAT, les outils d’accessibilité, les VPN d’entreprise et les déplacements produisent des anomalies bénignes. Exigez une authentification renforcée ou une investigation plutôt qu’un blocage irréversible fondé uniquement sur des labels de « proxy résidentiel ».

## Détection des appareils wireless et covert

Associez RADIUS/NAC au contexte des AP et au contexte physique :

1. trouver les premières combinaisons compte–appareil–AP observées ;
2. identifier les identifiants utilisés sans certificat EAP/posture géré ;
3. comparer les sessions simultanées et la présence sur site selon les badges/bâtiments ;
4. examiner les signaux inhabituellement faibles ou en limite, ainsi que les déplacements entre AP ;
5. rechercher sur les endpoints gérés proches un wireless scanning, une interface bridge/NAT récemment activée, des adaptateurs virtuels ou des tunnels ;
6. inventorier toute nouvelle activité de switchport, DHCP, réseau USB et PoE ;
7. effectuer un balayage RF/physique autorisé lorsque les éléments disponibles le justifient.

Cela détecte à la fois un chemin de type voisinage immédiat inspiré d’APT28 et un dispositif d’exercice. La randomisation des adresses MAC ne doit pas être considérée comme une identité ou une preuve de culpabilité.

## Détection de l’attribution financière

- Préserver la chaîne exacte, les tokens, les adresses, les transactions et les identifiants de blocs.
- Suivre la valeur à travers le change, les peel chains, le fan-out/in, les mixers, les bridges et les dépôts auprès de services, en étiquetant les heuristiques.
- Corréler l’heure, le montant après déduction des frais, l’événement du contrat, la liquidité et le retrait sur la chaîne de destination.
- Obtenir ou préserver légalement les données des exchanges, bridges, marchands, comptes, appareils et livraisons.
- Vérifier les entités/adresses actuellement sanctionnées et leurs dérivés dans le cadre du programme applicable ; ne pas se fier à une ancienne liste statique.
- Considérer l’utilisation de privacy protocols comme un élément de contexte de risque, et non comme une preuve d’acte répréhensible.

Les signaux d’alerte du FATF sont explicitement contextuels : un schéma inhabituel, le montant/la fréquence, la géographie, la source des fonds et les services renforçant l’anonymat deviennent significatifs lorsqu’ils sont réunis.<sup>[[5]](#references)</sup>

## Deception et canaries

Les défenseurs peuvent créer des signaux à haut niveau de confiance sans tenter de désanonymiser les utilisateurs ordinaires :

- identifiants ou documents uniques qui ne devraient jamais quitter un système ;
- endpoints d’administration fictifs et shares leurres ;
- noms DNS instrumentés intégrés uniquement dans des artefacts contrôlés ;
- clés cloud canary sans usage légitime ;
- identité Wi-Fi leurre qu’aucun appareil géré ne possède.

Définissez soigneusement la portée de la deception et encadrez-la. Un canary doit identifier l’utilisation abusive d’un actif appartenant au défenseur, et non collecter du trafic sans rapport provenant de tiers.

## Priorités des contre-mesures

1. Supprimer les routers, VPN et appliances exposés à Internet qui ne sont pas pris en charge.
2. Exiger une MFA résistante au phishing et des certificats liés à l’appareil, y compris pour les accès internes/wireless.
3. Centraliser des logs suffisamment immuables concernant l’identité, les endpoints, le DNS, les flux, les proxies, le cloud et les appareils réseau.
4. Restreindre la gestion et l’egress ; inventorier chaque service accessible de l’extérieur.
5. Surveiller le DNS, la transparency des certificats et la configuration cloud afin de détecter les actifs non autorisés.
6. Préserver la visibilité SaaS au niveau des processus et des objets.
7. Organiser des investigations inter-couches et une coordination avec les fournisseurs voisins.
8. Suivre les clusters d’infrastructure et les comportements, et pas uniquement les listes de blocage IP.

## Rigueur analytique

Utilisez un langage exprimant le niveau de confiance :

- **Observé :** l’enregistrement d’un capteur/fournisseur montre directement la relation.
- **Fortement étayé :** plusieurs observations indépendantes la privilégient par rapport aux alternatives.
- **Évalué :** inférence fondée sur les hypothèses et les éléments de preuve énoncés.
- **Inconnu :** le manque de visibilité empêche toute conclusion.

Conservez toujours au moins deux hypothèses : une infrastructure exploitée par l’acteur contre un intermédiaire compromis/partagé ; un acteur contre un service multi-tenant ; une évasion délibérée contre un comportement légitime lié à la confidentialité/CDN. La capacité à expliquer l’incertitude fait partie d’une détection correcte.

## References

- [1] [Google Cloud/Mandiant — Les acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicateurs de signaux d’alerte liés aux actifs virtuels](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Des acteurs de la RPC compromettent et maintiennent un accès persistant](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Directives visant à renforcer la visibilité et la sécurité de l’infrastructure de communications](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
