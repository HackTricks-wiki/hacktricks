# Attribution, détection et contre-mesures

{{#include ../banners/hacktricks-training.md}}

L’infrastructure d’évasion de l’attribution est conçue pour rendre les indicateurs individuels jetables. Les défenseurs doivent préserver les preuves brutes, modéliser les relations et rechercher les comportements qui persistent malgré un changement d’IP, de domaine ou de persona.

## Hiérarchie des preuves

| Preuve | Utilité | Principale réserve |
|---|---|---|
| IP source/ASN/géolocalisation | localiser la sortie visible et le fournisseur | la sortie peut être un relay, un NAT ou une victime ; la géolocalisation est approximative |
| DNS passif/enregistrement | historique de l’infrastructure et co-hébergement | la confidentialité/la rédaction et l’hébergement partagé créent des lacunes |
| Empreinte certificate/TLS/HTTP | regrouper les déploiements répétés | les logiciels courants et l’imitation créent des faux positifs |
| Timing des flux et forme des octets | relier les étapes des relays et les beacons récurrents | les CDN/NAT et une visibilité limitée réduisent la certitude |
| Processus/identité de l’endpoint | expliquer pourquoi une connexion a eu lieu | absent sur les équipements edge/IoT ; l’attaquant peut utiliser des outils natifs |
| Audit Cloud/CDN/API | identifier le tenant et le contrôle de l’infrastructure | la rétention et l’accès légal/du provider varient |
| Paiement/compte/appareil | relier l’approvisionnement à une personne/entité | les prête-noms, les compromissions et les appareils partagés doivent être pris en compte |
| Implant/configuration saisi(e) | révéler les clés, peers, contrôleurs et liens de build | l’intégrité de la collecte et le moment de la saisie sont importants |
| Preuves humaines/physiques | relier l’événement numérique au lieu/opérateur | intrusif, dépendant de la juridiction, nécessite une gestion stricte |

Aucune ligne ne devrait à elle seule justifier une attribution étatique à haute confiance. Utilisez des hypothèses concurrentes et indiquez quelle observation réfuterait chacune d’elles.

## Télémétrie minimale

1. **DNS :** client, question, type, réponses, TTL, code de réponse, resolver et horodatage.
2. **Flux réseau :** source/destination/port, début/fin, paquets/octets, flags TCP et emplacement du sensor.
3. **TLS/HTTP :** SNI lorsqu’il est visible, certificat, protocole négocié, empreinte client/serveur, méthode, catégorie authority/path, statut et nombre d’octets. Protégez les URL complètes sensibles.
4. **Identité :** résultat de l’authentification, facteur/certificat/appareil, source, application, ID de session et décision de risque.
5. **Endpoint :** processus initiateur, parent, utilisateur, signature/hash du binaire et destination.
6. **Équipement edge/réseau :** différence de configuration, login admin, intégrité des processus/fichiers/firmware, logs d’interface et de flux.
7. **Cloud/SaaS/CDN :** acteur, tenant/projet, action API, source, objet/ressource, token et résultat.
8. **Wireless/NAC :** station, indicateur de MAC randomisée, AP, signal, identité/certificat EAP, VLAN/IP assigné(e) et posture.

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
Les nœuds utiles incluent l’IP, le préfixe, l’ASN, le domaine, le compte DNS, le certificat/la clé, l’empreinte similaire à JA3/JA4, la grammaire HTTP, le hash de fichier/configuration, le tenant cloud, le token d’API, l’adresse e-mail, la persona, l’instrument de paiement et le dispositif physique. Chaque arête doit inclure `first_seen`, `last_seen`, le capteur/la source, le niveau de confiance et indiquer si elle est observée ou inférée.

La densité du graphe seule est trompeuse : un CDN ou une autorité de certification relie de nombreux acteurs sans rapport. Accordez davantage de poids aux relations rares contrôlées par l’opérateur — même compte d’API, clé SSH, liste d’autorisation d’origine, corps de réponse unique ou protocole de contrôle — qu’à l’hébergement courant.

## Chasse aux ORB et aux routeurs compromis

### Depuis une sortie observée

1. Déterminez si l’adresse correspond à un hébergement, une connexion résidentielle, mobile, éducative ou professionnelle ; ne rejetez pas les sources résidentielles.
2. Extrayez, pour une période délimitée, l’historique DNS, les services/certificats, les ports ouverts et les comportements observés de scan/d’exploitation.
3. Recherchez les pairs partageant des empreintes de service rares, des destinations de contrôleur, des éléments de certificat ou un calendrier de rotation.
4. Classez les rôles probables : accès, traversée, sortie/staging ou administration.
5. Vérifiez si plusieurs clusters d’intrusion sans lien ont utilisé le même pool ; la multi-location affaiblit l’attribution directe à un acteur, mais renforce l’hypothèse d’un ORB.
6. Suivez les nouveaux nœuds correspondant au profil de rôle après la disparition des anciennes IP.

### Chez le propriétaire du réseau

- Déclenchez une alerte lors de l’apparition d’une gestion exposée sur Internet et d’une authentification par défaut/legacy.
- Envoyez hors du dispositif les modifications de configuration des routeurs/firewalls/VPN et les authentifications des administrateurs.
- Établissez une baseline des connexions sortantes depuis les infrastructures qui initient normalement peu de sessions.
- Détectez les nouveaux processus de proxy/listener, tunnels, tâches planifiées, modifications du firmware et requêtes DNS inattendues.
- Remplacez les dispositifs en fin de vie ; un redémarrage qui supprime un malware volatile ne corrige pas l’exposition.
- Limitez la gestion à un plan d’administration authentifié et à des sources connues.

Mandiant recommande de suivre l’infrastructure ORB comme une entité évolutive, car le blocage temporaire des IP ne rend pas compte de la topologie et du cycle de vie.<sup>[[1]](#references)</sup>

## Analyses du Fast-flux et du DNS dynamique

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
Enquêtez sur les domaines à l’aide de plusieurs caractéristiques indépendantes, et non d’un seul seuil. Comparez-les à un modèle d’autorisation CDN/anti-DDoS et vérifiez la rotation des serveurs de noms faisant autorité afin de distinguer le single flux du double flux. Pour les DGA, ajoutez les rafales de réponses NXDOMAIN par client, la distribution des longueurs et des caractères, les requêtes synchronisées entre les hôtes ainsi que le processus qui les génère. Les recommandations actuelles de MITRE mettent également l’accent sur les changements à haute fréquence, les TTL faibles et la corrélation processus/réseau.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Lorsque le endpoint d’entreprise ou un point d’inspection autorisé dispose des deux identités, comparez :
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Augmentez le niveau de confiance lorsque le SNI et l’autorité appartiennent à des tenants sans lien, que le processus n’est pas un client approuvé, que la session est périodique ou longue, et que l’origine interne est rare. Un SNI vide est un élément à consigner, et non quelque chose de automatiquement malveillant. ECH peut masquer le SNI sur le réseau ; les journaux des endpoints, du DNS et du fournisseur/CDN deviennent donc plus importants. MITRE documente les variantes avec SNI incohérents et avec SNI vide.<sup>[[3]](#references)</sup>

## Détection des séquences de résolution via dead-drop

Le comportement à forte valeur de signal est une séquence plutôt qu’un domaine bloqué :
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Recherchez à l’échelle de toute la flotte les chemins d’objets identiques, les hash de réponses, les identifiants d’API et les destinations ultérieures. Préservez le contenu récupéré, car l’acteur peut le modifier ou le supprimer. Restreignez les API de services inutiles et exigez que les applications approuvées utilisent les proxies d’entreprise, tout en tenant compte des outils de développement et de l’automatisation. MITRE répertorie GitHub, les forums, les documents et les services sociaux/web dans des procédures réelles.<sup>[[4]](#references)</sup>

## Regroupement des Redirector et des déploiements réutilisables

Même lorsque les domaines et les adresses changent, les opérateurs redéploient souvent la même automatisation. Regroupez-les selon des combinaisons de :

- champs de certificats/réutilisation de clés et calendrier d’émission ;
- version TLS/ordre des chiffrements et extensions, ainsi que comportement du serveur ;
- code d’état HTTP identique, ordre des en-têtes, comportement du cache, icône/corps et page d’erreur ;
- paires de ports inhabituelles et chaînes de redirection ;
- modèle de fournisseur DNS/de serveurs de noms et calendrier des TTL ;
- date de déploiement, disponibilité et fenêtre de maintenance ;
- exposition de l’origine back-end ou allowlists identiques.

Une seule page Nginx générique constitue une preuve faible. Plusieurs correspondances rares et indépendantes, associées à une continuité temporelle, peuvent justifier l’hypothèse d’un cluster d’infrastructure.

## Détection des proxies résidentiels et des sessions impossibles

Conservez l’identité de session au-delà de la couche IP. Signalez les combinaisons telles que :

- un fingerprint de session/appareil change de pays ou d’ASN plus rapidement que ne le permet un déplacement ;
- une IP grand public change à chaque requête tandis que les cookies et l’identité TLS/navigateur restent fixes ;
- l’appareil local revendiqué présente une latence, un fuseau horaire ou une langue incompatibles avec la sortie ;
- une adresse alterne entre des populations de comptes sans lien ou présente un comportement de proxy backconnect ;
- une session privilégiée apparaît depuis un accès résidentiel sans certificat d’appareil de l’organisation.

Le Carrier NAT, les outils d’accessibilité, les VPN d’entreprise et les déplacements produisent des anomalies bénignes. Exigez une authentification step-up ou une investigation au lieu d’un blocage irréversible fondé uniquement sur des étiquettes de « proxy résidentiel ».

## Détection des appareils wireless et covert

Reliez RADIUS/NAC au contexte des AP et au contexte physique :

1. recherchez les premières associations compte–appareil–AP ;
2. identifiez les identifiants utilisés sans certificat/posture EAP géré ;
3. comparez les sessions simultanées et la présence dans les bâtiments déterminée par les badges ;
4. examinez les signaux inhabituellement faibles ou en limite, ainsi que les déplacements entre AP ;
5. recherchez sur les endpoints gérés voisins un wireless scanning, un bridge/NAT d’interface nouvellement activé, des adaptateurs virtuels ou des tunnels ;
6. inventoriez les nouvelles activités de ports de switch, DHCP, réseau USB et PoE ;
7. effectuez un balayage RF/physique autorisé lorsque les éléments disponibles le justifient.

Cela détecte à la fois un chemin de voisinage proche de type APT28 et un dispositif déposé dans le cadre d’un exercice. La randomisation MAC ne doit pas être considérée comme une identité ou une preuve de culpabilité.

## Détection de l’attribution financière

- Préservez la chaîne exacte, les tokens, les adresses, les transactions et les identifiants de blocs.
- Suivez la valeur à travers la monnaie rendue, les peel chains, le fan-out/in, les mixers, les bridges et les dépôts auprès de services, en étiquetant les heuristiques.
- Corrélez l’heure, le montant moins les frais, l’événement du contrat, la liquidité et le retrait sur la chaîne de destination.
- Obtenez ou préservez légalement les données des exchanges, bridges, marchands, comptes, appareils et livraisons.
- Vérifiez les entités/adresses actuellement sanctionnées et leurs dérivés dans le cadre du programme applicable ; ne vous appuyez pas sur une ancienne liste statique.
- Considérez l’utilisation de privacy protocols comme un élément de contexte de risque, et non comme une preuve de comportement répréhensible.

Les signaux d’alerte du FATF sont explicitement contextuels : un modèle, un montant/une fréquence, une géographie, une source de fonds et des services renforçant l’anonymat inhabituels deviennent significatifs lorsqu’ils sont combinés.<sup>[[5]](#references)</sup>

## Deception et canaries

Les défenseurs peuvent créer des signaux à haute confiance sans tenter de désanonymiser les utilisateurs ordinaires :

- identifiants ou documents uniques qui ne devraient jamais quitter un seul système ;
- endpoints administratifs fictifs et partages leurres ;
- noms DNS instrumentés intégrés uniquement à des artefacts contrôlés ;
- clés cloud canary sans utilisation légitime ;
- identité Wi-Fi leurre que ne possède aucun appareil géré.

Définissez soigneusement la portée de la deception et encadrez-la. Un canary doit identifier l’utilisation abusive d’un actif appartenant au défenseur, et non collecter du trafic sans rapport provenant de tiers.

## Priorités des contre-mesures

1. Supprimez les routeurs, VPN et appliances exposés à Internet et non pris en charge.
2. Exigez une MFA résistante au phishing et des certificats liés aux appareils, y compris pour les accès internes/wireless.
3. Centralisez les logs suffisamment immuables d’identité, d’endpoints, DNS, flux, proxy, cloud et équipements réseau.
4. Restreignez la gestion et l’egress ; inventoriez chaque service accessible depuis l’extérieur.
5. Surveillez le DNS, la certificate transparency et la configuration cloud pour détecter les actifs non autorisés.
6. Préservez la visibilité SaaS au niveau des processus-réseau et des objets.
7. Exercez les investigations inter-couches et la coordination avec les fournisseurs voisins.
8. Suivez les clusters et les comportements d’infrastructure, et pas uniquement les listes de blocage IP.

## Discipline analytique

Utilisez un langage exprimant le niveau de confiance :

- **Observé :** l’enregistrement du capteur/fournisseur montre directement la relation.
- **Fortement étayé :** plusieurs observations indépendantes la favorisent par rapport aux alternatives.
- **Évalué :** inférence fondée sur les hypothèses et les éléments de preuve énoncés.
- **Inconnu :** un manque de visibilité empêche toute conclusion.

Conservez toujours au moins deux hypothèses : infrastructure opérée par l’acteur contre intermédiaire compromis/partagé ; acteur unique contre service multi-tenant ; évasion délibérée contre comportement légitime lié à la confidentialité/CDN. La capacité à expliquer l’incertitude fait partie d’une détection correcte.

## References

- [1] [Google Cloud/Mandiant — Les acteurs d’espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicateurs de signaux d’alerte liés aux Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Des acteurs de la RPC compromettent et maintiennent un accès persistant](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Conseils de visibilité renforcée et de durcissement pour l’infrastructure de communications](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
