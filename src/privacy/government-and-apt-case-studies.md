# Études de cas gouvernementales et APT

{{#include ../banners/hacktricks-training.md}}

Ces cas publics montrent comment différentes techniques de protection de la vie privée sont combinées dans des opérations réelles. Les étiquettes d'attribution sont celles utilisées par les enquêteurs ou les gouvernements cités ; une adresse IP, une similarité d'outils ou une cohérence géopolitique seules ne constituent pas une attribution concluante.

## APT28 : accès Wi-Fi distant via le voisin le plus proche

**Constat public.** Volexity a attribué une intrusion survenue en 2022 à GruesomeLarch/APT28. Après que l'accès à Internet avec un identifiant validé a été bloqué par la MFA, l'acteur a compromis des organisations proches de la cible et a atteint le Wi-Fi d'entreprise de la cible depuis un hôte nearby dual-homed. Le chemin Wi-Fi acceptait l'identifiant sans la MFA requise depuis l'extérieur.<sup>[[1]](#references)</sup>

**Effet sur la vie privée.** L'accès final provenait d'une portée radio physique et les organisations intermédiaires étaient des victimes. L'opération a évité tout déplacement et a fait pointer la géolocalisation IP conventionnelle vers un voisin.

**Ce qui l'a exposée.** L'alerte de la cible, l'enquête sur l'hôte et le réseau, l'activité liée aux identifiants, la topologie des interfaces et la proximité physique devaient être analysées comme une seule chaîne. Le fait anormal n'était pas simplement une nouvelle IP ; il s'agissait d'une identité légitime arrivant via un contexte Wi-Fi/appareil inhabituel, tandis que des systèmes proches étaient compromis.

**Leçon défensive.** Appliquer un accès au Wi-Fi basé sur des certificats et des appareils, corréler RADIUS avec NAC/MDM et le contexte physique, et enquêter sur les infrastructures voisines plutôt que de supposer que le dernier saut correspond à l'opérateur.

## APT28 : infrastructure criminelle de Moobot réutilisée par le GRU

**Constat public.** En février 2024, le département de la Justice des États-Unis a décrit un botnet composé de centaines de routeurs Ubiquiti EdgeOS. Des acteurs criminels avaient installé Moobot sur des routeurs qui conservaient des identifiants administrateur par défaut connus ; l'unité 26165 du GRU a ensuite ajouté des scripts et des fichiers, transformant un botnet criminel existant en plateforme d'espionnage utilisée pour le spearphishing et le vol d'identifiants.<sup>[[2]](#references)</sup>

**Effet sur la vie privée.** Le GRU n'a pas construit lui-même toute l'infrastructure. L'utilisation d'une flotte déjà compromise a placé des adresses de particuliers et de petits bureaux sans lien entre l'acteur et les cibles, a mélangé l'activité étatique avec l'activité criminelle et a réduit les traces d'enregistrement propres à l'acteur.

**Ce qui l'a exposée.** Les fichiers des routeurs, le comportement de contrôle du malware et les informations de routage hors contenu ont étayé l'enquête. La neutralisation a temporairement modifié les règles du firewall et supprimé les fichiers malveillants, tandis que le DOJ a averti que des identifiants par défaut inchangés pouvaient permettre une réinfection.

**Leçon défensive.** Remplacer les routeurs qui ne sont plus pris en charge, supprimer l'administration exposée à Internet, modifier les paramètres par défaut, appliquer les correctifs, collecter les données de configuration et de flux des appareils en périphérie, et rechercher les comportements à l'échelle de la flotte. Une « IP résidentielle américaine » ne constitue pas une preuve qu'un opérateur américain est impliqué.

## Volt Typhoon : KV Botnet et living off the land

**Constat public.** Le DOJ et un avis conjoint de la CISA ont décrit Volt Typhoon, soutenu par l'État chinois, utilisant le KV Botnet — principalement composé de routeurs SOHO Cisco et NETGEAR en fin de vie compromis — afin de dissimuler l'origine chinoise des activités visant des infrastructures critiques. Chez les victimes, l'acteur privilégiait les comptes valides et les outils d'administration intégrés ; les agences ont signalé que l'accès avait persisté dans certains environnements pendant au moins cinq ans.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Effet sur la confidentialité.** Le chemin de type ORB masquait l'origine, tandis que le living-off-the-land réduisait le nombre de binaires nouveaux et les possibilités de détection par signature après l'accès. La dissimulation au niveau du réseau et des endpoints se renforçait mutuellement.

**Ce qui l'a exposé.** La structure des routeurs/contrôleurs, la collecte technique autorisée par un tribunal, la récurrence de l'activité et l'analyse inter-victimes ont compté davantage qu'un IOC isolé. Le redémarrage d'un routeur supprimait le malware KV volatil dans les cas décrits, mais ne corrigeait pas l'exposition sous-jacente liée à la fin de vie de l'appareil.

**Leçon défensive.** Remplacer les edge devices en fin de vie, centraliser les logs d'authentification et des équipements réseau, établir une baseline du comportement des administrateurs, restreindre la connectivité sortante et rechercher des séquences comportementales à travers les couches identité, endpoint et réseau.

## Réseaux ORB liés à la Chine : l'infrastructure en tant que service

**Constat public.** Mandiant a décrit un écosystème de réseaux ORB utilisés par plusieurs acteurs d'espionnage liés à la Chine. Les réseaux provisionnés utilisaient des nœuds VPS loués ; les réseaux non provisionnés utilisaient des IoT et des routeurs compromis ; les réseaux hybrides combinaient les deux. ORB3/SPACEHOP soutenait des activités associées à APT5/APT15. ORB2/FLORAHOX combinait un serveur d'administration, des serveurs loués, une couche Tor personnalisée et des équipements Cisco, ASUS et DrayTek compromis. Mandiant a estimé que certains réseaux étaient administrés indépendamment et loués à plusieurs acteurs APT.<sup>[[5]](#references)</sup>

**Effet sur la confidentialité.** L'infrastructure est devenue une frontière de service. Un opérateur pouvait obtenir des sorties géographiques/résidentielles sans maintenir le parc de victimes, tandis que le partage entre de nombreux clients affaiblissait l'association simple entre un acteur et une IP. Le renouvellement rapide du parc accélérait l'« extinction des IOC ».

**Ce qui l'a exposé.** La topologie réseau, les images de serveurs clonées, les ports/services, les relations avec les contrôleurs, les implants de routeurs et les cycles de vie restaient regroupables. Mandiant a indiqué que certaines IP de nœuds ne restaient dans un ORB que 31 jours.

**Leçon défensive.** Suivre un ORB comme une entité changeante : rôles des nœuds, empreintes de services, relations en amont, comportement de scan et rythme de rotation. L'expiration d'un indicateur IP doit mettre à jour le cluster, et non effacer le dossier.

## Système mondial d'espionnage de la RPC : routeurs, liens de confiance et traffic mirroring

**Constat public.** Un avis multinational de 2025 a décrit une activité recoupant des noms utilisés dans les rapports commerciaux, notamment Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 et GhostEmperor. Les agences ont signalé l'utilisation de VPS loués et de routeurs intermédiaires compromis pour atteindre des fournisseurs de télécommunications et de réseaux. Les acteurs pivotaient via des liens de confiance fournisseur/client, modifiaient les routes, créaient des tunnels GRE/IPsec, utilisaient des conteneurs sur les équipements et activaient SPAN/RSPAN/ERSPAN ou la capture native de paquets afin de collecter l'authentification et le trafic client.<sup>[[13]](#references)</sup>

**Effet sur la confidentialité.** Un routeur compromis est simultanément un relais, un point d'observation et un participant de confiance du réseau. Les interconnexions privées peuvent contourner les contrôles conçus autour de l'Internet public, tandis que le traffic mirroring collecte les identifiants sans déployer d'agent endpoint.

**Ce qui l'expose.** Les différences de configuration, l'administration SNMP/SSH/web inattendue, les nouvelles routes/tunnels statiques, les sessions de mirroring, les conteneurs Guest Shell, les fichiers PCAP, les changements de destinations TACACS+/RADIUS et la désactivation des logs. L'avis souligne que certains routeurs intermédiaires ne faisaient pas partie d'un botnet public précédemment identifié ; l'absence d'indicateurs ORB connus n'était donc pas exonératoire.

**Leçon défensive.** Utiliser une administration out-of-band, des logs centralisés de configuration/authentification, des contrôles d'intégrité des images signées et du runtime, des restrictions sur l'egress des interfaces de gestion et des alertes pour les changements de route/mirroring/tunnel/AAA. Étendre l'analyse d'une compromission présumée aux pairs de confiance avant l'éviction.

## UNC3886 RedPenguin : backdoors passives sur des routeurs d'ISP

**Constat public.** Mandiant a attribué à UNC3886 des backdoors personnalisées dérivées de TINYSHELL sur des routeurs Juniper MX en fin de vie. L'ensemble comprenait des implants actifs et passifs, des noms imitant des daemons légitimes, un comportement de désactivation des logs, une injection de processus dans un processus de confiance, une capacité de proxy SOCKS et une infrastructure évaluée comme constituée de nœuds de staging ORB. Les variantes passives inspectaient les paquets via `libpcap` et ne s'activaient qu'après détection d'un motif magique ; l'une d'elles pouvait passer à un callback actif fourni dans le trigger.<sup>[[14]](#references)</sup>

**Effet sur la confidentialité.** Un implant passif n'émet aucun beacon périodique permettant sa découverte. Il partage les ports et le trafic avec un véritable équipement réseau, s'active brièvement et peut relayer via un ORB plutôt que de se connecter directement à un contrôleur final.

**Ce qui l'expose.** L'analyse mémoire, les différences entre le code sur disque et le code en cours d'exécution, les filtres de capture de paquets et le comportement des sockets inattendus, les noms de processus/fichiers qui ne font qu'approximer ceux de daemons légitimes, l'administration via des terminal servers, les logs manquants et la relation en deux étapes entre les nœuds de staging et un contrôleur backend.

**Leçon défensive.** Acquérir la mémoire ainsi que les éléments du système de fichiers et de la configuration, comparer les processus/modules avec une image de référence fiable, surveiller l'utilisation de la capture de paquets et des socket filters, sécuriser les terminal servers d'administration et remplacer les équipements réseau en fin de vie. Une chasse aux outbound beacons sans résultat ne constitue pas une garantie de bon état.

## APT29 : domain fronting via Tor

**Constat public.** MITRE indique qu'APT29 utilise le transport enfichable Tor `meek` pour effectuer du domain fronting sur le trafic C2. Le nom TLS externe semblait être celui d'un domaine autorisé hébergé par un CDN, tandis que l'hôte HTTP interne sélectionnait la route réelle.<sup>[[6]](#references)</sup>

**Effet sur la confidentialité.** Un observateur chargé du filtrage pouvait voir un front/CDN courant plutôt que la destination interne, et son blocage risquait de provoquer des dommages collatéraux.

**Ce qui l'expose.** Le CDN peut observer l'incohérence de routage, et un défenseur disposant d'une visibilité endpoint ou TLS légale peut corréler le processus, l'autorité, la durée de connexion, le modèle d'octets et l'activité ultérieure. Les changements de politique du fournisseur peuvent désactiver la technique.

**Leçon défensive.** Ne pas s'appuyer uniquement sur une allowlist SNI. Appliquer un egress tenant compte des applications, comparer les identités TLS et HTTP lorsqu'elles sont visibles et relier l'événement réseau au processus initiateur.

## APT41 et autres dead-drop resolvers

**Constat public.** MITRE documente l'utilisation par APT41 de sites légitimes, notamment GitHub, Pastebin, Microsoft TechNet, Cloudflare et des forums communautaires, pour publier ou récupérer des informations C2. D'autres outils liés à des États ont utilisé de manière similaire des publications, des documents et les réseaux sociaux.<sup>[[7]](#references)</sup>

**Effet sur la confidentialité.** Un binaire contient un service/objet légitime plutôt qu'une adresse C2 stable. L'objet peut être modifié pour faire tourner l'infrastructure, et la requête initiale se fond dans le trafic TLS courant.

**Ce qui l'expose.** L'identifiant de l'objet ou du compte est stable ; des processus rares le récupèrent de manière répétée ; le contenu est décodé ; et une seconde connexion sortante suit. Les enregistrements du compte fournisseur et de l'API peuvent relier la publication à l'opérateur.

**Leçon défensive.** Conserver les chemins complets du proxy, les identifiants d'objets et la filiation des processus endpoint. Un événement au niveau du domaine tel que « connexion à GitHub » est trop général.

## Turla : C2 via adresses satellite

**Constat public.** Kaspersky a rapporté que Turla abusait de broadcasts downstream non chiffrés provenant d'anciens services Internet unidirectionnels DVB-S. Un opérateur situé dans la zone de couverture satellite pouvait sélectionner l'adresse d'un abonné légitime et recevoir les réponses diffusées vers celle-ci, donnant l'apparence d'un C2 hébergé derrière un fournisseur satellite dans une autre région.<sup>[[8]](#references)</sup>

**Effet sur la confidentialité.** L'adresse apparente du serveur n'identifiait pas le récepteur, et les procédures classiques de saisie d'hébergement et de WHOIS étaient moins utiles.

**Ce qui l'expose.** L'acteur avait toujours besoin d'un chemin de requête sortant, le routage était asymétrique, l'abonné légitime n'initiait pas l'échange C2 et une enquête RF/fournisseur pouvait réduire la zone de réception.

**Leçon défensive.** Considérer la géolocalisation comme une hypothèse parmi d'autres. Valider la symétrie du chemin, le RTT, la propriété du routage et la capacité réelle du prétendu endpoint à fournir le service observé.

## Cyclops Blink et VPNFilter : les edge devices comme couverture durable

**Constat public.** Un avis NCSC/CISA/FBI/NSA de 2022 a décrit le malware modulaire Cyclops Blink de Sandworm sur des équipements WatchGuard, déployé de manière persistante comme mise à jour du firmware et capable d'ajouter des modules. Le DOJ a décrit séparément le botnet VPNFilter antérieur d'APT28, composé de routeurs et de périphériques NAS, comme capable de collecte de renseignements, d'activité destructive et de misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Effet sur la confidentialité.** Les appliances edge sont constamment connectées, considérées comme des éléments d'infrastructure de confiance et peu couvertes par l'EDR. La persistance du firmware peut survivre à un simple redémarrage et transformer l'équipement victime en relais ou en point de contrôle.

**Ce qui l'expose.** L'intégrité du firmware, le protocole d'implant spécifique au fournisseur, l'exposition inattendue de la gestion, les changements de configuration et les outbound beacons. Les edge devices doivent être traités comme des sujets forensics, et non comme une plomberie transparente.

## RPDC : superposition de l'identité, du réseau et des finances

**Constat public.** Des affaires du DOJ décrivent des travailleurs de la RPDC obtenant des emplois à distance au moyen de fausses identités ou de pièces d'identité volées et de VPN, recevant des cryptomonnaies, fractionnant les transferts, échangeant des actifs/chaînes, utilisant des NFT et mélangeant les produits. D'autres affaires décrivent des traders OTC et des sociétés écrans convertissant des cryptomonnaies volées en achats. Le Treasury et le FBI ont publiquement relié les produits de Lazarus/TraderTraitor à des mixers et identifié des adresses issues de vols majeurs.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Effet sur la confidentialité.** Il ne s'agit pas d'« une monnaie privée ». C'est une chaîne multidomaine : la persona et l'accès à distance masquent la localisation du travailleur ; la crypto déplace la valeur ; la layering fragmente les récits transactionnels simples ; les traders OTC et les sociétés écrans servent de pont vers les biens et la monnaie fiduciaire.

**Ce qui l'expose.** Les anomalies liées à l'employeur et à l'appareil, les facilitateurs réutilisés, la continuité temporelle/de valeur sur la blockchain, les données des exchanges/bridges, les adresses sanctionnées, l'identité du compte et les données d'expédition/de société reconnectent la chaîne.

**Leçon défensive.** Les équipes chargées du recrutement, de l'IAM, des endpoints, de la paie, de la blockchain et des sanctions ont besoin d'un modèle de dossier partagé. Plus de détails apparaissent dans [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Schémas transversaux

| Schéma | Exemples APT | Adaptation du défenseur |
|---|---|---|
| La sortie est une autre victime | APT28/Moobot, Volt Typhoon/KV, ORBs | enquêter sur la sortie et la corriger ; ne pas l'assimiler à la localisation de l'acteur |
| Les contrôles diffèrent selon la frontière | APT28 nearest neighbor | fournir aux accès internes/sans fil le même niveau d'assurance d'identité qu'aux accès Internet |
| Un service légitime est une couche de routage | APT29, APT41 | conserver le contexte objet/chemin/processus, et pas uniquement le domaine de destination |
| Les edge devices manquent de télémétrie | KV, Moobot, Cyclops Blink, ORBs | centraliser les logs de configuration/authentification/flux et vérifier le firmware et l'inventaire |
| L'infrastructure est partagée et éphémère | ORBs liés à la Chine | regrouper les comportements et la topologie, et suivre les changements de rôle dans le temps |
| Plusieurs séparations faibles se composent | Personas RPDC + VPN + crypto + OTC | relier les éléments d'identité, d'appareil, de réseau, de paiement et les preuves physiques |

## References

- [1] [Volexity — L'attaque Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Perturbation du botnet de routeurs Moobot contrôlé par le GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Perturbation du botnet KV de la RPC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Des acteurs de la RPC compromettent et maintiennent un accès persistant aux infrastructures critiques américaines](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Des acteurs d'espionnage liés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla satellite](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Avis Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Perturbation de VPNFilter d'APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Le représentant de la Foreign Trade Bank de la RPDC inculpé dans des conspirations de blanchiment de cryptomonnaies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanctions contre Blender.io et fonds de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrer la compromission mondiale de réseaux par des acteurs soutenus par l'État chinois](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router : UNC3886 cible des routeurs Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
