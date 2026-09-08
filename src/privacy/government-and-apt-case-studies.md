# Études de cas gouvernementales et APT

Ces cas publics montrent comment différentes techniques de privacy sont combinées dans des opérations réelles. Les étiquettes d’attribution sont celles utilisées par les enquêteurs ou les gouvernements cités ; une adresse IP, une similarité d’outils ou une concordance géopolitique ne suffisent pas, à elles seules, à établir une attribution concluante.

## APT28 : accès Wi-Fi remote nearest-neighbor

**Conclusions publiques.** Volexity a attribué une intrusion survenue en 2022 à GruesomeLarch/APT28. Après le blocage de l’accès à Internet avec un credential validé par MFA, l’acteur a compromis des organisations proches de la cible et a atteint le Wi-Fi d’entreprise de la cible depuis un host dual-homed situé à proximité. Le chemin Wi-Fi acceptait le credential sans le MFA requis depuis l’extérieur.<sup>[[1]](#references)</sup>

**Effet sur la privacy.** L’accès final provenait d’une portée radio physique et les organisations intermédiaires étaient des victimes. L’opération a évité tout déplacement et a fait pointer la géolocalisation IP conventionnelle vers un voisin.

**Ce qui l’a révélée.** L’alerte de la cible, l’investigation des hosts et du réseau, l’activité liée aux credentials, la topologie des interfaces et la proximité physique ont dû être analysées comme une seule chaîne. Le fait anormal n’était pas simplement une nouvelle IP ; il s’agissait d’une identité légitime arrivant par un contexte Wi-Fi/device inhabituel, tandis que des systèmes voisins étaient compromis.

**Leçon défensive.** Appliquer un accès au Wi-Fi fondé sur des certificats et des devices, corréler RADIUS avec NAC/MDM et le contexte physique, et enquêter sur l’infrastructure voisine plutôt que de supposer que le dernier hop correspond à l’opérateur.

## APT28 : infrastructure Moobot criminelle réutilisée par le GRU

**Conclusions publiques.** En février 2024, le US Department of Justice a décrit un botnet composé de centaines de routeurs Ubiquiti EdgeOS. Des acteurs criminels avaient installé Moobot sur des routeurs qui conservaient des credentials administrateur par défaut connus ; l’unité 26165 du GRU a ensuite ajouté des scripts et des fichiers, transformant un botnet criminel existant en plateforme d’espionnage utilisée pour le spearphishing et le credential theft.<sup>[[2]](#references)</sup>

**Effet sur la privacy.** Le GRU n’a pas construit lui-même toute l’infrastructure. L’utilisation d’une fleet déjà compromise a placé des adresses de particuliers et de petites entreprises sans lien entre l’acteur et les cibles, a mêlé l’activité étatique à l’activité criminelle et a réduit les artifacts d’enregistrement propres à l’acteur.

**Ce qui l’a révélée.** Les fichiers des routeurs, le comportement de contrôle du malware et les informations de routage hors contenu ont étayé l’investigation. La disruption a temporairement modifié les règles du firewall et supprimé les fichiers malveillants, tandis que le DOJ a averti que des credentials par défaut inchangés pouvaient permettre une réinfection.

**Leçon défensive.** Remplacer les routeurs non supportés, supprimer l’administration exposée à Internet, modifier les valeurs par défaut, appliquer les patches, collecter les données de configuration et de flux des edge devices, et rechercher les comportements de fleet. Une « IP résidentielle américaine » ne constitue pas une preuve qu’il s’agit d’un opérateur américain.

## Volt Typhoon : KV Botnet et living off the land

**Conclusions publiques.** Le DOJ et un advisory conjoint de la CISA ont décrit Volt Typhoon, sponsorisé par l’État chinois, utilisant le KV Botnet — principalement composé de routeurs SOHO Cisco et NETGEAR en fin de vie compromis — pour dissimuler l’origine chinoise des activités ciblant des infrastructures critiques. Chez les victimes, l’acteur privilégiait les comptes valides et les outils d’administration intégrés ; les agences ont signalé que l’accès persistait dans certains environnements depuis au moins cinq ans.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Effet sur la confidentialité.** Le chemin similaire à ORB masquait l'origine, tandis que le living-off-the-land réduisait le nombre de binaires nouveaux et les possibilités de détection par signature après l'accès. La dissimulation réseau et endpoint se renforçait mutuellement.

**Ce qui l'a exposé.** La structure routeur/contrôleur, la collecte technique autorisée par un tribunal, la récurrence de l'activité et l'analyse inter-victimes ont davantage compté qu'un IOC isolé. Le redémarrage d'un routeur supprimait le malware KV volatil dans les cas décrits, mais ne corrigeait pas l'exposition sous-jacente liée à la fin de vie de l'appareil.

**Leçon défensive.** Remplacer les appareils edge en fin de vie, centraliser les logs d'authentification et des équipements réseau, établir une baseline du comportement des administrateurs, restreindre la connectivité sortante et rechercher les séquences comportementales à travers les couches identité, endpoint et réseau.

## Réseaux ORB associés à la Chine : l'infrastructure comme service

**Constat public.** Mandiant a décrit un écosystème de réseaux ORB utilisés par plusieurs acteurs d'espionnage associés à la Chine. Les réseaux provisionnés utilisaient des nœuds VPS loués ; les réseaux non provisionnés utilisaient des appareils IoT et des routeurs compromis ; les réseaux hybrides combinaient les deux. ORB3/SPACEHOP soutenait des activités associées à APT5/APT15. ORB2/FLORAHOX combinait un serveur d'administration, des serveurs loués, une couche Tor personnalisée et des appareils Cisco, ASUS et DrayTek compromis. Mandiant a estimé que certains réseaux étaient administrés indépendamment et loués à plusieurs acteurs APT.<sup>[[5]](#references)</sup>

**Effet sur la confidentialité.** L'infrastructure devenait une limite de service. Un opérateur pouvait obtenir des sorties géographiques/résidentielles sans maintenir le parc de victimes, tandis que le partage entre plusieurs clients compliquait l'association directe entre acteur et adresse IP. Le renouvellement rapide du parc accélérait l'« extinction des IOC ».

**Ce qui l'a exposé.** La topologie réseau, les images serveur clonées, les ports/services, les relations avec les contrôleurs, les implants de routeur et les cycles de vie restaient regroupables. Mandiant a signalé que certaines adresses IP de nœuds ne restaient dans un ORB que 31 jours.

**Leçon défensive.** Suivre un ORB comme une entité évolutive : rôles des nœuds, empreintes de services, relations en amont, comportement de scan et rythme de rotation. L'expiration d'un indicateur IP doit mettre à jour le cluster, et non effacer le dossier.

## Système d'espionnage mondial de la RPC : routeurs, liens de confiance et mirroring du trafic

**Constat public.** Un avis multinational de 2025 a décrit une activité recoupant des noms utilisés dans des rapports commerciaux, notamment Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 et GhostEmperor. Les agences ont signalé l'utilisation de VPS loués et de routeurs intermédiaires compromis pour atteindre des fournisseurs de télécommunications et de réseaux. Les acteurs se déplaçaient via des liens de confiance fournisseur/client, modifiaient les routes, créaient des tunnels GRE/IPsec, utilisaient des conteneurs sur les appareils et activaient SPAN/RSPAN/ERSPAN ou la capture native de paquets afin de collecter des identifiants et du trafic client.<sup>[[13]](#references)</sup>

**Effet sur la confidentialité.** Un routeur compromis est simultanément un relais, un point d'observation et un participant réseau de confiance. Les interconnexions privées peuvent contourner les contrôles conçus autour de l'Internet public, tandis que le mirroring du trafic collecte des identifiants sans déployer d'agent endpoint.

**Ce qui l'expose.** Les différences de configuration, l'administration SNMP/SSH/web inattendue, les nouvelles routes statiques/tunnels, les sessions de mirroring, les conteneurs Guest Shell, les fichiers PCAP, les modifications des destinations TACACS+/RADIUS et la désactivation des logs. L'avis souligne que certains routeurs intermédiaires ne faisaient pas partie d'un botnet public précédemment identifié ; l'absence d'indicateurs ORB connus ne constituait donc pas une preuve d'innocence.

**Leçon défensive.** Utiliser une administration hors bande, des logs centralisés de configuration/authentification, des contrôles d'intégrité des images signées et de l'exécution, des restrictions sur la sortie des interfaces de gestion, ainsi que des alertes pour les modifications de routes, de mirroring, de tunnels et d'AAA. Étendre l'analyse d'un compromis suspect aux pairs de confiance avant l'éviction.

## UNC3886 RedPenguin : backdoors passives sur des routeurs de FAI

**Constat public.** Mandiant a attribué à UNC3886 des backdoors dérivées de TINYSHELL sur des routeurs Juniper MX en fin de vie. L'ensemble comprenait des implants actifs et passifs, des noms imitant des daemons légitimes, des fonctionnalités de désactivation des logs, de l'injection de processus dans un processus de confiance, une capacité de proxy SOCKS et une infrastructure considérée comme constituée de nœuds de staging ORB. Les variantes passives inspectaient les paquets via `libpcap` et ne s'activaient qu'après détection d'un motif magique ; l'une d'elles pouvait basculer vers un callback actif fourni dans le trigger.<sup>[[14]](#references)</sup>

**Effet sur la confidentialité.** Un implant passif n'émet aucun beacon périodique permettant sa découverte. Il partage les ports et le trafic d'un véritable équipement réseau, s'active brièvement et peut relayer les communications via un ORB plutôt que de se connecter directement au contrôleur final.

**Ce qui l'expose.** L'analyse mémoire, les différences entre le code sur disque et le code en cours d'exécution, les filtres de capture de paquets ou comportements de socket inattendus, les noms de processus/fichiers qui ne font qu'approximativement penser à des daemons légitimes, l'administration via des serveurs de terminaux, l'absence de logs et la relation en deux étapes entre les nœuds de staging et un contrôleur backend.

**Leçon défensive.** Acquérir la mémoire en plus des preuves issues du système de fichiers et de la configuration, comparer les processus/modules à une image de référence saine, surveiller l'utilisation de la capture de paquets et des filtres de socket, sécuriser les serveurs de terminaux d'administration et remplacer les équipements réseau en fin de vie. Une recherche ne trouvant aucun beacon sortant ne constitue pas une preuve d'intégrité.

## APT29 : domain fronting avec Tor

**Constat public.** MITRE indique qu'APT29 utilise le transport pluggable Tor `meek` pour effectuer du domain fronting sur le trafic C2. Le nom TLS externe semblait être celui d'un domaine autorisé hébergé sur un CDN, tandis que l'hôte HTTP interne sélectionnait la route réelle.<sup>[[6]](#references)</sup>

**Effet sur la confidentialité.** Un observateur appliquant un filtrage pouvait voir un front/CDN courant plutôt que la destination interne, et son blocage risquait de provoquer des dommages collatéraux.

**Ce qui l'expose.** Le CDN peut observer la discordance de routage, et un défenseur disposant d'une visibilité endpoint ou TLS légale peut corréler le processus, l'autorité, la durée de connexion, le profil d'octets et l'activité ultérieure. Des changements de politique du fournisseur peuvent désactiver la technique.

**Leçon défensive.** Ne pas s'appuyer uniquement sur une allowlist SNI. Appliquer un egress conscient des applications, comparer les identités TLS et HTTP lorsqu'elles sont visibles, et relier l'événement réseau au processus initiateur.

## APT41 et autres dead-drop resolvers

**Constat public.** MITRE documente l'utilisation par APT41 de sites légitimes, notamment GitHub, Pastebin, Microsoft TechNet, Cloudflare et des forums communautaires, pour publier ou récupérer des informations C2. D'autres outils liés à des États ont utilisé de manière similaire des publications, des documents et des réseaux sociaux.<sup>[[7]](#references)</sup>

**Effet sur la confidentialité.** Un binaire contient un service/objet légitime plutôt qu'une adresse C2 stable. L'objet peut être modifié pour faire tourner l'infrastructure, et la requête initiale se fond dans le trafic TLS courant.

**Ce qui l'expose.** L'identifiant de l'objet ou du compte reste stable ; des processus rares le récupèrent de manière répétée ; le contenu est décodé ; puis une seconde connexion sortante est établie. Les journaux du compte fournisseur et de l'API peuvent relier la publication à l'opérateur.

**Leçon défensive.** Conserver les chemins proxy complets, les identifiants d'objet et la filiation des processus endpoint. Un événement au niveau du domaine tel que « connexion à GitHub » est trop général.

## Turla : C2 via adresses satellite

**Constat public.** Kaspersky a signalé que Turla abusait de diffusions descendantes non chiffrées provenant d'anciens services Internet unidirectionnels DVB-S. Un opérateur situé dans la zone de couverture satellite pouvait sélectionner l'adresse d'un abonné légitime et recevoir les réponses diffusées vers celle-ci, donnant l'impression que le C2 était hébergé derrière un fournisseur satellite dans une autre région.<sup>[[8]](#references)</sup>

**Effet sur la confidentialité.** L'adresse apparente du serveur n'identifiait pas le récepteur, et les procédures classiques de saisie d'hébergement ou de WHOIS étaient moins utiles.

**Ce qui l'expose.** L'acteur avait toujours besoin d'un chemin de requête sortant, le routage était asymétrique, l'abonné légitime n'initiait pas l'échange C2 et une enquête RF/fournisseur pouvait réduire la zone de réception.

**Leçon défensive.** Considérer la géolocalisation comme une simple hypothèse. Vérifier la symétrie du chemin, le RTT, la propriété du routage et la capacité réelle du endpoint présumé à produire le service observé.

## Cyclops Blink et VPNFilter : les appareils edge comme couverture durable

**Constat public.** Un avis NCSC/CISA/FBI/NSA de 2022 a décrit le malware modulaire Cyclops Blink de Sandworm sur des appareils WatchGuard, déployé de manière persistante comme mise à jour du firmware et capable d'ajouter des modules. Le DOJ a décrit séparément le botnet VPNFilter d'APT28, composé auparavant de routeurs et d'appareils NAS, comme capable de collecte de renseignement, d'activité destructive et de misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Effet sur la confidentialité.** Les appliances edge sont constamment connectées, considérées comme des éléments d'infrastructure de confiance et peu couvertes par l'EDR. La persistance au niveau du firmware peut survivre à un redémarrage ordinaire et transformer l'appareil victime en relais ou en point de contrôle.

**Ce qui l'expose.** L'intégrité du firmware, le protocole d'implant propre au fournisseur, l'exposition inattendue de la gestion, les modifications de configuration et les beacons sortants. Les appareils edge doivent être traités comme des sujets forensiques, et non comme une plomberie transparente.

## RPDC : superposition de l'identité, du réseau et des finances

**Constat public.** Des affaires du DOJ décrivent des travailleurs de la RPDC obtenant des emplois à distance grâce à de fausses identités ou à des identités volées et à des VPN, recevant des cryptomonnaies, fractionnant les transferts, échangeant des actifs/chaînes, utilisant des NFT et mélangeant les produits. D'autres affaires décrivent des traders OTC et des sociétés-écrans convertissant des cryptomonnaies volées en achats. Le Trésor et le FBI ont publiquement relié les produits de Lazarus/TraderTraitor à des mixers et identifié des adresses issues de vols majeurs.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Effet sur la confidentialité.** Il ne s'agit pas d'une « privacy coin ». C'est une chaîne multidomaine : la persona et l'accès distant masquent la localisation du travailleur ; la crypto déplace la valeur ; la superposition brouille les récits transactionnels simples ; les traders OTC et les sociétés-écrans servent de passerelle vers les biens et la monnaie fiduciaire.

**Ce qui l'expose.** Les anomalies liées à l'employeur et à l'appareil, les facilitateurs réutilisés, la continuité temporelle et de valeur sur la blockchain, les données des exchanges/bridges, les adresses sanctionnées, l'identité du compte et les données d'expédition et d'entreprise reconnectent la chaîne.

**Leçon défensive.** Les équipes recrutement, IAM, endpoint, paie, blockchain et sanctions ont besoin d'un modèle de dossier partagé. Plus de détails sont disponibles dans [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Tendances communes aux cas

| Tendance | Exemples APT | Adaptation du défenseur |
|---|---|---|
| La sortie est une autre victime | APT28/Moobot, Volt Typhoon/KV, ORBs | enquêter sur la sortie et la corriger ; ne pas l'assimiler à la localisation de l'acteur |
| Les contrôles diffèrent selon la frontière | APT28 nearest neighbor | accorder aux accès internes/sans fil le même niveau d'assurance d'identité qu'aux accès Internet |
| Un service légitime sert de couche de routage | APT29, APT41 | conserver le contexte objet/chemin/processus, et pas uniquement le domaine de destination |
| Les appareils edge manquent de télémétrie | KV, Moobot, Cyclops Blink, ORBs | centraliser les logs de configuration/authentification/flux et vérifier le firmware et l'inventaire |
| L'infrastructure est partagée et éphémère | ORBs associés à la Chine | regrouper les comportements et la topologie, et suivre les changements de rôle au fil du temps |
| Plusieurs séparations faibles se combinent | Personas RPDC + VPN + crypto + OTC | relier les éléments d'identité, d'appareil, de réseau, de paiement et physiques |

## References

- [1] [Volexity — L'attaque Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Perturbation du botnet de routeurs Moobot contrôlé par le GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Perturbation du botnet KV de la RPC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Des acteurs de la RPC compromettent et maintiennent un accès persistant aux infrastructures critiques américaines](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Des acteurs d'espionnage associés à la Chine utilisent des réseaux ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla satellite](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Avis Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Perturbation de VPNFilter d'APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Un représentant de la Foreign Trade Bank de la RPDC inculpé dans des conspirations de blanchiment de cryptomonnaies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanctions contre Blender.io et fonds de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrer le compromis de réseaux mondiaux par des acteurs chinois soutenus par l'État](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router : UNC3886 cible des routeurs Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
