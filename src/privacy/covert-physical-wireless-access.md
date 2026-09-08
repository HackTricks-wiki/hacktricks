# Accès physique et wireless covert

{{#include ../banners/hacktricks-training.md}}

Pour une implémentation détaillée et approuvée par le propriétaire, couvrant le rendez-vous outbound, la récupération de l'alimentation/uplink, un minimum de secrets conservés sur l'appareil, les tests de capture et la surveillance d'une éventuelle découverte, voir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Modifier le chemin réseau peut également modifier l'origine physique apparente. Un acteur sophistiqué peut utiliser un système compromis à proximité, un appareil dissimulé, un accès public, un backhaul cellulaire ou un récepteur satellite afin que les logs de la cible indiquent une origine éloignée de l'opérateur. Aucun de ces moyens ne supprime les éléments de preuve physiques, radio ou liés au provider ; ils déplacent l'attribution vers différents jeux de données.

## Matrice des techniques

| Technique | Origine apparente | Condition nécessaire | Éléments de preuve à forte valeur |
|---|---|---|---|
| Nearby wireless pivot | une entreprise ou un domicile adjacent à la cible | un hôte dual-homed compromis et un accès au Wi-Fi de la cible | logs endpoint de l'hôte voisin, association RF et RADIUS/DHCP de la cible |
| Public/guest network | NAT du site ou sortie du tunnel | accès autorisé ou bypass du contrôle d'accès | captive portal, DHCP, association AP, vidéosurveillance et données de paiement/localisation |
| Covert drop device | adresse filaire, Wi-Fi ou cellulaire de la cible ou d'un site proche | placement physique ou livraison | switchport/USB, RF, inventaire, alimentation et télémétrie du tunnel outbound |
| Cellular router/eSIM | NAT du carrier ou APN dédié | modem/SIM/subscription | IMEI/IMSI/eSIM, secteur cellulaire, compte carrier et timing du trafic |
| Satellite-link abuse | adresse de l'abonné dans l'empreinte du faisceau | faiblesse spécifique au protocole et au service | localisation RF, flux uplink, RTT/routage impossible et enregistrements du provider |

## Nearest-neighbor attack

Volexity a documenté en 2022 une opération d'APT28/GRU dans laquelle l'acteur était éloigné de sa cible finale. Il a effectué un password spraying contre le service public de la cible afin d'obtenir des identifiants valides, mais la MFA empêchait la connexion directe depuis Internet. Le Wi-Fi d'entreprise de la cible acceptait ces identifiants sans MFA. L'acteur a compromis des organisations physiquement proches de la cible, trouvé un système dual-homed disposant d'une portée wireless, puis utilisé ce système pour s'authentifier au Wi-Fi de la cible. Volexity a nommé cette méthode **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
La nouveauté réside dans la composition. Aucun opérateur ne se déplace jusqu'à la cible et le MFA du service exposé sur Internet continue de fonctionner. Le voisin compromis fournit la proximité physique ; l'identifiant de la cible volé fournit l'accès logique ; le Wi-Fi de la cible devient le chemin permettant de franchir la frontière.

### Prérequis et visibilité

- Un système situé à proximité doit pouvoir être contrôlé à distance et disposer d'une radio compatible ou d'un accès à un autre pivot proche.
- Le SSID cible doit atteindre ce système, et l'admission Wi-Fi doit accepter un identifiant, un certificat ou un état d'appareil réutilisable.
- Le pivot a souvent besoin de deux chemins simultanés : un vers l'opérateur et un autre vers le WLAN cible.
- La cible peut voir une nouvelle adresse MAC de station et un nom d'utilisateur légitime, mais aucun certificat d'appareil géré, état de conformité, historique ou accès au bâtiment attendu correspondant.
- Les logs de l'endpoint voisin peuvent afficher des scans sans fil, de nouveaux profils, des changements d'interface, du tunneling et des activités de remote control.

### Détection et prévention

1. Exiger EAP-TLS adossé à un certificat et un état de conformité d'appareil géré pour le Wi-Fi d'entreprise ; ne pas considérer comme suffisant un mot de passe ayant échoué au MFA sur Internet simplement parce qu'il arrive par radio.
2. Corréler l'authentification RADIUS avec l'identité MDM/NAC, l'association historique station/appareil, l'emplacement de l'AP, les événements d'accès physique et les sessions simultanées.
3. Déclencher une alerte lorsqu'un compte s'associe pour la première fois, depuis une zone périphérique d'AP inhabituelle, sans certificat géré, ou lorsque la même identité est active ailleurs.
4. Surveiller les endpoints capables de faire transiter le trafic entre des interfaces. Sous Windows, Linux et sur les appliances réseau, examiner les profils WLAN inattendus, la configuration du forwarding/NAT, les adaptateurs virtuels et les tunnels persistants.
5. Réduire les fuites de signal inutiles grâce à un positionnement raisonnable des AP et à une planification de la puissance. Il s'agit d'un contrôle complémentaire, pas d'une authentification.
6. Coordonner la réponse à incident avec les occupants voisins : la source radio finale peut elle-même être une victime.

Le [lab appartenant aux deux organisations](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduit ces éléments observables sans attaquer un voisin.

## Lieux publics et Wi-Fi tiers

L'utilisation du Wi-Fi d'un café, d'un hôtel, d'un aéroport ou d'une municipalité modifie l'adresse IP présentée à une destination. Elle ne crée pas l'anonymat. Le lieu ou son fournisseur peut conserver l'association à l'AP, l'adresse MAC de l'appareil, le bail DHCP, le compte du portail captif, la validation par SMS/e-mail et les logs de flux. L'entrée sur place, la vidéosurveillance, l'achat, les données de localisation mobile et les informations de déplacement peuvent relier l'événement numérique à une personne.

Un acteur peut tenter de réduire l'un de ces identifiants en utilisant des adresses MAC randomisées, un appareil séparé, des espèces ou un tunnel. La corrélation entre les différentes couches reste possible grâce à l'heure d'arrivée, aux habitudes de fréquentation répétées, aux empreintes radio, au comportement sur le portail, au timing du trafic, aux images des caméras et au fournisseur du tunnel. Un VPN déplace également la destination, des logs du lieu vers ceux du VPN ; il ne supprime pas le fait que le lieu sait que l'appareil était présent.

Les responsables des accès publics devraient isoler les clients, bloquer le trafic latéral, utiliser WPA2/3-Enterprise ou des clés par appareil lorsque cela est possible, conserver des logs DHCP/RADIUS/de sécurité proportionnés, protéger les portails captifs et publier une procédure de signalement des abus. Les Red teams ne devraient utiliser un tel lieu que lorsque ses conditions et l'engagement l'autorisent ; contourner un portail, voler un accès ou cibler d'autres clients ne constitue pas un raccourci de test autorisé.

## Dispositifs de dépôt furtifs et warshipping

Un dispositif de dépôt est un petit système placé dans un site ou livré à celui-ci, puis contrôlé via Ethernet sortant, Wi-Fi ou réseau cellulaire. Le « warshipping » conditionne l'appareil de sorte qu'une livraison ordinaire le transporte à l'intérieur du périmètre radio. Le matériel peut aller d'un ordinateur monocarte à un chargeur modifié, un périphérique USB, une appliance réseau ou un modem alimenté par batterie.

Architecture opérationnelle :
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
L’appareil peut fournir un foothold distant, effectuer des mesures wireless, émuler un périphérique d’exercice autorisé ou relayer du trafic. Sa source apparente est locale, mais il crée des artefacts physiques : numéros de série, emballages, fingerprints, caméras, journaux d’accès, consommation électrique, descripteurs USB, négociation du switchport, fingerprints DHCP, comportement de l’OUI MAC/de la randomisation, émissions RF et connexions récurrentes de rendezvous.

### Contrôles défensifs

- Maintenir des procédures pour la salle de réception et l’inventaire des actifs ; inspecter les appareils électroniques et colis inattendus adressés à des employés inexistants.
- Utiliser 802.1X/NAC sur les accès filaires et wireless, désactiver les ports inutilisés et placer les appareils inconnus dans un VLAN de remédiation restreint.
- Déclencher des alertes sur les nouveaux fingerprints DHCP, les MAC administrées localement qui persistent, les nouveaux appareils réseau/HID USB, le Wi-Fi Direct/Bluetooth non autorisé et les tunnels sortants de longue durée.
- Établir une baseline du switchport, du power-over-Ethernet, du DNS et du comportement TLS. Un petit hôte sans fiche d’inventaire qui établit périodiquement des connexions chiffrées est un meilleur signal que le seul « Raspberry Pi OUI ».
- Pendant un exercice, inventorier, étiqueter, définir le scope, chiffrer, fournir un remote kill, fixer une date limite de récupération et veiller à ce qu’une perte ne puisse pas exposer des identifiants réutilisables.

## Backhaul cellulaire et eSIM

Un modem cellulaire évite la gateway Internet de la cible et peut maintenir un drop accessible derrière le NAT de l’opérateur grâce à un rendezvous sortant. Les adresses mobiles peuvent changer ou être partagées ; l’opérateur cellulaire conserve néanmoins de nombreux éléments de preuve concernant l’abonné et le réseau : identité de la SIM/eSIM, IMSI, adresses/ports attribués, horaires des cellules/secteurs, données de compte/paiement et d’itinérance.

Du point de vue de l’entreprise, détecter les modems inattendus et les hotspots personnels au moyen de surveys wireless/RF, de l’inventaire USB/PCI des endpoints, de restrictions MDM, de la surveillance des rogue SSID et d’inspections physiques. Un drop qui utilise le cellulaire pour son contrôle peut tout de même être détecté par son comportement Ethernet/Wi-Fi local et ses émissions radio.

Pour les exercices autorisés, l’organisation devrait être propriétaire de l’abonnement et du modem, enregistrer les identifiants auprès du contrôleur et vérifier que les conditions de l’opérateur/fournisseur autorisent le trafic. Une étiquette prépayée ou un achat en cryptomonnaie n’efface pas les données relatives aux antennes, à l’appareil ou au détaillant.

## Randomisation des MAC et fingerprinting des appareils

Les systèmes modernes peuvent utiliser une MAC randomisée administrée localement pour chaque réseau. Cela réduit le tracking passif à long terme par une MAC d’usine stable ; cela ne dissimule pas :

- le timing des probes/associations et l’ensemble des capacités réseau demandées ;
- les éléments d’information 802.11, les débits pris en charge et le comportement spécifique au fournisseur ;
- les options/nom d’hôte DHCP, les identifiants IPv6 et le fingerprint du captive portal/navigateur ;
- l’identité ou le certificat 802.1X authentifié ;
- le compte de couche supérieure, le tunnel et le pattern de trafic ; ou
- l’observation physique.

Les défenseurs ne devraient pas utiliser des listes d’autorisation MAC comme mécanisme d’authentification. Relier l’identité radio au certificat et à la posture de l’appareil, et considérer les changements de MAC comme normaux sauf si un autre contexte est anormal.

## Détournement d’une liaison satellite

Kaspersky a documenté l’utilisation par Turla de vulnérabilités dans un ancien accès Internet satellite DVB-S unidirectionnel. Dans le modèle décrit, un abonné distant légitime envoyait des requêtes sortantes via une liaison terrestre, mais recevait les données descendantes via une diffusion satellite étendue non chiffrée. Un acteur situé dans la zone couverte par le satellite pouvait observer la liaison descendante, choisir l’adresse IP d’un abonné actif et faire en sorte que les réponses C2 soient adressées à cette IP. L’abonné légitime et l’acteur recevaient tous deux la diffusion ; l’acteur extrayait le trafic destiné au port sélectionné, tandis que l’abonné légitime rejetait les paquets non sollicités. L’opérateur du C2 semblait alors utiliser une adresse appartenant au fournisseur satellite dans une autre zone géographique.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Il s'agissait d'un protocole/service spécifique, limité par la bande passante et non équivalent à la compromission d'un terminal satellite moderne chiffré bidirectionnel. Cela ne masquait pas non plus le chemin de la requête sortante de l'acteur à un observateur suffisamment compétent. Les possibilités de détection incluent un routage asymétrique/impossible, du trafic vers un abonné qui n'a pas initié le flux, des ports de destination inhabituels, la télémétrie du provider, l'analyse de l'emplacement du récepteur/RF et la configuration du malware. Utilisez ce cas pour remettre en question l'hypothèse selon laquelle la géolocalisation d'une IP C2 géolocalise son contrôleur, et non comme une recette de construction.

## Feuille de corrélation physique-numérique

Lorsqu'une source apparemment locale est suspecte, établissez une seule chronologie :

1. normalisez les horloges AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch et contrôle d'accès physique ;
2. identifiez la première association radio ou activation de liaison, et pas seulement la première alerte ;
3. associez la station au certificat, à la posture de l'appareil, à l'empreinte DHCP et à l'emplacement du switch/AP ;
4. recherchez une activité simultanée de contrôle à distance/tunnel sur les systèmes voisins ;
5. examinez les livraisons, les visiteurs, les anomalies d'inventaire, les caméras et les résultats RF conformément à la policy/loi applicable ;
6. préservez l'appareil suspect et l'état réseau volatile ; ne redémarrez pas brutalement ;
7. déterminez si la source apparente est une infrastructure contrôlée par l'acteur ou une autre victime.

## References

- [1] [Volexity — L'attaque du voisin le plus proche : comment un APT russe a weaponized des réseaux Wi-Fi voisins](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla : command and control d'un APT dans le ciel](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Ajouts matériels (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Directives pour sécuriser les réseaux locaux sans fil](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
