# Accès physique et sans fil dissimulé

Pour une mise en œuvre détaillée et approuvée par le propriétaire, couvrant le rendez-vous sortant, la récupération de l'alimentation/de la liaison montante, un minimum de secrets stockés sur l'appareil, les tests de capture et la surveillance d'une éventuelle découverte, voir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Modifier le chemin réseau peut également modifier l'origine physique apparente. Un acteur sophistiqué peut utiliser un système compromis à proximité, un appareil dissimulé, un accès public, une liaison de secours cellulaire ou un récepteur satellite afin que les journaux de la cible désignent un autre emplacement que celui de l'opérateur. Aucun de ces moyens ne supprime les preuves physiques, radio ou liées au fournisseur ; ils déplacent l'attribution vers différents jeux de données.

## Matrice des techniques

| Technique | Origine apparente | Condition nécessaire | Preuves à forte valeur |
|---|---|---|---|
| Pivot sans fil à proximité | une entreprise ou un domicile voisin de la cible | hôte compromis à double interfaçage et accès au Wi-Fi de la cible | journaux du endpoint de l'hôte voisin, association RF et RADIUS/DHCP de la cible |
| Réseau public/invité | NAT du lieu ou sortie du tunnel | accès légal ou contournement du contrôle d'accès | portail captif, DHCP, association à l'AP, vidéosurveillance et données de paiement/localisation |
| Appareil de dépôt dissimulé | adresse filaire, Wi-Fi ou cellulaire de la cible ou à proximité | placement ou livraison physique | port de switch/USB, RF, inventaire, alimentation et télémétrie du tunnel sortant |
| Routeur cellulaire/eSIM | NAT de l'opérateur ou APN dédié | modem/SIM/abonnement | IMEI/IMSI/eSIM, secteur cellulaire, compte opérateur et chronologie du trafic |
| Abus d'une liaison satellite | adresse de l'abonné dans l'empreinte du faisceau | faiblesse spécifique au protocole et au service | localisation RF, flux de liaison montante, RTT/routage impossible et journaux du fournisseur |

## Nearest Neighbor Attack

Volexity a documenté en 2022 une opération d'APT28/GRU dans laquelle l'acteur était éloigné de sa cible finale. Il a utilisé le password spraying contre le service public de la cible afin d'obtenir des identifiants valides, mais la MFA empêchait la connexion directe depuis Internet. Le Wi-Fi d'entreprise de la cible acceptait ces identifiants sans MFA. L'acteur a compromis des organisations physiquement proches de la cible, a trouvé un système à double interfaçage disposant d'une portée sans fil, puis a utilisé ce système pour s'authentifier sur le Wi-Fi de la cible. Volexity a nommé cette technique **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
La nouveauté réside dans la composition. Aucun opérateur ne se rend sur la cible et le MFA du service exposé sur Internet continue de fonctionner. Le voisin compromis fournit la proximité physique ; l’identifiant volé de la cible fournit l’accès logique ; le Wi-Fi de la cible devient le chemin de franchissement de la frontière.

### Prérequis et visibilité

- Un système situé à proximité doit être contrôlable à distance et disposer d’une radio compatible ou d’un accès à un autre pivot proche.
- Le SSID cible doit atteindre ce système, et l’admission Wi-Fi doit accepter un identifiant, un certificat ou un état d’appareil réutilisable.
- Le pivot a souvent besoin de deux chemins simultanés : l’un vers l’opérateur et l’autre vers le WLAN cible.
- La cible peut voir une nouvelle adresse MAC de station et un nom d’utilisateur légitime, mais aucun certificat d’appareil géré, élément de posture, historique ou entrée attendue dans le bâtiment ne correspondant.
- Les journaux du endpoint voisin peuvent faire apparaître des scans sans fil, de nouveaux profils, des changements d’interface, du tunneling et des activités de contrôle à distance.

### Détection et prévention

1. Exiger EAP-TLS reposant sur un certificat et une posture d’appareil géré pour le Wi-Fi d’entreprise ; ne pas considérer qu’un mot de passe ayant échoué au MFA sur Internet devient suffisant simplement parce qu’il arrive par radio.
2. Corréler l’authentification RADIUS avec l’identité MDM/NAC, l’association historique station/appareil, l’emplacement de l’AP, les événements d’accès physique et les sessions simultanées.
3. Déclencher une alerte lorsqu’un compte s’associe pour la première fois, depuis un bord d’AP inhabituel, sans certificat géré ou alors que la même identité est active ailleurs.
4. Surveiller les endpoints capables de relier des interfaces. Sous Windows, Linux et sur les appliances réseau, rechercher les profils WLAN inattendus, les configurations de forwarding/NAT, les adaptateurs virtuels et les tunnels persistants.
5. Réduire les fuites de signal inutiles grâce à un positionnement raisonnable des AP et à une planification de la puissance. Il s’agit d’un contrôle complémentaire, pas d’une authentification.
6. Coordonner la réponse aux incidents avec les occupants voisins : la source radio finale peut elle-même être une victime.

Le [lab à deux organisations contrôlé](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduit ces observables sans attaquer un voisin.

## Lieux publics et Wi-Fi de tiers

L’utilisation du Wi-Fi d’un café, d’un hôtel, d’un aéroport ou d’une municipalité modifie l’adresse IP présentée à une destination. Elle ne crée pas d’anonymat. Le lieu ou son fournisseur peut conserver l’association à l’AP, l’adresse MAC de l’appareil, le bail DHCP, le compte du portail captif, la validation par SMS/e-mail et les journaux de flux. L’entrée physique, la vidéosurveillance, l’achat, la localisation mobile et les données de déplacement peuvent relier l’événement numérique à une personne.

Un acteur peut tenter de réduire une trace en utilisant des adresses MAC randomisées, un appareil distinct, de l’argent liquide ou un tunnel. La corrélation entre les couches reste possible grâce à l’heure d’arrivée, aux habitudes de fréquentation répétées, aux empreintes radio, au comportement sur le portail, au timing du trafic, aux images des caméras et au fournisseur du tunnel. Un VPN déplace également la destination des journaux du lieu vers ceux du VPN ; il ne supprime pas le fait que le lieu sait que l’appareil était présent.

Les responsables des accès publics devraient isoler les clients, bloquer le trafic latéral, utiliser WPA2/3-Enterprise ou des clés par appareil lorsque cela est possible, conserver des journaux DHCP/RADIUS/sécurité proportionnés, protéger les portails captifs et publier une procédure de signalement des abus. Les Red teams ne devraient utiliser un tel lieu que lorsque ses conditions d’utilisation et l’engagement l’autorisent ; contourner un portail, voler un accès ou cibler d’autres clients ne constitue pas un raccourci de test autorisé.

## Dispositifs de drop covert et warshipping

Un drop est un petit système placé dans un site ou qui y est livré, puis contrôlé via Ethernet sortant, Wi-Fi ou réseau cellulaire. Le « warshipping » conditionne l’appareil de sorte qu’une livraison ordinaire le fasse entrer dans le périmètre radio. Le matériel peut aller d’un ordinateur monocarte à un chargeur modifié, un périphérique USB, une appliance réseau ou un modem alimenté par batterie.

Architecture opérationnelle :
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Le dispositif peut fournir un accès initial à distance, effectuer des mesures sans fil, émuler un périphérique d’exercice autorisé ou relayer du trafic. Sa source apparente est locale, mais il crée des artefacts physiques : numéros de série, emballages, empreintes, caméras, journaux d’accès, consommation électrique, descripteurs USB, négociation du switchport, empreintes DHCP, comportement de l’OUI MAC/ de la randomisation, émissions RF et connexions de rendez-vous récurrentes.

### Contrôles défensifs

- Maintenir des procédures pour la salle de réception et l’inventaire des actifs ; inspecter les appareils électroniques et colis inattendus adressés à des employés inexistants.
- Utiliser 802.1X/NAC sur les accès filaires et sans fil, désactiver les ports inutilisés et placer les appareils inconnus dans un VLAN de remédiation restreint.
- Déclencher des alertes pour les nouvelles empreintes DHCP, les MAC administrées localement qui persistent, les nouveaux périphériques réseau/HID USB, le Wi-Fi Direct/Bluetooth non autorisé et les tunnels sortants de longue durée.
- Établir une base de référence du switchport, du Power over Ethernet, du DNS et du comportement TLS. Un petit hôte sans fiche d’inventaire qui effectue périodiquement des connexions chiffrées constitue un signal plus pertinent que le seul « Raspberry Pi OUI ».
- Pendant un exercice, inventorier, étiqueter, définir le périmètre, chiffrer, fournir une fonction d’arrêt à distance, fixer une date limite de récupération et s’assurer qu’une perte ne puisse pas exposer des identifiants réutilisables.

## Backhaul cellulaire et eSIM

Un modem cellulaire évite la gateway Internet de la cible et peut maintenir un drop accessible derrière le NAT de l’opérateur grâce à un rendez-vous sortant. Les adresses mobiles peuvent changer ou être partagées ; l’opérateur cellulaire dispose néanmoins de solides éléments concernant l’abonné et le réseau : identité SIM/eSIM, IMSI, adresses/ports attribués, synchronisation de cellule/secteur, données de compte/paiement et d’itinérance.

Du point de vue de l’entreprise, détecter les modems et hotspots personnels inattendus au moyen de relevés sans fil/RF, de l’inventaire USB/PCI des endpoints, de restrictions MDM, de la surveillance des SSID rogue et d’inspections physiques. Un drop qui utilise le réseau cellulaire pour son contrôle peut tout de même être détecté par son comportement Ethernet/Wi-Fi local et ses émissions radio.

Pour les exercices autorisés, l’organisation devrait être propriétaire de l’abonnement et du modem, enregistrer les identifiants auprès du controller et vérifier que les conditions de l’opérateur/fournisseur autorisent le trafic. Une étiquette prépayée ou un achat en cryptocurrency n’efface pas les données relatives aux antennes, à l’appareil ou au point de vente.

## Randomisation MAC et device fingerprinting

Les systèmes modernes peuvent utiliser une MAC randomisée administrée localement pour chaque réseau. Cela réduit le suivi passif à long terme fondé sur une MAC d’usine stable ; cela ne dissimule pas :

- le calendrier des probes/associations et l’ensemble des capacités réseau demandées ;
- les éléments d’information 802.11, les débits pris en charge et le comportement spécifique au fournisseur ;
- les options/nom d’hôte DHCP, les identifiants IPv6 et l’empreinte du captive portal/navigateur ;
- l’identité ou le certificat 802.1X authentifié ;
- le compte de couche supérieure, le tunnel et le profil de trafic ; ou
- l’observation physique.

Les défenseurs ne devraient pas utiliser les listes d’autorisation MAC comme mécanisme d’authentification. Relier l’identité radio au certificat/à la posture de l’appareil et considérer les changements de MAC comme normaux, sauf si un autre contexte est anormal.

## Détournement de liaison satellite

Kaspersky a documenté l’utilisation par Turla de faiblesses dans d’anciens services Internet satellite DVB-S unidirectionnels. Selon le modèle décrit, un abonné distant légitime envoyait des requêtes sortantes via une liaison terrestre, mais recevait les données descendantes via une diffusion satellite étendue non chiffrée. Un acteur situé dans la zone de couverture du satellite pouvait observer la liaison descendante, choisir l’adresse IP d’un abonné actif et faire en sorte que les réponses C2 soient adressées à cette IP. L’abonné légitime et l’acteur recevaient tous deux la diffusion ; l’acteur extrayait le trafic destiné au port sélectionné tandis que l’abonné légitime rejetait les paquets non sollicités. L’opérateur du C2 semblait alors utiliser une adresse appartenant au fournisseur satellite dans une autre zone géographique.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Cela était spécifique au protocole/service, limité par la bande passante et ne revenait pas à compromettre un terminal satellite chiffré bidirectionnel moderne. Cela ne dissimulait pas non plus le chemin de la requête sortante de l'acteur à un observateur suffisamment capable. Les possibilités de détection incluent un routage asymétrique/impossible, du trafic vers un abonné qui n'a pas initié le flux, des ports de destination inhabituels, la télémétrie du fournisseur, l'étude de l'emplacement du récepteur et des RF, ainsi que la configuration du malware. Utilisez ce cas pour remettre en question l'hypothèse selon laquelle géolocaliser une IP C2 permet de géolocaliser son contrôleur, et non comme une recette de mise en œuvre.

## Feuille de travail de corrélation physique-numérique

Lorsqu'une source apparemment locale est suspecte, établissez une seule chronologie :

1. synchronisez les horloges des AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch et systèmes de contrôle des accès physiques ;
2. identifiez la première association radio ou le premier établissement de liaison, et pas seulement la première alerte ;
3. associez la station au certificat, à la posture de l'appareil, à l'empreinte DHCP et à l'emplacement du switch/AP ;
4. recherchez une activité simultanée de contrôle à distance/tunnel sur les systèmes voisins ;
5. examinez les livraisons, les visiteurs, les anomalies d'inventaire, les caméras et les résultats RF conformément aux politiques/lois applicables ;
6. préservez l'appareil suspect et l'état réseau volatile ; ne le redémarrez pas brutalement ;
7. déterminez si la source apparente est une infrastructure contrôlée par l'acteur ou une autre victime.

## References

- [1] [Volexity — The Nearest Neighbor Attack: How a Russian APT weaponized nearby Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in the sky](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
