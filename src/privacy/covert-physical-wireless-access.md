# Accès physique et sans fil furtif

{{#include ../banners/hacktricks-training.md}}

Pour une implémentation détaillée approuvée par le propriétaire, couvrant le rendez-vous sortant, la récupération de l’alimentation/de la liaison montante, la minimisation des secrets stockés sur l’appareil, les tests de capture et la surveillance en cas de découverte, voir [Nœuds de terrain autorisés résilients à la capture](capture-resilient-authorized-field-nodes.md).

Modifier le chemin réseau peut aussi modifier l’origine physique apparente. Un acteur sophistiqué peut utiliser un système compromis à proximité, un appareil caché, un accès public, une liaison cellulaire ou un récepteur satellite afin que les journaux de la cible désignent un autre endroit que celui de l’opérateur. Aucun de ces moyens n’élimine les traces physiques, radio ou laissées chez le fournisseur ; ils déplacent l’attribution vers d’autres jeux de données.

## Matrice des techniques

| Technique | Origine apparente | Condition nécessaire | Preuves à forte valeur |
|---|---|---|---|
| Pivot sans fil à proximité | une entreprise ou un domicile à côté de la cible | hôte à double connexion compromis et accès au Wi-Fi de la cible | journaux endpoint de l’hôte voisin, association RF et RADIUS/DHCP de la cible |
| Réseau public/visiteur | NAT du lieu ou sortie du tunnel | accès légal ou contournement du contrôle d’accès | portail captif, DHCP, association au point d’accès, vidéosurveillance et données de paiement/de localisation |
| Appareil de dépôt furtif | adresse filaire, Wi-Fi ou cellulaire de la cible ou des environs | installation ou livraison physique | télémétrie du port de commutation/USB, RF, inventaire, alimentation et tunnel sortant |
| Routeur cellulaire/eSIM | NAT de l’opérateur ou APN dédié | modem/SIM/abonnement | IMEI/IMSI/eSIM, secteur cellulaire, compte opérateur et chronologie du trafic |
| Détournement de liaison satellite | adresse d’abonné dans l’empreinte du faisceau | vulnérabilité spécifique au protocole et au service | localisation RF, flux de liaison montante, RTT/routage impossibles et dossiers du fournisseur |

## Attaque du voisin le plus proche

Volexity a documenté une opération APT28/GRU de 2022 dans laquelle l’acteur était éloigné de sa cible finale. Il a lancé une attaque par pulvérisation de mots de passe contre le service public de la cible pour obtenir des identifiants valides, mais l’authentification multifacteur a empêché la connexion directe depuis Internet. Le Wi-Fi d’entreprise de la cible acceptait ces identifiants sans authentification multifacteur. L’acteur a compromis des organisations physiquement proches de la cible, trouvé un système à double connexion avec une portée sans fil, puis utilisé ce système pour s’authentifier au Wi-Fi de la cible. Volexity a nommé cette technique **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

La nouveauté réside dans la combinaison. Aucun opérateur ne se rend sur la cible et le MFA du service exposé à Internet continue de fonctionner. Le voisin compromis fournit la proximité physique ; les identifiants volés de la cible fournissent l’accès logique ; le Wi-Fi de la cible devient le chemin qui franchit la frontière.

### Prérequis et visibilité

- Un système à proximité doit pouvoir être contrôlé à distance et disposer d’une radio compatible ou d’un accès à un autre pivot proche.
- Le SSID cible doit être accessible depuis ce système, et l’admission Wi-Fi doit accepter un identifiant, un certificat ou un état d’appareil réutilisable.
- Le pivot a souvent besoin de deux chemins simultanés : l’un vers l’opérateur, l’autre vers le WLAN cible.
- La cible peut voir une nouvelle adresse MAC de station et un nom d’utilisateur légitime, mais aucun certificat d’appareil géré correspondant, aucune posture, aucun historique ni entrée attendue dans le bâtiment.
- Les journaux du poste voisin peuvent indiquer des balayages sans fil, de nouveaux profils, des changements d’interface, du tunneling et une activité de contrôle à distance.

### Détection et prévention

1. Exiger le protocole EAP-TLS basé sur un certificat et une posture d’appareil géré pour le Wi-Fi d’entreprise ; ne pas considérer comme suffisant un mot de passe qui n’a pas satisfait au MFA sur Internet simplement parce qu’il est présenté par radio.
2. Corréler l’authentification RADIUS avec l’identité MDM/NAC, l’association historique station/appareil, l’emplacement de l’AP, les événements de contrôle d’accès physique et les sessions simultanées.
3. Déclencher une alerte lorsqu’un compte s’associe pour la première fois depuis un bord d’AP inhabituel, sans certificat géré, ou lorsque la même identité est active ailleurs.
4. Surveiller les terminaux capables de relier des interfaces. Sous Windows, Linux et sur les équipements réseau, examiner les profils WLAN inattendus, la configuration du transfert/NAT, les adaptateurs virtuels et les tunnels persistants.
5. Réduire la propagation inutile du signal en choisissant judicieusement l’emplacement et la puissance des AP. Il s’agit d’une mesure complémentaire, pas d’une méthode d’authentification.
6. Coordonner la réponse aux incidents avec les occupants voisins : la source radio finale peut elle-même être une victime.

Le [lab contrôlé impliquant deux organisations](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduit ces éléments observables sans attaquer un voisin.

### Valider un chemin de pivot Windows

Un hôte Windows à double connexion ne relie pas automatiquement ses interfaces. Commencez par inventorier ses adaptateurs, ses routes et son état WLAN, puis connectez-vous uniquement à l’aide d’un profil approuvé. L’argument `name` de `netsh wlan connect` désigne un profil installé, et non un SSID et un mot de passe quelconques. Comparez la table de routage avant et après la connexion afin qu’une nouvelle route par défaut n’interrompe pas le chemin de contrôle et ne fausse pas le résultat. Poursuivez avec les [vérifications après association](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) seulement après avoir confirmé l’interface et la route prévues.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

L’artefact d’incident publié par Volexity illustre une autre distinction utile. Son code C# intégré ouvre l’API WLAN, énumère les interfaces, lit un fichier XML EAP depuis le disque et appelle `WlanSetProfileEapXmlUserData` pour un profil nommé sur la première interface sans fil. L’API définit les identifiants utilisateur EAP d’un profil 802.1X existant, mais le composant publié ne contient ni `WlanConnect` ni la logique de découverte décrite dans le rapport. Considérez-le comme un outil de provisionnement de profil plutôt que comme un connecteur complet, et inspectez le profil obtenu dans le cadre de l’[évaluation du client et du supplicant](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Lieux publics et Wi-Fi tiers

Utiliser le Wi-Fi d’un café, d’un hôtel, d’un aéroport ou d’une municipalité modifie l’adresse IP visible par une destination. Cela ne rend pas anonyme. Le lieu ou son fournisseur peut conserver les journaux d’association aux points d’accès, les adresses MAC des appareils, les baux DHCP, les comptes de portail captif, les validations par SMS ou e-mail et les journaux de flux. L’entrée dans les lieux, la vidéosurveillance, les achats, la géolocalisation mobile et les données de voyage peuvent relier l’événement numérique à une personne.

Un acteur peut tenter de réduire l’exposition d’un identifiant en utilisant des adresses MAC aléatoires, un appareil distinct, des espèces ou un tunnel. Une corrélation entre plusieurs couches reste possible à partir de l’heure d’arrivée, des habitudes de fréquentation, des empreintes radio, du comportement sur le portail, du minutage du trafic, des images des caméras et du fournisseur du tunnel. Un VPN déplace également les informations détenues sur la destination des journaux du lieu vers ceux du VPN ; il n’efface pas la connaissance du lieu quant à la présence de l’appareil.

Les responsables des réseaux publics devraient isoler les clients, bloquer le trafic latéral, utiliser WPA2/3-Enterprise ou des clés par appareil lorsque c’est possible, conserver des journaux DHCP/RADIUS/de sécurité proportionnés, protéger les portails captifs et publier une procédure de signalement des abus. Les équipes red team ne devraient utiliser un tel lieu que si ses conditions d’utilisation et le cadre de la mission l’autorisent ; contourner un portail, voler un accès ou cibler d’autres clients n’est pas un raccourci de test autorisé.

## Dispositifs de dépôt furtifs et warshipping

Un dispositif de dépôt est un petit système placé dans un site ou qui y est livré, puis contrôlé via Ethernet sortant, Wi-Fi ou réseau cellulaire. Le « warshipping » consiste à conditionner l’appareil de sorte qu’une livraison ordinaire le fasse entrer dans le périmètre radio. Le matériel peut aller d’un ordinateur monocarte à un chargeur modifié, un périphérique USB, un équipement réseau ou un modem alimenté par batterie.

Architecture opérationnelle :

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

L’appareil peut fournir un point d’appui à distance, effectuer des mesures sans fil, émuler un périphérique d’exercice autorisé ou relayer du trafic. Sa source apparente est locale, mais il laisse des traces physiques : numéros de série, emballages, empreintes digitales, caméras, journaux d’accès, consommation électrique, descripteurs USB, négociation du port de commutation, empreintes DHCP, comportement de l’OUI MAC et de la randomisation, émissions RF et connexions récurrentes de rendez-vous.

### Mesures défensives

- Maintenir des procédures de réception et d’inventaire des actifs ; inspecter les appareils électroniques inattendus et les colis adressés à des employés inexistants.
- Utiliser 802.1X/NAC pour les accès filaires et sans fil, désactiver les ports inutilisés et placer les appareils inconnus dans un VLAN de remédiation restreint.
- Déclencher des alertes en cas de nouvelles empreintes DHCP, d’adresses MAC administrées localement qui persistent, de nouveaux périphériques USB réseau/HID, de Wi-Fi Direct/Bluetooth non autorisés et de tunnels sortants de longue durée.
- Établir une référence du comportement des ports de commutation, de l’alimentation par Ethernet, du DNS et de TLS. Un petit hôte absent de l’inventaire qui établit périodiquement des connexions chiffrées constitue un signal plus fort que le seul « OUI Raspberry Pi ».
- Pendant un exercice, inventorier, étiqueter, définir le périmètre, chiffrer, prévoir un mécanisme d’arrêt à distance, fixer une échéance de récupération et veiller à ce qu’une perte ne puisse pas exposer des identifiants réutilisables.

## Liaison cellulaire et eSIM

Un modem cellulaire évite la passerelle Internet de la cible et peut rester joignable derrière un NAT opérateur grâce à un rendez-vous sortant. Les adresses mobiles peuvent changer ou être partagées ; l’opérateur cellulaire dispose néanmoins de données solides sur l’abonné et le réseau : identité de la SIM/eSIM, IMSI, IMEI de l’appareil, adresses/ports attribués, horaires des cellules/secteurs, données de compte/paiement et d’itinérance.

Du point de vue de l’entreprise, détecter les modems inattendus et les hotspots personnels au moyen de relevés sans fil/RF, de l’inventaire USB/PCI des terminaux, de restrictions MDM, de la surveillance des SSID malveillants et d’inspections physiques. Un dispositif implanté qui utilise le réseau cellulaire pour le contrôle peut tout de même être détecté par son comportement Ethernet/Wi-Fi local et ses émissions radio.

Pour les exercices autorisés, l’organisation devrait détenir l’abonnement et le modem, consigner les identifiants auprès du contrôleur et vérifier que les conditions de l’opérateur/fournisseur autorisent le trafic. Une étiquette prépayée ou un achat en cryptomonnaie n’efface pas les données des antennes-relais, des appareils ou des commerçants.

## Randomisation MAC et empreinte des appareils

Les systèmes modernes peuvent utiliser une adresse MAC aléatoire administrée localement pour chaque réseau. Cela réduit le suivi passif à long terme fondé sur une adresse MAC d’usine stable ; cela ne masque pas :

- le moment des sondes/associations et l’ensemble des capacités réseau demandées ;
- les éléments d’information 802.11, les débits pris en charge et les comportements propres au fournisseur ;
- les options/nom d’hôte DHCP, les identifiants IPv6 et l’empreinte du navigateur/portail captif ;
- l’identité ou le certificat 802.1X authentifié ;
- les comptes de couche supérieure, les tunnels et les schémas de trafic ; ou
- l’observation physique.

Les défenseurs ne devraient pas utiliser de listes d’autorisation MAC comme méthode d’authentification. Associer l’identité radio au certificat et à la posture de l’appareil, et considérer les adresses MAC changeantes comme normales, sauf si d’autres éléments de contexte sont anormaux.

## Détournement de liaison satellite

Kaspersky a documenté l’utilisation par Turla de faiblesses dans d’anciens services Internet satellite unidirectionnels DVB-S. Selon le modèle rapporté, un abonné distant légitime envoyait ses requêtes sortantes par une liaison terrestre, mais recevait les données descendantes via une diffusion satellite à grande portée non chiffrée. Un acteur situé dans la zone de couverture satellite pouvait observer la liaison descendante, choisir l’adresse IP d’un abonné actif et faire adresser les réponses C2 à cette adresse IP. L’abonné légitime et l’acteur recevaient tous deux la diffusion ; l’acteur extrayait le trafic destiné au port choisi, tandis que l’abonné légitime rejetait les paquets non sollicités. L’opérateur C2 semblait alors utiliser une adresse du fournisseur satellite située dans une autre région géographique.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Cela était spécifique à un protocole/service, limité par la bande passante et ne correspondait pas à la compromission d’un terminal satellite bidirectionnel chiffré moderne. Cela ne masquait pas non plus le chemin de la requête sortante de l’acteur à un observateur suffisamment compétent. Les possibilités de détection comprennent un routage asymétrique/impossible, du trafic vers un abonné qui n’a pas initié la connexion, des ports de destination inhabituels, la télémétrie du fournisseur, une enquête sur l’emplacement du récepteur et les signaux RF, ainsi que la configuration du malware. Utilisez ce cas pour remettre en question l’hypothèse selon laquelle géolocaliser une adresse IP de C2 permet de géolocaliser son contrôleur — et non comme un guide de fabrication.

## Feuille de corrélation entre le physique et le numérique

Lorsqu’une source apparemment locale est suspecte, établissez une chronologie unique :

1. synchronisez les horloges AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, commutateur et contrôle d’accès physique ;
2. identifiez la première association radio ou activation de liaison, et pas seulement la première alerte ;
3. associez la station au certificat, à la posture de l’appareil, à l’empreinte DHCP et à l’emplacement du commutateur/de l’AP ;
4. recherchez toute activité simultanée de contrôle à distance/tunnel sur les systèmes à proximité ;
5. examinez les livraisons, les visiteurs, les écarts d’inventaire, les caméras et les résultats RF conformément aux politiques/lois applicables ;
6. préservez l’appareil suspect et l’état volatil du réseau ; ne le redémarrez pas à l’aveugle ;
7. déterminez si la source apparente est une infrastructure contrôlée par l’acteur ou une autre victime.

## References

- [1] [Volexity — L’attaque du voisin le plus proche : comment un APT russe a militarisé les réseaux Wi-Fi à proximité](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla : commande et contrôle APT dans le ciel](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Ajouts de matériel (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Recommandations pour sécuriser les réseaux locaux sans fil](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Code WLAN PowerShell/C# expurgé](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Fonction WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
