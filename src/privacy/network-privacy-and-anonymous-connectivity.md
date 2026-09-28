# Confidentialité réseau et connectivité anonyme

{{#include ../banners/hacktricks-training.md}}

La confidentialité réseau est une décision de routage, pas une identité complète. Sélectionnez un chemin en vous demandant qui ne doit pas pouvoir relier la **source**, la **destination**, le **contenu** et le **timing**.

Pour l'inventaire normalisé — `Pros`, `Cons`, la `Procedure` étape par étape et la `Detection` pour chaque famille de chemins d'accès — commencez par le [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Cette page présente les options courantes pouvant être déployées.

## Ce que chaque observateur peut généralement voir

| Chemin | Réseau local / ISP | Intermédiaire | Destination | Limitation principale | Vitesse relative |
|---|---|---|---|---|---|
| HTTPS direct | Métadonnées de la source, de la destination, timing/volume | L'hébergeur/CDN voit la connexion | Adresse IP source, données du navigateur/de l'application | Aucune confidentialité de l'adresse IP source | La plus rapide |
| VPN commercial | Source connectée au VPN ; pas les métadonnées habituelles de la destination | Le VPN voit les métadonnées de la source et de la destination | Adresse IP de sortie du VPN | Un fournisseur devient un point de corrélation | Généralement rapide |
| VPN/VPS auto-hébergé | Source connectée au VPS | Journaux de l'hôte, du compte, du paiement et du control plane | Adresse IP de sortie du VPS | Facile à attribuer au serveur/compte loué | Généralement rapide |
| Tor Browser | Source connectée à Tor/bridge ; timing/volume | Chaque relay ne voit qu'une partie limitée | Exit Tor, données du navigateur | Plus lent ; risques liés au compte, à l'endpoint et à la corrélation | Moyenne/lente |
| Tails/Whonix | Chemin Tor similaire, avec des limites de routage plus strictes | Mêmes limitations que Tor | Exit Tor/données de l'application | Les erreurs opérationnelles ainsi que l'hôte/le matériel restent des facteurs | Moyenne/lente |
| Wi-Fi public invité + HTTPS | Le lieu voit l'appareil local/le timing et les destinations | L'ISP du lieu voit les métadonnées | Adresse IP publique de l'invité | Corrélation physique, avec le captive portal et l'appareil | Rapide/variable |
| Hotspot cellulaire | L'opérateur voit l'abonné, l'appareil, la localisation et les destinations | VPN/Tor s'ils sont utilisés | Adresse IP de sortie de l'opérateur, du VPN ou de Tor | L'abonnement mobile et la localisation sont des identifiants durables | Rapide/variable |
| Mixnet | L'accès voit l'utilisation du mixnet ; timing/volume | Plusieurs nœuds de mixage | Gateway/egress | Écosystème émergent ; coût en latence et en bande passante | La plus lente |

HTTPS protège le contenu en transit, mais pas toutes les métadonnées. EFF indique que le domaine, l'heure et la taille du trafic peuvent rester visibles pour les intermédiaires, même lorsque les chemins des pages, les identifiants et les messages sont chiffrés.<sup>[[1]](#references)</sup>

## VPN : confidentialité rapide avec une confiance concentrée

Un VPN est utile pour dissimuler les métadonnées de destination à l'ISP d'accès, protéger un premier hop sur un réseau non fiable, présenter une adresse egress stable pour un engagement ou accéder à un réseau privé. Il ne rend **pas** un utilisateur anonyme. Le VPN voit la connexion source et peut observer les métadonnées de destination ; les comptes, cookies, données GPS, fingerprints et informations de paiement restent visibles.<sup>[[1]](#references)</sup>

### Checklist d'évaluation d'un fournisseur

1. **Propriété et juridiction :** identifiez l'entité juridique, la société mère, les pays d'exploitation, les sous-traitants d'infrastructure et les procédures légales applicables.
2. **Données collectées :** distinguez les données de compte/facturation, l'adresse IP source, les horodatages de connexion, la bande passante, la télémétrie des crashs, les requêtes DNS et les logs de destination. « Aucun browsing log » ne signifie pas « aucune donnée ».
3. **Conservation et suppression :** recherchez les durées précises et vérifiez si les backups, les systèmes anti-fraude et les processeurs suivent le même calendrier.
4. **Preuves :** privilégiez les audits publics indiquant leur périmètre, leur date, leurs conclusions et les mesures correctives ; les clients reproductibles/open source ; les rapports de transparence ; et les incidents documentés.
5. **Protocole et client :** WireGuard, OpenVPN ou un autre protocole maintenu et audité ; mises à jour automatiques ; gestion du DNS et d'IPv6 ; kill switch ; et tests de leak pour chaque plateforme.
6. **Modèle économique :** comprenez comment un service gratuit ou subventionné est financé. La présence dans un app store ne constitue pas à elle seule une preuve de fonctionnement fiable.
7. **Adéquation du paiement :** un moyen de paiement alternatif peut réduire les informations de facturation divulguées au VPN, mais n'efface pas l'adresse IP source observée à chaque connexion.

### Configurer et vérifier un VPN

1. Installez le client signé du fournisseur/de l'organisation depuis sa source officielle.
2. Sélectionnez le **full tunnel**, sauf si une route documentée doit le contourner. Le split tunneling crée des chemins de corrélation et de leak.
3. Activez le comportement fail-closed/always-on et bloquez le trafic pendant la reconnexion.
4. Faites passer le DNS par le tunnel et testez IPv4 et IPv6. Désactivez un protocole uniquement s'il ne peut pas être tunnellisé de manière sûre et si la perte de fonctionnalité est acceptée.
5. Testez la mise en veille/réactivation, le changement de réseau, la connexion au captive portal, le crash du tunnel et le tethering via hotspot. Le NCSC avertit que les clients tethered peuvent contourner le VPN d'un téléphone sur certaines plateformes.<sup>[[2]](#references)</sup>
6. Utilisez un endpoint de test contrôlé par l'organisation pour enregistrer les valeurs IPv4, IPv6, le resolver DNS et le timing de connexion observés. N'exposez pas un engagement sensible à des sites de « leak test » aléatoires.
7. Effectuez un nouveau test après toute modification du client, de l'OS, du réseau ou de la policy.

### Contournements du routage sur un LAN hostile

Un VPN peut rester visiblement « connecté » alors que certains paquets le contournent, car le système d'exploitation choisit une route **avant** que le VPN ne chiffre le paquet. TunnelCrack a démontré deux façons d'exploiter les exceptions de routage courantes : **LocalNet** fait apparaître une destination Internet comme située sur le subnet directement connecté, tandis que **ServerIP** usurpe la résolution de la gateway VPN afin qu'une adresse cible hérite de l'exception clear-network nécessaire au transport VPN. Il s'agit de défaillances du client/routage, et non de cassures de WireGuard, OpenVPN, IPsec ou TLS ; les payloads HTTPS restent chiffrés de bout en bout, mais l'observateur local peut récupérer les métadonnées de destination/timing ainsi que toute donnée de protocole en clair.<sup>[[18]](#references)</sup>

TunnelVision applique la même primitive pré-chiffrement via l'option DHCP 121. Un serveur DHCP malveillant ou compromis peut installer une route classless plus spécifique que la route catch-all du VPN, en sélectionnant l'interface physique pour un hôte ou une plage arbitraire. Le control channel du VPN peut rester actif ; un kill switch déclenché uniquement par la déconnexion du tunnel peut donc ne pas s'activer, et une simple vérification publique de « fuite d'IP » peut manquer les contournements sélectifs.<sup>[[19]](#references)</sup>

Un packet-filter kill switch qui n'autorise que DHCP et le transport VPN authentifié sur l'interface physique devrait transformer ce comportement en fail-closed, mais une injection de routes ciblée peut encore créer un side channel de déni sélectif. Pour les workloads Linux à conséquences élevées, préférez le [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), plus robuste, où le namespace de l'application ne possède ni interface physique ni route par défaut clear-network.<sup>[[19]](#references)</sup>

#### Vérification dans un lab contrôlé

Testez le client/OS/version exact sur un AP, un serveur DHCP, un endpoint VPN et une destination que vous contrôlez ; les affirmations générales sur un produit deviennent rapidement obsolètes, car les implémentations du routage et du packet-filter dépendent de la plateforme. Capturez également sur l'endpoint lui-même ainsi que sur le serveur de test : un site affichant l'egress IP ne prouve pas à lui seul que chaque destination suit le tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connectez le VPN, notez l'adresse du serveur VPN et sauvegardez toutes les tables de routage IPv4/IPv6 ainsi que les règles de policy-routing. Sous Windows, utilisez `route print` ; sous macOS, utilisez `netstat -rn` ; sous Linux, utilisez les commandes ci-dessous.
2. Interrogez la route sélectionnée pour plusieurs adresses IP de destination que vous contrôlez. Le next hop/interface doit être le tunnel, à l'exception de l'endpoint de transport VPN documenté.
3. Pour TunnelVision, renouvelez le lease sur le réseau DHCP contrôlé et installez une route option 121 **uniquement pour une destination de test que vous contrôlez**. Une réussite signifie que le trafic reste tunnellisé ou est bloqué — il ne doit jamais être émis comme trafic destiné à la destination sur l'interface physique.
4. Pour LocalNet, attribuez au client un subnet public de documentation réservé au lab, tel que `203.0.113.0/24`, et placez-y la destination de test contrôlée. Vérifiez que l'activation de l'accès LAN ne permet pas aux destinations de type Internet de contourner le tunnel.
5. Pour ServerIP, avant la connexion VPN, faites en sorte que le DNS contrôlé résolve le hostname VPN contrôlé vers la destination de test contrôlée, tandis que la gateway du lab redirige le transport VPN vers le véritable endpoint VPN contrôlé. Le client ne doit pas exempter le trafic d'application non lié vers l'adresse usurpée.
6. Répétez avec « local network access » activé et désactivé, après une reconnexion, une mise en veille/réactivation, un changement de réseau et un crash du processus VPN. Testez IPv4, IPv6 et DNS indépendamment.
7. Inspectez la capture de l'interface physique. Elle doit contenir DHCP et des paquets chiffrés à destination du serveur VPN, mais aucun paquet adressé directement à la destination de test contrôlée. Vérifiez également qu'un contournement refusé ne peut pas basculer silencieusement après des prompts utilisateur ou une réparation de la connectivité.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser : une meilleure dissociabilité sur le Web

Tor construit un circuit à travers plusieurs relais afin qu'aucun relais ne connaisse normalement à la fois la source et la destination. La destination voit un nœud de sortie Tor plutôt que l'adresse IP de l'utilisateur ; le réseau local voit normalement une connexion Tor.<sup>[[3]](#references)</sup> Tor est conçu pour les applications TCP à faible latence ; il est donc plus lent et ne peut pas garantir une protection contre un adversaire capable de corréler les deux extrémités.<sup>[[4]](#references)</sup>

### Workflow Tor Browser sécurisé

1. Téléchargez Tor Browser uniquement depuis le Tor Project ou un miroir officiel et vérifiez la signature lorsque c'est possible.
2. Utilisez **Tor Browser**, et non un navigateur normal pointé vers un port SOCKS Tor. Les navigateurs classiques peuvent provoquer des leaks DNS/WebRTC et exposer un état identifiant.<sup>[[5]](#references)</sup>
3. Conservez la taille, les polices, les extensions et les paramètres de confidentialité par défaut. Des modules complémentaires supplémentaires peuvent rendre le navigateur plus unique.<sup>[[6]](#references)</sup>
4. Choisissez le niveau de sécurité **Safer** ou **Safest** lorsque le niveau accru de dysfonctionnement est acceptable.
5. Utilisez un bridge lorsque Tor direct est bloqué ou lorsque les adresses IP de relais ordinaires créeraient une visibilité locale inacceptable. Les bridges réduisent la reconnaissance facile ; ils n'éliminent pas l'analyse du trafic.<sup>[[7]](#references)</sup>
6. Ne vous connectez pas à un compte identifiant, ne fournissez pas d'informations identifiantes et n'ouvrez pas de documents actifs téléchargés dans une application externe connectée au réseau.
7. Utilisez une session/un contexte distinct pour chaque identité. « New circuit » ne revient pas à effacer l'identité du navigateur/de l'application ; utilisez **New Identity** ou redémarrez l'environnement isolé selon le cas.
8. Préférez HTTPS authentifié ou un service onion authentifié. Un nœud de sortie Tor peut observer le trafic HTTP non chiffré.

### Tor et VPN

Les combiner n'est pas automatiquement plus sûr. Un VPN avant Tor peut masquer les connexions directes aux relais Tor auprès d'un FAI, tandis que le VPN voit la source ; Tor avant un VPN donne au VPN une vue stable de l'activité post-Tor et peut réduire l'ensemble d'anonymat. Une mauvaise configuration peut introduire des leaks. Le Tor Project recommande ces combinaisons uniquement pour des threat models avancés et explicites.<sup>[[8]](#references)</sup>

## Wi-Fi public et invité

HTTPS moderne signifie que les voisins passifs ne peuvent généralement pas lire le contenu Web correctement chiffré, mais un Wi-Fi invité ne fournit pas l'anonymat. Le lieu peut enregistrer les heures d'association, les identifiants des appareils, les données du portail captif, les destinations et les détails DHCP ; les caméras, les achats, les transports et l'observation physique peuvent identifier l'utilisateur. Un faux hotspot portant un nom similaire peut également capturer les identifiants du portail ou manipuler le trafic non chiffré.<sup>[[9]](#references)</sup>

### Workflow légal sur un réseau invité

1. Utilisez uniquement un réseau proposé aux invités ou pour lequel le propriétaire a accordé une autorisation explicite. Demandez au personnel le SSID exact et la procédure du portail.
2. Mettez à jour le endpoint et le travel router avant votre arrivée. Désactivez le partage de fichiers/imprimantes, la découverte entrante, la connexion automatique et la détection des réseaux mémorisés.
3. Activez l'adresse Wi-Fi privée/aléatoire du système d'exploitation. Les systèmes Apple actuels peuvent utiliser des adresses rotatives sur les réseaux ouverts/faibles ; la randomisation moderne d'Android est généralement persistante par SSID. Cela ne réduit qu'un seul identifiant local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Préférez un travel router contrôlé par l'organisation ou un bridge device à faible niveau de confiance entre un poste de travail privilégié et le réseau invité. Cela centralise la politique firewall/VPN, mais ne masque pas le router au lieu.<sup>[[12]](#references)</sup>
5. Complétez un portail captif uniquement via le device/browser désigné à faible niveau de confiance. N'entrez jamais d'identifiants personnels ou réutilisés dans un contexte supposé anonyme. Fermez le navigateur du portail après l'établissement de la connectivité.
6. Démarrez un VPN full-tunnel ou Tor avant toute activité sensible et confirmez le comportement fail-closed.
7. Oubliez le réseau après utilisation et examinez la politique du compte du portail et de conservation des données.

{% hint style="danger" %}
Cracker le Wi-Fi d'un voisin, contourner un portail, utiliser des identifiants invités leakés, cloner l'accès d'un autre invité ou dissimuler un Raspberry Pi dans un café sont des activités non autorisées, et non une technique de confidentialité. Les équivalents sûrs sont un réseau invité légal, un site approuvé par le client ou un drop node documenté, installé et récupéré avec le consentement écrit du propriétaire.
{% endhint %}

## Travel routers

Un travel router peut isoler un poste de travail des broadcasts locaux hostiles, appliquer un firewall, fournir un SSID interne cohérent et reconnecter automatiquement un VPN. Il n'est **pas** anonyme : le réseau amont voit son identité radio et le timing du trafic, tandis que son fournisseur VPN voit la source du tunnel.

- Utilisez un firmware OpenWrt/vendor pris en charge et supprimez les services inutilisés.
- Administrez-le via Ethernet ou un SSID de gestion dédié avec un mot de passe unique.
- Désactivez l'administration côté WAN, UPnP, WPS, le partage de fichiers et le trafic entrant non sollicité.
- Utilisez une MAC WAN randomisée/privée uniquement lorsque cela est pris en charge et autorisé.
- Appliquez la politique VPN sur le router, notamment pour DNS et IPv6, et bloquez les sorties lorsque le tunnel échoue.
- Ne supposez pas qu'un hotspot de téléphone fait passer les devices tethered dans le VPN du téléphone ; testez-le.

## Réseaux cellulaires, SIM et eSIM

Les réseaux cellulaires sont pratiques, mais pas anonymes. Les opérateurs conservent les identifiants des abonnés/des appareils ainsi que la localisation déduite de l'attachement au réseau ; une eSIM reste un abonnement mobile. Le prépayé ne signifie pas systématiquement non enregistré : les exigences varient selon les pays et évoluent.<sup>[[13]](#references)</sup>

Sur le plan opérationnel :

- Utilisez un device distinct et pris en charge pour réduire l'exposition des données personnelles, et non pour créer un abonné fictif.
- Ne transportez pas continuellement un device « distinct » à côté d'un téléphone personnel si la co-localisation fait partie du threat model.
- Désactivez les accès cellulaires, Wi-Fi, Bluetooth et de localisation inutilisés ; éteindre l'appareil constitue une boundary radio plus forte que les boutons de l'interface.
- Faites passer le trafic sensible dans le chemin VPN/Tor approuvé, tout en reconnaissant que l'opérateur connaît toujours la localisation de l'abonnement/du device et le endpoint du tunnel.
- Vérifiez les règles actuelles d'enregistrement et de conservation auprès du régulateur national ou d'un conseil juridique local ; ne vous fiez pas aux listes en ligne de « pays disposant de SIM anonymes ».

## Métadonnées DNS et TLS

- **DoH/DoT/DoQ** chiffrent le DNS entre le client et le resolver, empêchant la lecture ou la modification locale simple, mais le resolver voit toujours les requêtes et les identifiants de transport. Ils déplacent la confiance ; ils ne fournissent pas l'anonymat.<sup>[[14]](#references)</sup>
- **ODoH** ajoute un proxy afin que le resolver n'ait pas besoin de connaître l'IP du client, en supposant que le proxy et la cible ne colludent pas. L'analyse du trafic est explicitement hors périmètre.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** peut protéger le nom interne du serveur dans une négociation TLS lorsque le client, le DNS et le serveur le prennent en charge. L'IP de destination, le timing, le volume et le endpoint restent visibles.<sup>[[16]](#references)</sup>
- Avec un environnement VPN ou Tor correctement configuré, le DNS devrait suivre le chemin pris en charge par cet environnement. Ajouter un resolver distinct peut créer un nouvel observateur ou une nouvelle empreinte.

### Workflow de vérification du DNS chiffré/ECH

1. Déterminez si le DNS est contrôlé par l'environnement VPN/Tor, le système d'exploitation ou l'application. Configurez-le dans **une seule** couche prévue à cet effet au lieu d'empiler des resolvers indépendants.
2. Sélectionnez un resolver à partir de sa politique publiée de confidentialité/conservation et activez le mode chiffré strict lorsque la plateforme le prend en charge. Le fallback opportuniste peut revenir silencieusement au texte clair.
3. Interrogez un sous-domaine unique sous une zone de test faisant autorité que vous contrôlez ; vérifiez que le journal faisant autorité voit le resolver récursif prévu.
4. Capturez uniquement le trafic du device de test avec autorisation. Vérifiez que le réseau d'accès ne peut pas lire le DNS en texte clair, tout en reconnaissant qu'il peut voir le endpoint du resolver/tunnel chiffré.
5. Testez un resolver chiffré bloqué/injoignable. La condition de réussite est le comportement fail-closed choisi ou le fallback documenté, et non une requête en clair accidentelle.
6. Pour ECH, utilisez un hôte contrôlé compatible ECH et inspectez les diagnostics client/serveur afin de confirmer que le **inner** ClientHello a été accepté. La simple présence d'un enregistrement HTTPS ne prouve pas que ECH a réussi.
7. Répétez après les changements de réseau, les portails captifs, les mises à jour du navigateur et les reconnexions VPN. Notez quel composant contrôle le DNS/ECH afin que les administrateurs ultérieurs ne créent pas de bypass.

## Mixnets

Les mixnets tels que Nym ou Katzenpost ajoutent des paquets de taille fixe, des délais, du réordonnancement et du cover traffic pour résister à la corrélation temporelle. Ces propriétés coûtent en latence et en bande passante, et les preuves indépendantes à l'échelle du déploiement sont limitées. Considérez les mixnets grand public actuels comme des **options émergentes/à forte latence**, et non comme des remplacements plus rapides ou garantis de Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow d'évaluation

1. Identifiez un client maintenu et l'application exacte prise en charge ; ne forcez pas arbitrairement le trafic du navigateur/système à passer par un proxy non documenté.
2. Lisez le threat model actuel concernant les hypothèses relatives à l'entrée, aux mix nodes, au gateway, à la destination et à la collusion.
3. Installez depuis la source officielle signée dans un compartiment de test séparé et utilisez uniquement un endpoint vous appartenant et sans danger.
4. Mesurez la latence de livraison, les limites de taille des messages, la fiabilité, les retransmissions et le comportement lorsque le gateway est indisponible.
5. Inspectez le trafic local et l'endpoint contrôlé pour confirmer le chemin et la source prévus. Vérifiez si les réponses utilisent le même modèle de confidentialité.
6. Testez l'arrêt/la panne : l'application ne doit pas revenir silencieusement à un accès Internet direct.
7. Ne désactivez pas le cover traffic, ne réduisez pas les délais et ne choisissez pas de routes fixes inhabituelles uniquement pour gagner en vitesse ; ces changements peuvent invalider le modèle d'anonymat déclaré.
8. Maintenez cette solution au stade expérimental jusqu'à ce que le déploiement spécifique, l'analyse indépendante et la fiabilité opérationnelle correspondent au niveau de conséquences.

## Checklist de pré-vol réseau

- [ ] L'autorisation couvre le réseau d'accès, la cible, les dates et l'infrastructure source.
- [ ] Le endpoint ne contient aucune identité indépendante ni session de synchronisation active.
- [ ] Le comportement IPv4, IPv6, DNS et de reconnexion correspond au plan.
- [ ] L'injection contrôlée de routes DHCP/sous-réseau local ne peut pas déplacer le trafic de test vers l'interface physique.
- [ ] La destination ne voit que la sortie prévue.
- [ ] Le comportement du portail captif et du hotspot a été testé sans trafic sensible.
- [ ] Le partage/la découverte locale et la connexion automatique aux réseaux sont désactivés.
- [ ] Le tableau des observateurs et le risque résiduel de corrélation du trafic sont acceptés.
- [ ] La politique du fournisseur, la conservation des données et le contact d'urgence sont à jour.

Pour les relais à connaissances réparties, les workloads dont les routes sont imposées, les transports pluggables, les services onion, I2P et les navigateurs distants jetables, consultez [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Choisir le VPN qui vous convient](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Guide de sécurité des appareils : réseaux privés virtuels](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Protections de confidentialité et d'anonymat offertes par Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Une brève introduction à Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Utiliser Tor avec d'autres navigateurs](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins et modules complémentaires dans Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Débloquer Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Utiliser Tor Browser avec un VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Les réseaux Wi-Fi publics sont-ils sûrs ?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Confidentialité Wi-Fi avec les appareils Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implémenter la randomisation MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principes pour les postes de travail sécurisés à accès privilégié](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Enregistrement obligatoire des SIM : perspectives politiques et réglementaires](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommandations pour les opérateurs de services DNS respectueux de la confidentialité](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS oblivious sur HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Contourner les tunnels : fuite du trafic client VPN par abus des tables de routage](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision : comment les attaquants peuvent décloaker les VPN fondés sur le routage pour provoquer un VPN Leak total](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
