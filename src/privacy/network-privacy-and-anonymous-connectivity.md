# Confidentialité réseau et connectivité anonyme

La confidentialité réseau est une décision de routage, pas une identité complète. Sélectionnez un chemin en vous demandant qui doit être incapable de relier la **source**, la **destination**, le **contenu** et le **moment**.

Pour l'inventaire normalisé — `Pros`, `Cons`, `Procedure` étape par étape et `Detection` pour chaque famille de chemins d'accès — commencez par le [Catalogue des techniques d'accès Internet anonyme](anonymous-internet-access-techniques.md). Cette page développe les options couramment déployables.

## Ce que chaque observateur peut généralement voir

| Chemin | Réseau local / FAI | Intermédiaire | Destination | Limitation principale | Vitesse relative |
|---|---|---|---|---|---|
| HTTPS direct | Métadonnées de source, de destination, timing/volume | L'hébergeur/CDN voit la connexion | Adresse IP source, données du navigateur/de l'application | Aucune confidentialité de l'adresse IP source | La plus rapide |
| VPN commercial | Source connectée au VPN ; pas les métadonnées habituelles de destination | Le VPN voit les métadonnées de source et de destination | Adresse IP de sortie du VPN | Un fournisseur devient un point de corrélation | Généralement rapide |
| VPN/VPS auto-hébergé | Source connectée au VPS | Journaux de l'hôte, du compte, du paiement et du plan de contrôle | Adresse IP de sortie du VPS | Facile à attribuer au serveur/compte loué | Généralement rapide |
| Tor Browser | Source connectée à Tor/bridge ; timing/volume | Chaque relais ne voit qu'une portion limitée | Sortie Tor, données du navigateur | Plus lent ; risques liés aux comptes, aux endpoints et à la corrélation | Modérée/lente |
| Tails/Whonix | Chemin Tor similaire, avec des limites de routage plus strictes | Mêmes limitations que Tor | Sortie Tor/données de l'application | Les erreurs opérationnelles et l'hôte/le matériel restent pertinents | Modérée/lente |
| Wi-Fi public invité + HTTPS | Le lieu voit l'appareil local/le timing et les destinations | Le FAI du lieu voit les métadonnées | Adresse IP publique du réseau invité | Corrélation physique/portail captif/appareil | Rapide/variable |
| Hotspot cellulaire | L'opérateur voit l'abonné/l'appareil/la localisation et les destinations | VPN/Tor, le cas échéant | Adresse IP de sortie de l'opérateur, du VPN ou de Tor | L'abonnement mobile et la localisation sont des identifiants durables | Rapide/variable |
| Mixnet | Le réseau d'accès voit l'utilisation du mixnet ; timing/volume | Plusieurs nœuds de mélange | Gateway/sortie | Écosystème émergent ; coût en latence et en bande passante | La plus lente |

HTTPS protège le contenu en transit, mais pas toutes les métadonnées. L'EFF indique que le domaine, l'heure et la taille du trafic peuvent rester visibles pour les intermédiaires, même lorsque les chemins de page, les identifiants et les messages sont chiffrés.<sup>[[1]](#references)</sup>

## VPN : confidentialité rapide et confiance concentrée

Un VPN est utile pour masquer les métadonnées de destination au FAI d'accès, protéger un premier saut sur un réseau non fiable, présenter une adresse de sortie stable pour un engagement ou accéder à un réseau privé. Il ne rend **pas** l'utilisateur anonyme. Le VPN voit la connexion source et peut observer les métadonnées de destination ; les comptes, cookies, données GPS, empreintes et informations de paiement restent visibles.<sup>[[1]](#references)</sup>

### Liste de contrôle pour évaluer un fournisseur

1. **Propriété et juridiction :** identifiez l'entité juridique, la société mère, les pays d'exploitation, les sous-traitants d'infrastructure et les procédures légales applicables.
2. **Données collectées :** distinguez les données de compte/facturation, l'adresse IP source, les horodatages de connexion, la bande passante, la télémétrie des plantages, les requêtes DNS et les journaux de destination. « Aucun journal de navigation » ne signifie pas « aucune donnée ».
3. **Conservation et suppression :** recherchez les durées précises et vérifiez si les sauvegardes, les systèmes antifraude et les sous-traitants suivent le même calendrier.
4. **Éléments probants :** privilégiez les audits publics indiquant leur périmètre, leur date, leurs conclusions et les mesures correctives ; les clients reproductibles/open source ; les rapports de transparence ; ainsi que les incidents documentés.
5. **Protocole et client :** WireGuard, OpenVPN ou un autre protocole maintenu et examiné ; mises à jour automatiques ; gestion du DNS et de l'IPv6 ; kill switch ; tests de leak pour chaque plateforme.
6. **Modèle économique :** comprenez comment un service gratuit ou subventionné est financé. La seule présence dans un app store ne prouve pas la fiabilité de l'exploitation.
7. **Adéquation du paiement :** un moyen de paiement alternatif peut réduire la divulgation des informations de facturation au VPN, mais n'efface pas l'adresse IP source observée à chaque connexion.

### Configurer et vérifier un VPN

1. Installez le client signé du fournisseur/de l'organisation depuis sa source officielle.
2. Sélectionnez le **full tunnel**, sauf si une route documentée doit le contourner. Le split tunneling crée des chemins de corrélation et de leak.
3. Activez le comportement fail-closed/always-on et bloquez le trafic pendant la reconnexion.
4. Faites passer le DNS par le tunnel et testez IPv4 et IPv6. Désactivez un protocole uniquement s'il ne peut pas être tunnellisé correctement et si la perte de fonctionnalité est acceptée.
5. Testez la sortie de veille, le réveil, le changement de réseau, la connexion au portail captif, le crash du tunnel et le tethering par hotspot. Le NCSC avertit que les clients connectés en tethering peuvent contourner le VPN d'un téléphone sur certaines plateformes.<sup>[[2]](#references)</sup>
6. Utilisez un endpoint de test contrôlé par l'organisation pour enregistrer l'IPv4, l'IPv6, le résolveur DNS et le timing de connexion observés. N'exposez pas un engagement sensible à des sites aléatoires de « test de leak ».
7. Recommencez les tests après toute modification du client, du système d'exploitation, du réseau ou de la politique.

## Tor Browser : unlinkability Web renforcée

Tor construit un circuit à travers plusieurs relais afin qu'aucun relais ne connaisse normalement à la fois la source et la destination. La destination voit une sortie Tor plutôt que l'adresse IP de l'utilisateur ; le réseau local voit normalement une connexion Tor.<sup>[[3]](#references)</sup> Tor est conçu pour les applications TCP à faible latence ; il est donc plus lent et ne peut pas garantir une protection contre un adversaire capable de corréler les deux extrémités.<sup>[[4]](#references)</sup>

### Procédure sûre avec Tor Browser

1. Téléchargez Tor Browser uniquement depuis le Tor Project ou un miroir officiel et vérifiez la signature lorsque cela est possible.
2. Utilisez **Tor Browser**, et non un navigateur normal dirigé vers un port SOCKS Tor. Les navigateurs ordinaires peuvent provoquer des leaks DNS/WebRTC et exposer un état identifiant.<sup>[[5]](#references)</sup>
3. Conservez la taille, les polices, les extensions et les paramètres de confidentialité par défaut. Des modules complémentaires peuvent rendre le navigateur plus unique.<sup>[[6]](#references)</sup>
4. Choisissez le niveau de sécurité **Safer** ou **Safest** lorsque la dégradation fonctionnelle supplémentaire est acceptable.
5. Utilisez un bridge lorsque Tor direct est bloqué ou lorsque les adresses IP de relais ordinaires créeraient une visibilité locale inacceptable. Les bridges réduisent la reconnaissance facile ; ils n'éliminent pas l'analyse du trafic.<sup>[[7]](#references)</sup>
6. Ne vous connectez pas à un compte identifiant, ne fournissez pas d'informations identifiantes et n'ouvrez pas de documents actifs téléchargés dans une application externe connectée au réseau.
7. Utilisez une session/un contexte distinct pour chaque identité. « New circuit » n'est pas équivalent à l'effacement de l'identité du navigateur/de l'application ; utilisez **New Identity** ou redémarrez l'environnement isolé selon le cas.
8. Préférez HTTPS authentifié ou un onion service authentifié. Une sortie Tor peut observer le trafic HTTP non chiffré.

### Tor et VPN

Les combiner n'est pas automatiquement plus sûr. Un VPN avant Tor peut masquer les connexions directes aux relais Tor auprès d'un FAI, tandis que le VPN voit la source ; Tor avant un VPN donne au VPN une vue stable de l'activité post-Tor et peut réduire l'ensemble d'anonymat. Une mauvaise configuration peut introduire des leaks. Le Tor Project recommande ces combinaisons uniquement pour des modèles de menace avancés et explicites.<sup>[[8]](#references)</sup>

## Wi-Fi public et invité

Le HTTPS moderne signifie que les voisins passifs ne peuvent généralement pas lire le contenu Web correctement chiffré, mais un Wi-Fi invité n'est pas l'anonymat. Le lieu peut enregistrer les heures d'association, les identifiants de l'appareil, les données du portail captif, les destinations et les détails DHCP ; les caméras, les achats, les transports et l'observation physique peuvent identifier l'utilisateur. Un faux hotspot au nom similaire peut également capturer les identifiants du portail ou manipuler le trafic non chiffré.<sup>[[9]](#references)</sup>

### Procédure légale sur un réseau invité

1. Utilisez uniquement un réseau proposé aux invités ou pour lequel le propriétaire a accordé une autorisation explicite. Demandez au personnel le SSID exact et la procédure du portail.
2. Mettez à jour l'endpoint et le routeur de voyage avant l'arrivée. Désactivez le partage de fichiers/imprimantes, la découverte entrante, la connexion automatique et la recherche de réseaux mémorisés.
3. Activez l'adresse Wi-Fi privée/aléatoire du système d'exploitation. Les systèmes Apple actuels peuvent utiliser des adresses tournantes sur les réseaux ouverts/faibles ; la randomisation moderne d'Android est généralement persistante par SSID. Cela ne réduit qu'un seul identifiant local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Préférez un routeur de voyage contrôlé par l'organisation ou un appareil bridge à faible confiance entre une station de travail privilégiée et le réseau invité. Cela centralise la politique de pare-feu/VPN, mais ne masque pas le routeur au lieu.<sup>[[12]](#references)</sup>
5. Effectuez la procédure du portail captif uniquement avec l'appareil/le navigateur à faible confiance désigné. N'entrez jamais d'identifiants personnels ou réutilisés dans un contexte supposé anonyme. Fermez le navigateur du portail une fois la connectivité établie.
6. Démarrez un VPN full-tunnel ou Tor avant toute activité sensible et confirmez le comportement fail-closed.
7. Oubliez le réseau après utilisation et examinez la politique du compte du portail et de conservation des données.

{% hint style="danger" %}
Craquer le Wi-Fi d'un voisin, contourner un portail, utiliser des identifiants invités leakés, cloner l'accès d'un autre invité ou dissimuler un Raspberry Pi dans un café sont des activités non autorisées, et non une technique de confidentialité. Les équivalents sûrs sont un réseau invité légal, un site approuvé par le client ou un nœud de dépôt documenté, placé et récupéré avec l'autorisation écrite du propriétaire.
{% endhint %}

## Routeurs de voyage

Un routeur de voyage peut isoler une station de travail des broadcasts locaux hostiles, appliquer un pare-feu, fournir un SSID interne cohérent et reconnecter automatiquement un VPN. Il n'est **pas** anonyme : le réseau amont voit son identité radio et le timing du trafic, tandis que son fournisseur VPN voit la source du tunnel.

- Utilisez un firmware OpenWrt/fournisseur pris en charge et supprimez les services inutilisés.
- Administrez-le via Ethernet ou un SSID de gestion dédié avec un mot de passe unique.
- Désactivez l'administration côté WAN, UPnP, WPS, le partage de fichiers et le trafic entrant non sollicité.
- Utilisez une adresse MAC WAN aléatoire/privée uniquement lorsque cela est pris en charge et autorisé.
- Appliquez la politique VPN sur le routeur, y compris le DNS et l'IPv6, et bloquez la sortie lorsque le tunnel échoue.
- Ne supposez pas qu'un hotspot téléphonique fait passer les appareils connectés en tethering par le VPN du téléphone ; testez-le.

## Réseaux cellulaires, SIM et eSIM

Le réseau cellulaire est pratique, mais pas anonyme. Les opérateurs conservent les identifiants de l'abonné et de l'appareil ainsi que la localisation dérivée de l'attachement au réseau ; une eSIM reste un abonnement mobile. Le prépayé ne signifie pas systématiquement non enregistré : les exigences varient selon les pays et évoluent.<sup>[[13]](#references)</sup>

Sur le plan opérationnel :

- Utilisez un appareil séparé et pris en charge pour réduire l'exposition des données personnelles, et non pour créer un abonné fictif.
- Ne transportez pas en permanence un appareil « séparé » aux côtés d'un téléphone personnel si la colocalisation fait partie du modèle de menace.
- Désactivez les fonctions cellulaires, Wi-Fi, Bluetooth et l'accès à la localisation inutilisés ; l'extinction constitue une limite radio plus forte que les simples boutons de l'interface.
- Faites passer le trafic sensible par le chemin VPN/Tor approuvé, tout en reconnaissant que l'opérateur connaît toujours la localisation de l'abonnement/de l'appareil et l'endpoint du tunnel.
- Vérifiez les règles actuelles d'enregistrement et de conservation auprès du régulateur national ou d'un conseil juridique local ; ne vous fiez pas aux listes en ligne de « pays avec des SIM anonymes ».

## Métadonnées DNS et TLS

- **DoH/DoT/DoQ** chiffrent le DNS entre le client et le résolveur, empêchant la lecture ou la modification locale simple, mais le résolveur voit toujours les requêtes et les identifiants de transport. Ils déplacent la confiance ; ils ne fournissent pas l'anonymat.<sup>[[14]](#references)</sup>
- **ODoH** ajoute un proxy afin que le résolveur n'ait pas besoin de connaître l'adresse IP du client, en supposant que le proxy et la cible ne colludent pas. L'analyse du trafic est explicitement hors périmètre.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** peut protéger le nom de serveur interne dans une poignée de main TLS lorsque le client, le DNS et le serveur le prennent en charge. L'adresse IP de destination, le timing, le volume et l'endpoint restent visibles.<sup>[[16]](#references)</sup>
- Dans un environnement VPN ou Tor correctement configuré, le DNS doit suivre le chemin pris en charge par cet environnement. Ajouter un résolveur distinct peut créer un nouvel observateur ou une nouvelle empreinte.

### Procédure de vérification du DNS chiffré/ECH

1. Déterminez si le DNS est contrôlé par l'environnement VPN/Tor, le système d'exploitation ou l'application. Configurez-le dans **une seule** couche prévue à cet effet au lieu d'empiler des résolveurs sans lien.
2. Sélectionnez un résolveur selon sa politique publiée de confidentialité/conservation et activez le mode chiffré strict lorsque la plateforme le prend en charge. Le fallback opportuniste peut revenir silencieusement au texte en clair.
3. Interrogez un sous-domaine unique sous une zone de test faisant autorité que vous contrôlez ; confirmez que le journal faisant autorité voit le résolveur récursif prévu.
4. Capturez uniquement le trafic de l'appareil de test avec autorisation. Confirmez que le réseau d'accès ne peut pas lire le DNS en clair, tout en reconnaissant qu'il peut voir l'endpoint du résolveur/tunnel chiffré.
5. Testez un résolveur chiffré bloqué/injoignable. La condition de réussite est le comportement fail-closed choisi ou le fallback documenté, et non une requête en clair accidentelle.
6. Pour ECH, utilisez un hôte contrôlé compatible ECH et examinez les diagnostics client/serveur afin de confirmer que le **ClientHello** interne a été accepté. La simple publication d'un enregistrement HTTPS ne prouve pas que ECH a fonctionné.
7. Répétez les tests après les changements de réseau, les portails captifs, les mises à jour du navigateur et les reconnexions VPN. Notez quel composant gère le DNS/ECH afin que les administrateurs suivants ne créent pas de contournement.

## Mixnets

Les mixnets comme Nym ou Katzenpost ajoutent des paquets de taille fixe, des délais, du réordonnancement et du trafic de couverture pour résister à la corrélation temporelle. Ces propriétés coûtent en latence et en bande passante, et les preuves indépendantes à l'échelle du déploiement sont limitées. Considérez les mixnets grand public actuels comme des **options émergentes/à forte latence**, et non comme des remplacements plus rapides ou garantis de Tor/VPN.<sup>[[17]](#references)</sup>

### Procédure d'évaluation

1. Identifiez un client maintenu et l'application exacte prise en charge ; ne forcez pas arbitrairement le trafic du navigateur/système à travers un proxy non documenté.
2. Lisez le modèle de menace actuel concernant l'entrée, les nœuds de mélange, la gateway, la destination et les hypothèses de collusion.
3. Installez-le depuis la source officielle signée dans un compartiment de test séparé et utilisez uniquement un endpoint détenu et inoffensif.
4. Mesurez la latence de livraison, les limites de taille des messages, la fiabilité, les retransmissions et le comportement lorsque la gateway est indisponible.
5. Inspectez le trafic local et l'endpoint détenu afin de confirmer le chemin prévu et la source. Vérifiez si les réponses utilisent la même conception de confidentialité.
6. Testez l'arrêt et les défaillances : l'application ne doit pas revenir silencieusement à un accès Internet direct.
7. Ne désactivez pas le trafic de couverture, ne réduisez pas les délais et ne choisissez pas de routes fixes inhabituelles uniquement pour gagner en vitesse ; ces modifications peuvent invalider le modèle d'anonymat annoncé.
8. Maintenez cette solution au stade expérimental jusqu'à ce que le déploiement spécifique, l'analyse indépendante et la fiabilité opérationnelle correspondent au niveau de conséquences.

## Liste de contrôle préalable au réseau

- [ ] L'autorisation couvre le réseau d'accès, la cible, les dates et l'infrastructure source.
- [ ] L'endpoint ne contient aucune identité non liée ni session de synchronisation active.
- [ ] IPv4, IPv6, DNS et comportement de reconnexion correspondent au plan.
- [ ] La destination ne voit que la sortie prévue.
- [ ] Le comportement du portail captif et du hotspot a été testé sans trafic sensible.
- [ ] Le partage/la découverte locale et la connexion automatique aux réseaux sont désactivés.
- [ ] Le tableau des observateurs et le risque résiduel de corrélation du trafic sont acceptés.
- [ ] La politique du fournisseur, la conservation et le contact d'urgence sont à jour.

Pour les relais à connaissances réparties, les workloads dont le routage est imposé, les transports pluggables, les onion services, I2P et les navigateurs distants jetables, consultez [Architectures avancées de confidentialité réseau](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Choisir le VPN qui vous convient](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Guide de sécurité des appareils : réseaux privés virtuels](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Protections de confidentialité et d'anonymat offertes par Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Brève introduction à Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Utiliser Tor avec d'autres navigateurs](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins et modules complémentaires dans Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Débloquer Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Utiliser Tor Browser avec un VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Les réseaux Wi-Fi publics sont-ils sûrs ?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Confidentialité Wi-Fi avec les appareils Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implémenter la randomisation MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principes pour les stations de travail sécurisées à accès privilégié](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Enregistrement obligatoire des SIM : perspectives politiques et réglementaires](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommandations pour les opérateurs de services de confidentialité DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS oblivious sur HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Modèle de menace](https://katzenpost.network/docs/threat_model/)
