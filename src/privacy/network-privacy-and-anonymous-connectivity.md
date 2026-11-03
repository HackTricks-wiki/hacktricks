# Confidentialité réseau et connectivité anonyme

{{#include ../banners/hacktricks-training.md}}

La confidentialité réseau est une décision de routage, pas une identité complète. Choisissez un chemin en vous demandant qui ne doit pas pouvoir relier **la source**, **la destination**, **le contenu** et **le timing**.

Pour l’inventaire normalisé — `Pros`, `Cons`, `Procedure` étape par étape et `Detection` pour chaque famille de chemins d’accès — commencez par le [catalogue des techniques d’accès anonyme à Internet](anonymous-internet-access-techniques.md). Cette page développe les options courantes pouvant être déployées.

## Ce que chaque observateur peut généralement voir

| Chemin | Réseau local / FAI | Intermédiaire | Destination | Limitation principale | Vitesse relative |
|---|---|---|---|---|---|
| HTTPS direct | Source, métadonnées de destination, timing/volume | L’hébergeur/CDN voit la connexion | Adresse IP source, données du navigateur/de l’application | Pas de confidentialité de l’adresse IP source | La plus rapide |
| VPN commercial | Source connectée au VPN ; pas les métadonnées de destination habituelles | Le VPN voit la source et les métadonnées de destination | Adresse IP de sortie du VPN | Un fournisseur devient un point de corrélation | Généralement rapide |
| VPN/VPS auto-hébergé | Source connectée au VPS | Journaux de l’hébergeur/compte/paiement/plan de contrôle | Adresse IP de sortie du VPS | Facile à attribuer au serveur/compte loué | Généralement rapide |
| Tor Browser | Source connectée à Tor/au bridge ; timing/volume | Chaque relais ne voit qu’une partie limitée | Sortie Tor, données du navigateur | Plus lent ; risques liés aux comptes, aux terminaux et à la corrélation | Moyenne/lente |
| Tails/Whonix | Chemin Tor similaire, avec des limites de routage plus strictes | Mêmes limites de Tor | Sortie Tor/données de l’application | Les erreurs opérationnelles et l’hôte/le matériel restent des risques | Moyenne/lente |
| Wi-Fi public invité + HTTPS | L’établissement voit l’appareil local/le timing et les destinations | Le FAI de l’établissement voit les métadonnées | Adresse IP publique de l’invité | Corrélation physique/portail captif/appareil | Rapide/variable |
| Partage de connexion cellulaire | L’opérateur voit l’abonné/l’appareil/la localisation et les destinations | VPN/Tor, le cas échéant | Adresse IP de sortie de l’opérateur, du VPN ou de Tor | L’abonnement mobile et la localisation sont des identifiants durables | Rapide/variable |
| Mixnet | Le point d’accès voit l’utilisation du mixnet ; timing/volume | Plusieurs nœuds de mixage | Gateway/sortie | Écosystème émergent ; coût en latence et en bande passante | La plus lente |

HTTPS protège le contenu en transit, mais pas toutes les métadonnées. L’EFF indique que le domaine, l’heure et la taille du trafic peuvent rester visibles aux intermédiaires, même lorsque les chemins de page, les identifiants et les messages sont chiffrés.<sup>[[1]](#references)</sup>

Une surcouche chiffrée n’est pas automatiquement un réseau d’anonymat : les pairs directs Yggdrasil peuvent voir les adresses IP les uns des autres.<sup>[[20]](#references)</sup> Son [transfert en espace utilisateur et son transport SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) constituent une option de tunneling, pas une couche d’anonymisation de la source.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN : confidentialité rapide et confiance concentrée

Un VPN est utile pour cacher les métadonnées de destination au FAI d’accès, protéger le premier saut sur un réseau non fiable, présenter une adresse de sortie stable lors d’une intervention ou accéder à un réseau privé. Il ne rend **pas** un utilisateur anonyme. Le VPN voit la connexion source et peut observer les métadonnées de destination ; les comptes, cookies, données GPS, empreintes numériques et informations de paiement subsistent.<sup>[[1]](#references)</sup>

### Liste de vérification pour évaluer un fournisseur

1. **Propriété et juridiction :** identifiez l’entité juridique, la société mère, les pays d’exploitation, les sous-traitants d’infrastructure et les procédures légales applicables.
2. **Données collectées :** distinguez les données de compte/facturation, l’adresse IP source, les horodatages de connexion, la bande passante, la télémétrie des plantages, les requêtes DNS et les journaux de destination. « Aucun journal de navigation » ne signifie pas « aucune donnée ».
3. **Conservation et suppression :** recherchez les durées précises et vérifiez si les sauvegardes, les systèmes anti-fraude et les sous-traitants suivent le même calendrier.
4. **Éléments de preuve :** privilégiez les audits publics indiquant leur périmètre, leur date, leurs conclusions et les mesures correctives ; les clients reproductibles/open source ; les rapports de transparence ; et les incidents documentés.
5. **Protocole et client :** WireGuard, OpenVPN ou un autre protocole audité et maintenu ; mises à jour automatiques ; gestion du DNS et d’IPv6 ; kill switch ; et tests de leak sur chaque plateforme.
6. **Modèle économique :** comprenez comment un service gratuit ou subventionné est financé. La présence dans une boutique d’applications ne prouve pas à elle seule que le service fonctionne de manière fiable.
7. **Mode de paiement :** un moyen de paiement alternatif peut limiter les informations de facturation communiquées au VPN, mais n’efface pas l’adresse IP source observée à chaque connexion.

### Configurer et vérifier un VPN

1. Installez le client signé du fournisseur/de l’organisation depuis sa source officielle.
2. Choisissez le **tunnel complet**, sauf si une route documentée doit le contourner. Le split tunneling crée des risques de corrélation et de leak.
3. Activez le mode fail-closed/toujours actif et bloquez le trafic pendant la reconnexion.
4. Faites passer le DNS par le tunnel et testez IPv4 et IPv6. Désactivez un protocole uniquement s’il ne peut pas être acheminé par le tunnel en toute sécurité et si la perte de fonctionnalité est acceptée.
5. Testez la veille/le réveil, le changement de réseau, la connexion au portail captif, le plantage du tunnel et le partage de connexion. Le NCSC avertit que, sur certaines plateformes, les appareils connectés à un téléphone en partage de connexion peuvent contourner le VPN du téléphone.<sup>[[2]](#references)</sup>
6. Utilisez un endpoint de test contrôlé par l’organisation pour consigner les adresses IPv4 et IPv6 observées, le résolveur DNS et le timing des connexions. N’exposez pas une intervention sensible à des sites de « test de leak » aléatoires.
7. Recommencez les tests après toute modification du client, du système d’exploitation, du réseau ou de la politique.

### Contournements du routage sur un LAN hostile

Un VPN peut rester visiblement « connecté » alors que certains paquets le contournent, car le système d’exploitation choisit une route **avant** que le VPN ne chiffre le paquet. TunnelCrack a démontré deux façons d’exploiter les exceptions de routage courantes : **LocalNet** fait apparaître une destination Internet comme si elle se trouvait sur le sous-réseau directement connecté, tandis que **ServerIP** usurpe la résolution de la passerelle VPN afin qu’une adresse cible hérite de l’exception réseau en clair dont le transport VPN a besoin. Il s’agit de défaillances du client/routage, et non de failles de WireGuard, OpenVPN, IPsec ou TLS ; les données HTTPS restent chiffrées de bout en bout, mais l’observateur local peut récupérer les métadonnées de destination/de timing ainsi que toute donnée de protocole en clair.<sup>[[18]](#references)</sup>

TunnelVision applique le même mécanisme avant chiffrement via l’option DHCP 121. Un serveur DHCP malveillant ou compromis peut installer une route sans classe plus spécifique que la route fourre-tout du VPN, et ainsi sélectionner l’interface physique pour un hôte ou une plage quelconque. Le canal de contrôle du VPN peut rester actif : un kill switch qui ne se déclenche qu’en cas de déconnexion du tunnel peut donc ne pas s’activer, et une seule vérification publique de « fuite d’IP » peut ne pas détecter les contournements sélectifs.<sup>[[19]](#references)</sup>

Un kill switch par filtrage de paquets qui n’autorise sur l’interface physique que DHCP et le transport VPN authentifié devrait imposer un comportement fail-closed, mais l’injection ciblée de routes peut toujours créer un canal auxiliaire de déni sélectif. Pour les charges de travail Linux à fort enjeu, privilégiez le [modèle plus robuste de namespace réseau imposant les routes](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), où le namespace de l’application n’a ni interface physique ni route par défaut vers le réseau en clair.<sup>[[19]](#references)</sup>

#### Vérification en laboratoire contrôlé

Testez le client/la version du système d’exploitation exacts sur un point d’accès, un serveur DHCP, un endpoint VPN et une destination qui vous appartiennent ; les affirmations sur un produit entier deviennent vite obsolètes, car les implémentations de routage et de filtrage de paquets varient selon les plateformes. Capturez le trafic sur l’endpoint lui-même ainsi que sur le serveur de test : un site affichant l’adresse IP de sortie ne prouve pas que toutes les destinations empruntent le tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connectez le VPN, consignez l’adresse du serveur VPN et enregistrez toutes les tables de routage IPv4/IPv6 et les règles de routage par politique. Sous Windows, utilisez `route print` ; sous macOS, utilisez `netstat -rn` ; sous Linux, utilisez les commandes ci-dessous.
2. Interrogez la route sélectionnée pour plusieurs adresses IP de destination qui vous appartiennent. Le prochain saut/l’interface doit être le tunnel, à l’exception de l’endpoint de transport VPN documenté.
3. Pour TunnelVision, renouvelez le bail sur le réseau DHCP contrôlé et installez une route de l’option 121 **uniquement pour une destination de test qui vous appartient**. Le test est réussi si le trafic reste dans le tunnel ou est bloqué — il ne doit jamais être émis comme trafic destiné à cette destination sur l’interface physique.
4. Pour LocalNet, attribuez au client un sous-réseau de documentation public réservé au laboratoire, par exemple `203.0.113.0/24`, et placez la destination de test qui vous appartient dans ce sous-réseau. Vérifiez que l’activation de l’accès au LAN ne permet pas aux destinations Internet de contourner le tunnel.
5. Pour ServerIP, avant la connexion au VPN, faites résoudre par le DNS contrôlé le nom d’hôte VPN qui vous appartient vers la destination de test qui vous appartient, tandis que la passerelle du laboratoire achemine le transport VPN vers le véritable endpoint VPN qui vous appartient. Le client ne doit pas exempter le trafic d’application sans rapport vers l’adresse usurpée.
6. Répétez les tests avec l’accès au réseau local activé puis désactivé, après une reconnexion, une veille/un réveil, un changement de réseau et un plantage du processus VPN. Testez séparément IPv4, IPv6 et DNS.
7. Examinez la capture de l’interface physique. Elle doit contenir DHCP et des paquets chiffrés à destination du serveur VPN, et non des paquets adressés directement à la destination de test qui vous appartient. Vérifiez aussi qu’un contournement rejeté ne peut pas basculer silencieusement vers une autre route après des invites utilisateur ou une réparation de la connectivité.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser : une meilleure unlinkability sur le Web

Tor crée un circuit passant par plusieurs relais, de sorte qu'en temps normal aucun relais ne connaît à la fois la source et la destination. La destination voit un nœud de sortie Tor plutôt que l'adresse IP de l'utilisateur ; le réseau local voit normalement une connexion Tor.<sup>[[3]](#references)</sup> Tor est conçu pour les applications TCP à faible latence : il est donc plus lent et ne peut garantir une protection contre un adversaire capable de corréler les deux extrémités.<sup>[[4]](#references)</sup>

### Procédure d'utilisation sécurisée de Tor Browser

1. Téléchargez Tor Browser uniquement depuis le Tor Project ou un miroir officiel et, si possible, vérifiez la signature.
2. Utilisez **Tor Browser**, et non un navigateur ordinaire configuré pour utiliser un port SOCKS Tor. Les navigateurs ordinaires peuvent provoquer des leaks DNS/WebRTC et révéler des informations d'identification.<sup>[[5]](#references)</sup>
3. Conservez la taille, les polices, les extensions et les paramètres de confidentialité par défaut. Les modules complémentaires peuvent rendre le navigateur plus unique.<sup>[[6]](#references)</sup>
4. Choisissez le niveau de sécurité **Plus sûr** ou **Le plus sûr** si les problèmes de compatibilité supplémentaires sont acceptables.
5. Utilisez un bridge si Tor est bloqué en accès direct ou si les adresses IP des relais ordinaires créeraient une visibilité locale inacceptable. Les bridges réduisent la facilité de détection, mais n'éliminent pas l'analyse du trafic.<sup>[[7]](#references)</sup>
6. Ne vous connectez pas à un compte permettant de vous identifier, ne fournissez pas d'informations identifiantes et n'ouvrez pas de documents actifs téléchargés dans une application externe connectée au réseau.
7. Utilisez une session/un contexte distinct pour chaque identité. « Nouveau circuit » n'efface pas l'identité du navigateur/de l'application ; utilisez **Nouvelle identité** ou redémarrez l'environnement isolé, selon le cas.
8. Privilégiez HTTPS authentifié ou un service onion authentifié. Un nœud de sortie Tor peut observer le trafic HTTP non chiffré.

### Tor et VPN

Les combiner n'améliore pas automatiquement la sécurité. Un VPN avant Tor peut masquer à un FAI les connexions directes aux relais Tor, tandis que le VPN voit la source ; Tor avant un VPN donne au VPN une vue stable de l'activité post-Tor et peut réduire l'ensemble d'anonymat. Une mauvaise configuration peut provoquer des leaks. Le Tor Project ne recommande ces combinaisons que pour des modèles de menace explicites et avancés.<sup>[[8]](#references)</sup>

## Wi-Fi public et invité

Avec HTTPS moderne, les personnes à proximité qui écoutent passivement ne peuvent généralement pas lire le contenu Web correctement chiffré, mais un Wi-Fi invité ne garantit pas l'anonymat. Le lieu peut enregistrer les heures de connexion, les identifiants des appareils, les données du portail captif, les destinations et les informations DHCP ; les caméras, les achats, les déplacements et l'observation physique peuvent permettre d'identifier l'utilisateur. Un faux hotspot portant un nom similaire peut aussi récupérer les identifiants du portail ou manipuler le trafic non chiffré.<sup>[[9]](#references)</sup>

### Procédure d'utilisation légale d'un réseau invité

1. Utilisez uniquement un réseau proposé aux invités ou un réseau pour lequel le propriétaire vous a donné une autorisation explicite. Demandez au personnel le SSID exact et la procédure du portail.
2. Mettez à jour le terminal et le routeur de voyage avant votre arrivée. Désactivez le partage de fichiers/imprimantes, la découverte entrante, la connexion automatique et la recherche de réseaux mémorisés.
3. Activez l'adresse Wi-Fi privée/aléatoire du système d'exploitation. Les systèmes Apple actuels peuvent utiliser des adresses rotatives sur les réseaux ouverts/faiblement sécurisés ; la randomisation Android moderne est généralement persistante par SSID. Cela ne modifie qu'un seul identifiant local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privilégiez un routeur de voyage contrôlé par votre organisation ou un appareil relais à faible niveau de confiance entre un poste de travail privilégié et le réseau invité. Cela centralise les règles de pare-feu/VPN, mais ne masque pas le routeur au lieu.<sup>[[12]](#references)</sup>
5. Utilisez le portail captif uniquement depuis l'appareil/navigateur désigné à faible niveau de confiance. Ne saisissez jamais d'identifiants personnels ou réutilisés dans un contexte supposément anonyme. Fermez le navigateur du portail une fois la connexion établie.
6. Démarrez un VPN en tunnel complet ou Tor avant toute activité sensible et vérifiez le comportement en cas d'échec.
7. Oubliez le réseau après utilisation et consultez les règles du portail concernant les comptes et la conservation des données.

{% hint style="danger" %}
Pirater le Wi-Fi d'un voisin, contourner un portail, utiliser des identifiants invités leakés, cloner l'accès d'un autre invité ou cacher un Raspberry Pi dans un café constitue une activité non autorisée, pas une technique de confidentialité. Les solutions sûres sont un réseau invité légal, un site approuvé par le client ou un nœud de dépôt documenté, installé et récupéré avec le consentement écrit du propriétaire.
{% endhint %}

## Routeurs de voyage

Un routeur de voyage peut isoler un poste de travail des diffusions locales malveillantes, appliquer un pare-feu, fournir un SSID interne cohérent et rétablir automatiquement une connexion VPN. Il **n'est pas** anonyme : le réseau en amont voit son identité radio et le minutage du trafic, et le fournisseur VPN voit la source du tunnel.

- Utilisez un firmware OpenWrt/fabricant pris en charge et supprimez les services inutilisés.
- Administrez-le par Ethernet ou via un SSID de gestion dédié avec un mot de passe unique.
- Désactivez l'administration côté WAN, UPnP, WPS, le partage de fichiers et le trafic entrant non sollicité.
- Utilisez une adresse MAC WAN privée/aléatoire uniquement si elle est prise en charge et autorisée.
- Appliquez les règles VPN sur le routeur, y compris pour DNS et IPv6, et bloquez le trafic sortant si le tunnel échoue.
- Ne supposez pas qu'un hotspot de téléphone fait passer les appareils connectés via le VPN du téléphone ; vérifiez-le.

## Réseaux cellulaires, cartes SIM et eSIM

Le réseau cellulaire est pratique, mais n'est pas anonyme. Les opérateurs conservent des identifiants d'abonné/d'appareil ainsi que des données de localisation dérivées de la connexion au réseau ; une eSIM reste un abonnement mobile. Le prépayé ne signifie pas nécessairement non enregistré : les exigences varient d'un pays à l'autre et évoluent.<sup>[[13]](#references)</sup>

En pratique :

- Utilisez un appareil distinct pris en charge pour réduire l'exposition de vos données personnelles, pas pour créer un faux abonné.
- Ne transportez pas en permanence un appareil « distinct » à côté d'un téléphone personnel si la co-localisation fait partie du modèle de menace.
- Désactivez les fonctions cellulaires, Wi-Fi, Bluetooth et de localisation inutilisées ; l'arrêt de l'appareil constitue une séparation radio plus forte que les boutons de l'interface.
- Faites passer le trafic sensible par le VPN/Tor approuvé, tout en gardant à l'esprit que l'opérateur connaît l'abonnement, la localisation de l'appareil et le point de terminaison du tunnel.
- Vérifiez les règles actuelles d'enregistrement et de conservation auprès de l'autorité nationale de régulation ou d'un avocat local ; ne vous fiez pas aux listes en ligne de « pays où les SIM sont anonymes ».

## Métadonnées DNS et TLS

- **DoH/DoT/DoQ** chiffrent le DNS entre le client et le résolveur, empêchant sa lecture ou sa modification locale par des moyens simples, mais le résolveur voit toujours les requêtes et les identifiants de transport. Ils déplacent la confiance, sans fournir l'anonymat.<sup>[[14]](#references)</sup>
- **ODoH** ajoute un proxy afin que le résolveur n'ait pas besoin de connaître l'adresse IP du client, à condition que le proxy et la cible ne collaborent pas. L'analyse du trafic est explicitement hors périmètre.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** peut protéger le nom de serveur interne dans une poignée de main TLS lorsque le client, le DNS et le serveur le prennent en charge. L'adresse IP de destination, le minutage, le volume et le terminal restent visibles.<sup>[[16]](#references)</sup>
- Dans un environnement VPN ou Tor correctement configuré, le DNS doit suivre le chemin pris en charge par cet environnement. L'ajout d'un résolveur distinct peut créer un nouvel observateur ou une nouvelle empreinte.

### Procédure de vérification du DNS chiffré/ECH

1. Déterminez si le DNS est contrôlé par l'environnement VPN/Tor, le système d'exploitation ou l'application. Configurez-le dans **une seule** couche prévue à cet effet, au lieu d'empiler des résolveurs sans rapport.
2. Choisissez un résolveur en fonction de sa politique publiée en matière de confidentialité/de conservation et activez le mode chiffré strict lorsque la plateforme le prend en charge. Le repli opportuniste peut rétablir silencieusement le texte brut.
3. Interrogez un sous-domaine unique d'une zone de test faisant autorité que vous contrôlez ; vérifiez que le journal faisant autorité indique le résolveur récursif prévu.
4. Avec autorisation, capturez uniquement le trafic de l'appareil de test. Vérifiez que le réseau d'accès ne peut pas lire le DNS en texte brut, tout en gardant à l'esprit qu'il peut voir le point de terminaison du résolveur/tunnel chiffré.
5. Testez un résolveur chiffré bloqué/injoignable. Le résultat attendu est le comportement de repli documenté ou de blocage en cas d'échec choisi, et non une requête accidentellement en clair.
6. Pour ECH, utilisez un hôte de test contrôlé prenant en charge ECH et examinez les diagnostics du client/serveur pour confirmer que le **ClientHello interne** a été accepté. La simple présence d'un enregistrement HTTPS ne prouve pas la réussite d'ECH.
7. Répétez les tests après des changements de réseau, l'utilisation de portails captifs, les mises à jour du navigateur et les reconnexions VPN. Notez quel composant gère DNS/ECH afin que de futurs administrateurs ne créent pas de contournement.

## Mixnets

Les mixnets tels que Nym ou Katzenpost ajoutent des paquets de taille fixe, des délais, du réordonnancement et du trafic de couverture pour résister à la corrélation temporelle. Ces propriétés coûtent en latence et en bande passante, et les preuves indépendantes à l'échelle d'un déploiement sont limitées. Considérez les mixnets grand public actuels comme des **options émergentes à latence élevée**, et non comme des remplacements plus rapides ou garantis de Tor/VPN.<sup>[[17]](#references)</sup>

### Procédure d'évaluation

1. Identifiez un client maintenu et l'application exacte prise en charge ; ne forcez pas le trafic arbitraire du navigateur/système à passer par un proxy non documenté.
2. Lisez le modèle de menace actuel concernant les hypothèses sur le point d'entrée, les nœuds de mixage, la passerelle, la destination et la collusion.
3. Installez le logiciel depuis sa source officielle signée dans un compartiment de test distinct et utilisez uniquement un point de terminaison inoffensif que vous possédez.
4. Mesurez la latence de livraison, les limites de taille des messages, la fiabilité, les retransmissions et le comportement en cas d'indisponibilité de la passerelle.
5. Examinez le trafic local et le point de terminaison que vous possédez afin de confirmer le chemin prévu et la source. Vérifiez si les réponses utilisent le même modèle de confidentialité.
6. Testez l'arrêt/la défaillance : l'application ne doit pas basculer silencieusement vers un accès Internet direct.
7. Ne désactivez pas le trafic de couverture, ne réduisez pas les délais et ne choisissez pas des routes fixes inhabituelles uniquement pour gagner en vitesse ; ces changements peuvent invalider le modèle d'anonymat déclaré.
8. Gardez la solution au stade expérimental jusqu'à ce que le déploiement spécifique, l'analyse indépendante et la fiabilité opérationnelle répondent au niveau de conséquences attendu.

## Liste de vérification préalable au réseau

- [ ] L'autorisation couvre le réseau d'accès, la cible, les dates et l'infrastructure source.
- [ ] Le terminal ne contient aucune identité sans rapport ni session de synchronisation active.
- [ ] IPv4, IPv6, DNS et le comportement en cas de reconnexion sont conformes au plan.
- [ ] L'injection de routes DHCP/sous-réseau local contrôlée ne peut pas rediriger le trafic de test vers l'interface physique.
- [ ] La destination ne voit que la sortie prévue.
- [ ] Le portail captif et le comportement du hotspot ont été testés sans trafic sensible.
- [ ] Le partage/la découverte locaux et la connexion automatique aux réseaux sont désactivés.
- [ ] Le tableau des observateurs et le risque résiduel de corrélation du trafic sont acceptés.
- [ ] Les règles du fournisseur, la conservation des données et le contact d'urgence sont à jour.

Pour les relais à connaissances séparées, les charges de travail avec routage imposé, les transports enfichables, les services onion, I2P et les navigateurs distants jetables, consultez [Architectures avancées de confidentialité réseau](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Choisir le VPN qui vous convient](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Guide de sécurité des appareils : réseaux privés virtuels](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Les protections de confidentialité et d'anonymat offertes par Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Brève introduction à Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Utiliser Tor avec d'autres navigateurs](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins et modules complémentaires dans Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Débloquer Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Utiliser Tor Browser avec un VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Les réseaux Wi-Fi publics sont-ils sûrs ?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Confidentialité Wi-Fi avec les appareils Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implémenter la randomisation MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principes relatifs aux postes de travail sécurisés à accès privilégié](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Enregistrement obligatoire des cartes SIM : perspectives politiques et réglementaires](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommandations à l'intention des opérateurs de services de confidentialité DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS sur HTTPS obfusqué](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Modèle de menace](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Contourner les tunnels : fuite du trafic des clients VPN par abus des tables de routage](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision : comment les attaquants peuvent démasquer les VPN basés sur le routage et provoquer un leak VPN total](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [FAQ Yggdrasil : Yggdrasil est-il anonyme ?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [README Yggstack](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
