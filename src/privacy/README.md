# Confidentialité offensive, évasion de l'attribution et OPSEC

{{#include ../banners/hacktricks-training.md}}

Cette section étudie la confidentialité du point de vue d'une red team, d'un opérateur d'intrusion et du défenseur qui tente de reconstituer les actions de cet opérateur. **L'anonymat ne consiste pas simplement à masquer une adresse IP.** Les opérations matures séparent les personnes, endpoints, comptes, infrastructures, chemins réseau, payloads et paiements susceptibles d'être reliés dans un graphe d'attribution.

Le contenu inclut volontairement des techniques rapportées dans des opérations gouvernementales et APT : réseaux d'operational-relay-box (ORB), edge devices compromis, sorties résidentielles, niveaux de redirectors, fast flux, domain fronting, dead-drop resolvers, pivots wireless voisins, covert drop devices, abus de liaisons satellite, fausses personas et layering financier. Chaque technique est présentée selon :

1. l'objectif opérationnel et le mapping ATT&CK ;
2. le mécanisme et les limites de confiance ;
3. ce que chaque observateur peut encore enregistrer ;
4. les erreurs et artefacts persistants qui permettent de la déjouer ;
5. la télémétrie défensive, les analytics et les mitigations ; et
6. une émulation autorisée utilisant une infrastructure détenue ou explicitement incluse dans le périmètre.

Il s'agit donc à la fois d'une référence d'offensive tradecraft et d'un manuel d'attribution destiné aux défenseurs. L'objectif est de rendre les comportements avancés compréhensibles et testables, et non de prétendre qu'un seul service commercial rend un opérateur invisible.

**Limite de recherche :** 8 septembre 2026. La disponibilité des providers, le comportement des produits, les sanctions, les seuils cash/prepaid, les règles d'enregistrement des SIM et la réglementation des cryptomonnaies changent fréquemment ; vérifiez-les à nouveau avant de vous y fier.

{% hint style="danger" %}
Comprendre une technique ne constitue pas une autorisation de l'utiliser. Les pages expliquent les abus criminels tels que les routeurs compromis, le Wi-Fi d'un voisin, les appareils dissimulés, les identités volées et le blanchiment au niveau des mécanismes et de la détection. Les étapes de reproduction utilisent uniquement des systèmes de laboratoire détenus en propre, des identités synthétiques et des assets de test. N'accédez jamais à un tiers, ne contournez jamais les exigences KYC ou les sanctions, et ne dissimulez jamais des produits criminels. L'accès non autorisé est criminalisé dans de nombreuses juridictions, notamment par le CFAA américain, le Computer Misuse Act britannique et les lois des États membres de l'UE mettant en œuvre la Directive 2013/40/UE.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Cartographie des objectifs de l'adversaire

| Objectif de l'adversaire | Familles de techniques | Question défensive principale |
|---|---|---|
| Masquer l'origine de l'opérateur | VPN/Tor, proxies externes et multi-hop, sorties résidentielles/mobiles, ORBs, liaisons satellite | L'adresse du dernier hop appartient-elle à un acteur, à une victime involontaire ou à un relay de courte durée ? |
| Maintenir le véritable C2 indétectable | redirectors, CDNs, domain fronting, dead-drop resolvers, dynamic DNS, fast flux | Quel comportement stable subsiste malgré la rotation des IP/domaines ? |
| Emprunter la confiance et la réputation | serveurs compromis, routeurs, comptes cloud et web-service, domain shadowing | Un asset réputé se comporte-t-il différemment de sa baseline historique ? |
| Franchir une limite physique ou réseau | pivots Wi-Fi nearest-neighbor, drops sur site, rogue peripherals, cellular backhaul | Quelle nouvelle radio, quel appareil, switchport ou tunnel sortant est apparu ? |
| Séparer l'humain de l'opération | personas, compartimentation des comptes/appareils, communications de couverture, séparation des achats | Quel champ de récupération, browser, horaire, langue, paiement ou événement d'administration relie les personas ? |
| Obscurcir le financement et le cash-out | mules/nominees, valeur prepaid, mixers, CoinJoin, peel chains, chain hopping, brokers OTC | Où les enregistrements d'identité on-chain et off-chain se reconnectent-ils ? |

Les concepts ATT&CK les plus proches concernant le resource-development et le C2 sont **Acquire Infrastructure (T1583)**, **Compromise Infrastructure (T1584)**, **Establish/Compromise Accounts (T1585/T1586)**, **Proxy (T1090)**, **Dynamic Resolution (T1568)** et **Web Service (T1102)**.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Confidentialité, pseudonymat, anonymat et sécurité

| Objectif | Signification | Échec typique |
|---|---|---|
| **Confidentialité** | Les personnes extérieures ne peuvent pas lire le contenu | Les métadonnées identifient toujours les parties |
| **Confidentialité des données** | La divulgation d'informations est limitée à ce qui est nécessaire | Un provider conserve plus de données que prévu |
| **Pseudonymat** | L'activité utilise une identité stable qui n'est pas publiquement liée à une identité légale | L'e-mail de récupération, le paiement, l'IP, la photo ou le style d'écriture la relie |
| **Anonymat** | Un observateur ne peut pas distinguer l'acteur d'un ensemble significatif d'autres personnes | Le login, le fingerprint, le timing, la localisation ou la corrélation des transactions réduit cet ensemble |
| **Non-linkability** | Deux actions ne peuvent pas être attribuées de manière fiable au même acteur | Des identifiants réutilisés, une activité simultanée ou une infrastructure partagée les relie |
| **Sécurité** | Les systèmes résistent à la compromission | Un compte sécurisé mais identifié reste non anonyme |

Ces propriétés dépendent de l'observateur. Un marchand peut ne pas voir le numéro de carte alors que l'émetteur connaît toujours le client et la transaction. Un site web peut voir une sortie Tor plutôt qu'une IP personnelle, tandis qu'un login de compte identifie immédiatement l'utilisateur.

## Commencer par l'observateur

Avant de choisir des outils, notez :

1. **Assets :** identité, localisation, destinations de navigation, contenu des messages, graphe social, informations de paiement, nom du client, infrastructure source de red team ou preuves stockées.
2. **Observateurs :** opérateur du Wi-Fi local, ISP/opérateur mobile, VPN, entrée/sortie Tor, resolver DNS, site web, ad network, cloud host, émetteur du paiement, marchand, exchange, contreparties, employeur ou gouvernement.
3. **Points de corrélation :** adresse IP, champs de compte/récupération, numéro de téléphone, identifiants de l'appareil, cookies, browser fingerprint, fuseau horaire, instrument de paiement, adresse de livraison, style d'écriture, graphe des transactions, présence physique et caméras.
4. **Capacité et durée :** le tracking commercial passif diffère d'un observateur ciblé capable d'obtenir les données des providers par subpoena, de saisir des endpoints ou d'observer les deux extrémités d'une connexion.
5. **Coût de l'échec :** embarras, suspension de compte, préjudice pour le client, perte financière, danger physique ou exposition juridique.

Sélectionnez ensuite les contrôles durables les plus limités. Un plan compliqué qui est régulièrement contourné est plus faible qu'un plan plus simple appliqué de manière cohérente.

## Tableau de décision rapide

| Besoin | Point de départ raisonnable | Ce que cela ne résout **pas** |
|---|---|---|
| Masquer les métadonnées de navigation à un ISP/réseau local | VPN réputé ou Tor Browser | Comptes, cookies, device fingerprint, compromission de l'endpoint |
| Anonymat web renforcé | Tor Browser ; Tails pour une session amnésique | Corrélation globale du trafic, divulgations personnelles, observation physique |
| Travail persistant compartimenté | Whonix ou Qubes-Whonix ; qubes/profils séparés | Compromission de l'hyperviseur/host, liaison comportementale des identités |
| Egress rapide de red team autorisée | Jump host fourni par le client ou VPS/VPN spécifique à l'engagement | Attribution par le provider/client ; obligations de périmètre et de politique cloud |
| Réduire l'exposition du numéro de carte auprès d'un marchand | Carte virtuelle de l'émetteur ou wallet tokenisé | Connaissance de l'émetteur/réseau, livraison, données de compte et d'appareil |
| Minimiser les données de paiement au point de vente | Cash obtenu légalement lorsqu'il est accepté | CCTV, reçus, historique de retrait, limites de cash |
| Améliorer la confidentialité des cryptomonnaies sur une public chain | Propre wallet/node, nouvelles adresses, coin control, Tor, PayJoin pris en charge | Exchange/KYC, enregistrements des contreparties, analyse permanente de la chain |
| Confidentialité par défaut du montant/récepteur/émetteur on-chain | Monero avec des contextes de wallet séparés et network privacy | Enregistrements d'acquisition/off-ramp, compromission de l'endpoint, données marchand/livraison |

## Règles fondamentales

- **Séparez les contextes avant le début de l'activité.** Mettre en place la séparation après que les comptes, appareils et paiements ont déjà été reliés ne permet généralement pas d'effacer l'historique.
- **Ne vous personnalisez pas au point de devenir unique.** Le browser fingerprinting peut corréler l'activité même après la suppression des cookies ou le changement d'IP ; les configurations standard avec des anonymity sets plus larges sont généralement préférables.<sup>[[5]](#references)</sup>
- **Protégez l'endpoint.** L'anonymat réseau ne peut pas sauver un appareil déverrouillé, infecté ou saisi.
- **Chiffrez le contenu et minimisez les métadonnées.** Le chiffrement de bout en bout protège le contenu des messages, mais pas nécessairement l'identité des interlocuteurs, le moment, le lieu ou l'appareil utilisé.
- **Considérez les providers comme des observateurs.** Les VPN, services e-mail, cloud hosts, exchanges, émetteurs de paiement et alias forwarders voient différentes parties de l'activité.
- **Privilégiez les affirmations vérifiables.** Recherchez la documentation des protocoles, des logiciels reproductibles, des audits publics, les détails de rétention et les transparency reports plutôt que le marketing « de niveau militaire ».
- **Réévaluez périodiquement.** Les services, lois, threat actors et paramètres par défaut changent.

## Carte des sections orientées offensive

- [Catalogue des techniques d'accès Internet anonyme](anonymous-internet-access-techniques.md) — 48 familles de chemins d'accès avec avantages, inconvénients, étapes de déploiement/émulation, détection, exposition à la capture et monitoring de découverte côté contrôleur.
- [Catalogue des techniques de paiement anonyme](anonymous-payment-techniques.md) — 48 familles de paiements avec avantages, inconvénients, workflows légaux, détection, exposition à la capture et monitoring de compromission.
- [Field Nodes autorisés résistants à la capture](capture-resilient-authorized-field-nodes.md) — rendezvous sortant stable, récupération dual-uplink, minimisation des secrets, capture drills et monitoring de découverte/compromission pour des drops approuvés par le propriétaire.
- [Infrastructure offensive et évasion de l'attribution](offensive-infrastructure-and-attribution-evasion.md) — ORBs, relays multi-hop/résidentiels, redirectors, fronting, fast flux, domain shadowing, web services et infrastructure de personas.
- [Accès physique et wireless covert](covert-physical-wireless-access.md) — attaques nearest-neighbor, accès public, drop devices, cellular backhaul et abus satellite.
- [Études de cas gouvernementales et APT](government-and-apt-case-studies.md) — cas publics reconstruits et télémétrie les ayant exposés.
- [Tradecraft d'obfuscation financière](financial-obfuscation-tradecraft.md) — fonctionnement du layering des paiements, raisons de ses échecs et méthodes de suivi par les enquêteurs.
- [Attribution, détection et contre-mesures](attribution-detection-and-countermeasures.md) — modèle de détection cross-layer et logique pratique de hunting.
- [Labs d'émulation d'adversaire autorisés](authorized-adversary-emulation-labs.md) — exercices reproductibles utilisant des réseaux détenus en propre et des données synthétiques.

## Fondamentaux de l'opérateur et guides complémentaires

- [Modélisation des menaces et séparation des identités](threat-modeling-and-identity-separation.md)
- [Confidentialité réseau et connectivité anonyme](network-privacy-and-anonymous-connectivity.md)
- [Architectures avancées de confidentialité réseau](advanced-network-privacy-architectures.md)
- [Systèmes d'exploitation axés sur la confidentialité](privacy-operating-systems.md)
- [Communications et partage préservant la confidentialité](privacy-preserving-communications-and-sharing.md)
- [Infrastructure de red team autorisée](authorized-red-team-infrastructure.md)
- [Paiements numériques privés](private-digital-payments.md)
- [Confidentialité des cryptomonnaies](cryptocurrency-privacy.md)
- [Protocoles de paiement préservant la confidentialité](privacy-preserving-payment-protocols.md)
- [Tests de confidentialité reproductibles](reproducible-privacy-testing.md)
- [Playbooks de confidentialité opérationnelle](operational-privacy-playbooks.md)

## Index des guides et de la vérification

| Technique | Guide de déploiement | Test de vérification/échec |
|---|---|---|
| Toutes les familles de techniques d'accès Internet | [Catalogue des techniques d'accès Internet anonyme](anonymous-internet-access-techniques.md) | Détection par technique et [labs reproductibles](authorized-adversary-emulation-labs.md) |
| Toutes les familles de techniques de paiement | [Catalogue des techniques de paiement anonyme](anonymous-payment-techniques.md) | Détection par technique et [synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Field node physique approuvé par le propriétaire | [Field Nodes autorisés résistants à la capture](capture-resilient-authorized-field-nodes.md) | Capture drill, monitoring de l'état off-device et runbook de découverte suspectée |
| ORBs, relays résidentiels, fronting, fast flux et dead drops | [Infrastructure offensive et évasion de l'attribution](offensive-infrastructure-and-attribution-evasion.md) | [Labs d'émulation détenus en propre](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Wi-Fi nearest-neighbor, drops, chemins cellulaires et satellite | [Accès physique et wireless covert](covert-physical-wireless-access.md) | [Lab de wireless pivot détenu en propre](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Infrastructure cross-layer et attribution de l'opérateur | [Attribution, détection et contre-mesures](attribution-detection-and-countermeasures.md) | [Modèle de rapport d'exercice](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chains, mixers, chain hopping, nominees et conversion OTC | [Tradecraft d'obfuscation financière](financial-obfuscation-tradecraft.md) | [Graphe de transactions synthétique](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Compartimentation de l'identité/browser | [Modélisation des menaces et séparation des identités](threat-modeling-and-identity-separation.md) | [Tests du browser et de l'OS](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, guest Wi-Fi, travel router, cellulaire | [Confidentialité réseau et connectivité anonyme](network-privacy-and-anonymous-connectivity.md) | [Test du chemin réseau](reproducible-privacy-testing.md#network-path-test) |
| Split relays, OHTTP, namespaces, bridges, onions, I2P | [Architectures avancées de confidentialité réseau](advanced-network-privacy-architectures.md) | [Tests Tor/onion et des routes](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix et Qubes | [Systèmes d'exploitation axés sur la confidentialité](privacy-operating-systems.md) | [Test d'isolation de l'OS](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare et fichiers chiffrés | [Communications et partage préservant la confidentialité](privacy-preserving-communications-and-sharing.md) | [Tests des communications/fichiers](reproducible-privacy-testing.md#communications-metadata-test) |
| Egress/drop nodes de red team autorisés | [Infrastructure de red team autorisée](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash, prepaid et cartes virtuelles | [Paiements numériques privés](private-digital-payments.md) | [Test de confidentialité des paiements](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning et Monero | [Confidentialité des cryptomonnaies](cryptocurrency-privacy.md) | [Test de confidentialité des paiements](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler et e-cash fédéré | [Protocoles de paiement préservant la confidentialité](privacy-preserving-payment-protocols.md) | [Test de confidentialité des paiements](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Votre plan de sécurité](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Fraude et activités connexes liées aux ordinateurs](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Directive 2013/40/UE relative aux attaques contre les systèmes d'information](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Réduire le browser fingerprinting dans les spécifications web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583) et Compromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
{{#include ../banners/hacktricks-training.md}}
