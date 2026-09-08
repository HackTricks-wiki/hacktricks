# Confidentialité des cryptomonnaies

{{#include ../banners/hacktricks-training.md}}

La confidentialité des cryptomonnaies est une question de protocole et d'opérations, et non un synonyme de secret ou d'immunité. Les registres publics, les exchanges, les serveurs de wallet, les pairs du réseau, les commerçants et les transactions ultérieures exposent différentes parties du graphe.

Commencez par le [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) pour le format avantages/inconvénients/procédure/détection de chaque technique. Cette page approfondit les mécanismes propres aux cryptomonnaies et leurs limites opérationnelles.

{% hint style="danger" %}
Ce chapitre concerne l'auto-garde légale et la minimisation des données. Ne l'utilisez pas pour blanchir des produits, contourner des sanctions/obligations fiscales/de déclaration, effectuer des transactions avec des parties interdites, induire en erreur un fournisseur réglementé ou exploiter un service de transmission sans licence. La technologie de confidentialité ne modifie ni l'origine légale ni la propriété des fonds.
{% endhint %}

## Modèle de menace par couche

| Couche | Observateur | Divulgation courante |
|---|---|---|
| Acquisition/off-ramp | Exchange, banque, broker, contrepartie P2P | Identité, compte de financement, destination, appareil, IP, heure |
| Registre | Toute personne exécutant des analytics | Adresses/outputs, montants et heures sur les chaînes transparentes ; métadonnées spécifiques au protocole ailleurs |
| Backend du wallet | Fournisseur RPC, explorer, nœud distant | Requêtes d'adresses, soldes, IP, diffusion des transactions |
| Réseau | FAI, pairs, entrée du réseau d'anonymat | IP, synchronisation, volume et utilisation du protocole |
| Contrepartie | Payeur/bénéficiaire | Facture/adresse, livraison, conversation, compte et synchronisation |
| Endpoint | Malware, sauvegarde cloud, saisie physique | Seed, clés, libellés, historique, captures d'écran et presse-papiers |

L'auto-garde peut retirer un dépositaire du chemin de contrôle, mais n'efface ni le registre, ni l'enregistrement d'acquisition, ni les métadonnées réseau, ni les preuves présentes sur l'endpoint.

## Comparaison des protocoles

| Méthode | Propriété de confidentialité utile | Limites importantes |
|---|---|---|
| Bitcoin on-chain | Auto-garde ; les adresses fraîches évitent la simple réutilisation d'adresse | Graphe public et permanent des transactions ; heuristiques de montant/synchronisation et de dépense |
| Bitcoin PayJoin | L'input du bénéficiaire peut casser l'heuristique de propriété commune des inputs | Les deux wallets doivent être compatibles ; la transaction reste publique ; compatibilité inégale |
| Bitcoin CoinJoin | Crée une ambiguïté entre les participants coordonnés | Motifs reconnaissables, liens avant/après, consolidation, risques liés aux politiques, à la légalité et aux fournisseurs |
| Lightning | Les paiements routés par onion ne sont pas publiés globalement comme des transferts ordinaires | Les ouvertures/fermetures de channels sont on-chain ; les endpoints, pairs, probes ou custodians peuvent déduire des données |
| Monero | Confidentialité on-chain par défaut plus forte pour le bénéficiaire, le montant et l'ensemble des émetteurs | Les liens avec l'exchange, le nœud, la synchronisation, l'endpoint et la contrepartie subsistent |
| Ethereum/stablecoins | Large disponibilité et interopérabilité avec les smart contracts | État/actions publics ; métadonnées RPC ; les émetteurs centralisés peuvent bloquer/geler/signaler |

## Bitcoin : base préservant la confidentialité

Bitcoin est pseudonyme, et non anonyme. Les transactions confirmées sont publiques et durables ; la réutilisation d'adresses, la propriété commune des inputs, la détection de la monnaie rendue et les adresses publiquement identifiées peuvent construire des clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Choisissez un wallet d'auto-garde maintenu.** Téléchargez-le depuis le projet officiel, vérifiez les signatures/hash lorsqu'ils sont proposés et appliquez les mises à jour de sécurité.
2. **Créez le wallet sur un endpoint de confiance.** Notez le seed de récupération hors ligne ; ne le placez jamais dans un e-mail, une conversation, des captures d'écran ou des notes cloud ordinaires. Testez la récupération avant d'y placer une valeur importante.
3. **Ne gardez en hot wallet que la valeur opérationnelle.** Utilisez une garde hors ligne/matérielle adaptée pour les valeurs à long terme, avec un plan de récupération qui n'expose pas le seed à un seul emplacement fragile.
4. **Générez une nouvelle adresse de réception/facture pour chaque transaction.** Ne publiez pas d'adresse statique lorsqu'un serveur de facturation ou une remise privée authentifiée est possible.
5. **Utilisez votre propre full node lorsque c'est possible.** Un explorer/serveur Electrum tiers peut connaître les adresses interrogées et les métadonnées IP. Configurez uniquement le comportement Tor/proxy pris en charge par le wallet ; Tor masque une extrémité réseau, pas le graphe blockchain.
6. **Étiquetez chaque UTXO en privé** avec sa source, son propriétaire, son objectif et son état de conformité. Activez le coin control afin que des contextes d'identité sans lien ne soient pas dépensés ensemble.
7. **Prévisualisez la transaction :** inputs sélectionnés, destination de la monnaie rendue, montant, frais, contrepartie et éventuelle fusion des compartiments lors de la dépense. Évitez les consolidations inutiles.
8. **Conservez séparément les documents légaux et chiffrez-les.** Préservez la base d'acquisition, les factures, les autorisations et les informations fiscales/de déclaration sans publier la correspondance.
9. **Considérez les dépenses ultérieures comme faisant partie de la même décision de confidentialité.** Une réception correctement séparée peut être reliée lorsque son output est dépensé avec des fonds identifiés.

La documentation de confidentialité de Bitcoin Core explique qu'un full node évite de révéler les requêtes du wallet à des serveurs tiers, mais que la diffusion des transactions et l'historique public nécessitent toujours une analyse.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin est un paiement collaboratif dans lequel le bénéficiaire ajoute un input. Cela contredit l'hypothèse simpliste selon laquelle tous les inputs appartiennent à l'émetteur. Le BIP 78 décrit le protocole interactif original ; le draft BIP 77 définit une conception asynchrone v2 utilisant une boîte aux lettres chiffrée/OHTTP.<sup>[[3]](#references)</sup>

Utilisation sûre :

1. Vérifiez que les deux wallets maintenus prennent en charge la même version de PayJoin.
2. Obtenez la facture compatible PayJoin via un canal authentifié ; protégez-la comme toute demande de paiement.
3. Vérifiez le montant et la destination d'origine, puis laissez le wallet valider la proposition/PSBT, la contribution aux frais et les substitutions interdites.
4. Confirmez le résumé final du wallet. N'approuvez pas manuellement un output, un montant ou des frais excessifs inattendus.
5. Si la négociation échoue, vérifiez si le wallet revient de manière sûre à un paiement ordinaire ou s'il exige une nouvelle facture.
6. Conservez les reçus/documents privés nécessaires à la propriété, à la comptabilité et aux litiges.

PayJoin améliore une heuristique d'analyse de chaîne ; il ne masque pas le paiement aux parties, à la plateforme d'acquisition, aux endpoints ou au registre public.

## CoinJoin : avantages et limites

CoinJoin coordonne plusieurs utilisateurs dans une même transaction afin de rendre la correspondance inputs-outputs moins certaine. Des recherches sur certaines conceptions historiques de Wasabi et Samourai ont identifié des transactions très reconnaissables et montré que le comportement avant/après le mix peut réduire considérablement l'anonymat.<sup>[[4]](#references)</sup> Ce résultat ne doit pas être généralisé à chaque implémentation ou version future, mais il démontre pourquoi un nombre d'« ensemble d'anonymat » n'est pas une garantie.

Avant toute utilisation légale :

- vérifiez la législation locale actuelle, le statut des sanctions, la politique de l'exchange/custodian et les obligations fiscales/de déclaration ;
- utilisez un software maintenu et non custodial obtenu auprès de son projet officiel ;
- comprenez le modèle du coordinator, les frais, les contrôles contre le déni de service et vérifiez si le service actuel fonctionne toujours — zkSNACKs a arrêté son coordinator en 2024, bien que d'autres coordinators Wasabi puissent exister ;
- conservez en privé les documents relatifs à l'origine des fonds et aux transactions ;
- n'acceptez jamais de fonds inconnus pour le compte d'autrui et n'utilisez pas de « mixer » custodial promettant des retraits intraçables ;
- gardez les outputs séparés par source/contexte et évitez toute consolidation ultérieure qui détruirait l'ambiguïté recherchée.

Les conséquences juridiques dépendent des faits et de la juridiction. Les plaidoyers de culpabilité de Samourai en 2025 concernaient l'exploitation consciente d'un transmetteur de fonds sans licence qui déplaçait des produits criminels ; ils n'établissent pas que chaque transaction collaborative ou utilisateur recherchant la confidentialité est criminel.<sup>[[5]](#references)</sup>

## Lightning Network

Le routage onion Sphinx de Lightning est conçu pour qu'un hop intermédiaire connaisse son prédécesseur et son successeur, plutôt que l'intégralité du chemin.<sup>[[6]](#references)</sup> Il ne fournit pas un anonymat complet : le financement/la fermeture des channels sont publics, les nœuds annoncent la topologie, les contreparties connaissent les endpoints, le routage/probing peut révéler des soldes ou des parties, et un wallet custodial voit l'activité du compte de son utilisateur.

Pour améliorer la confidentialité :

1. Préférez un wallet maintenu et non custodial si la confidentialité vis-à-vis des intermédiaires est importante ; planifiez d'abord la sauvegarde/récupération des channels.
2. Utilisez une nouvelle facture ou offer pour chaque paiement. Vérifiez si le wallet prend précisément en charge BOLT 12/route blinding au lieu de le supposer.
3. Évitez de publier des alias de nœuds, coordonnées et endpoints réseau stables inutiles.
4. Connectez-vous via un réseau de confidentialité pris en charge si approprié, en comprenant que les schémas de disponibilité/synchronisation peuvent toujours être corrélés.
5. Ne supposez pas qu'un paiement off-chain ne laisse aucune trace : l'émetteur, le bénéficiaire, les pairs, les watchtowers, les fournisseurs de liquidité et les services de wallet peuvent conserver des observations.

Des recherches publiées ont démontré l'inférence de l'émetteur/du bénéficiaire et du solde des channels à partir de données publiques et de probing actif, bien que les attaques et les mitigations évoluent.<sup>[[7]](#references)</sup>

## Monero

Monero utilise des adresses stealth à usage unique pour les outputs, RingCT pour masquer les montants et des ring signatures pour fournir une ambiguïté probabiliste concernant l'émetteur ; ses spécifications techniques actuelles indiquent une ring size de 16 (15 decoys).<sup>[[8]](#references)</sup> Il s'agit de garanties par défaut plus fortes pour la confidentialité on-chain que celles des registres transparents, et non d'une protection magique contre les erreurs liées aux endpoints ou aux opérations.

### Workflow légal

1. **Acquérez légalement.** Un exchange réglementé peut connaître l'achat et le retrait même lorsque les détails on-chain ultérieurs sont confidentiels. Conservez les documents relatifs à la source, à la base et aux déclarations.
2. **Installez le wallet officiel maintenu** et vérifiez son téléchargement conformément aux instructions du projet. Sauvegardez le seed hors ligne et testez la restauration avec un petit montant.
3. **Préférez un nœud local** pour maximiser la confidentialité des requêtes du wallet. Si cela n'est pas pratique, choisissez un nœud distant de confiance accessible via une configuration onion/I2P officiellement prise en charge. Un nœud distant peut journaliser l'IP, les requêtes, la synchronisation et les ID de transaction ; certaines conceptions lightweight divulguent une view key.
4. **Utilisez une nouvelle subaddress par payeur, campagne ou facture.** Un payeur peut corréler la réutilisation de la même subaddress.<sup>[[9]](#references)</sup>
5. **Étiquetez localement les contextes entrants.** Évitez de fusionner opérationnellement des réceptions séparées lorsqu'un payeur averti pourrait reconnaître le comportement ultérieur.
6. **Protégez les métadonnées réseau.** Suivez la configuration officielle du réseau d'anonymat ; tenez compte des leaks documentés liés aux horodatages, à la synchronisation intermittente, à la forme de la bande passante et à la réutilisation des streams.<sup>[[10]](#references)</sup>
7. **Conservez les données de conformité/audit en privé.** Ne divulguez une view key ou une preuve de transaction que délibérément, à l'auditeur/à la partie concernée, et comprenez précisément ce qu'elle révèle.

Les études historiques de traçabilité incluent des bugs et des périodes de sélection des decoys qui ont depuis changé ; n'appliquez pas les anciens pourcentages de réussite aux transactions actuelles. De même, FCMP++ reste un travail de roadmap à la date de clôture des recherches de ce chapitre, en septembre 2026, et non une protection déployée.<sup>[[11]](#references)</sup>

## Ethereum et stablecoins

Les ressources de confidentialité d'Ethereum indiquent que les actions on-chain sont visibles et que l'infrastructure wallet/RPC ajoute une exposition de l'IP et des métadonnées.<sup>[[12]](#references)</sup> Les transferts de tokens, approvals, interactions avec les smart contracts, services de noms et financements du gas peuvent tous relier des identités.

Les stablecoins centralisés ajoutent le contrôle de l'émetteur. Les conditions actuelles de USDC et Tether se réservent le pouvoir de bloquer/geler des adresses ou des actifs et de se conformer aux obligations légales et procédurales.<sup>[[13]](#references)</sup> Ils peuvent être utiles comme instruments de paiement, mais constituent de mauvais choix lorsque l'objectif est la résistance à la censure ou l'anonymat on-chain.

## Limites de conformité

- Les recommandations du FATF sont mises en œuvre par le droit national et évoluent avec le temps ; sa mise à jour de 2026 met l'accent sur l'octroi de licences/l'enregistrement des VASP et la mise en œuvre de la Travel Rule.<sup>[[14]](#references)</sup>
- Aux États-Unis, FinCEN distingue une personne utilisant une monnaie virtuelle convertible pour ses propres biens/services d'une entreprise qui l'accepte, la transmet ou l'échange ; les faits et les règles ultérieures sont importants.<sup>[[15]](#references)</sup>
- Le règlement européen sur les transferts de fonds exige les informations relatives à l'émetteur/au bénéficiaire lorsqu'un fournisseur de services sur crypto-actifs intervient et ajoute des règles de vérification pour certains transferts depuis/vers des adresses self-hosted.<sup>[[16]](#references)</sup>
- Les sanctions et obligations fiscales continuent de s'appliquer. Effectuez les screenings requis, refusez les parties interdites et conservez les documents ; les listes et le statut juridique peuvent changer rapidement.<sup>[[17]](#references)</sup>

Avant toute valeur importante, activité transfrontalière, coordination améliorant la confidentialité ou activité d'échange/transmission de type professionnel, obtenez un conseil professionnel à jour pour les juridictions concernées.

Pour Bitcoin Silent Payments, Zcash entièrement shielded, GNU Taler, l'e-cash Chaumian fédéré et BOLT 12, consultez [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Protégez votre confidentialité](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Fonctionnalités de confidentialité](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Une proposition simple de PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoption et confidentialité réelle des implémentations CoinJoin décentralisées dans Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Les fondateurs de Samourai Wallet plaident coupables (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocole de routage onion](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Une analyse empirique de la confidentialité dans le Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Projet Monero — [Adresses stealth](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) et [Spécifications techniques](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Réseaux](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Étude de l'évolution de la confidentialité de Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Confidentialité sur Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Conditions de USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Mise à jour ciblée 2026 sur les actifs virtuels et les VASP](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Application des réglementations de FinCEN aux personnes administrant, échangeant ou utilisant des monnaies virtuelles](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Règlement (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Guide de conformité aux sanctions pour le secteur des monnaies virtuelles](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
