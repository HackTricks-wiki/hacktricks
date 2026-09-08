# Confidentialité des cryptomonnaies

La confidentialité des cryptomonnaies est une question de protocole et d'opérations, et non un synonyme de secret ou d'immunité. Les registres publics, les exchanges, les serveurs de wallet, les pairs du réseau, les marchands et les transactions ultérieures exposent différentes parties du graphe.

Commencez par le [Catalogue des techniques de paiement anonyme](anonymous-payment-techniques.md) pour le format avantages/inconvénients/procédure/détection de chaque technique. Cette page approfondit les mécanismes propres aux cryptomonnaies et leurs limites opérationnelles.

{% hint style="danger" %}
Ce chapitre concerne l'auto-conservation légale et la minimisation des données. Ne l'utilisez pas pour blanchir des produits, contourner des sanctions/impôts/obligations déclaratives, effectuer des transactions avec des parties interdites, induire en erreur un prestataire réglementé ou exploiter un service de transmission sans licence. La technologie de confidentialité ne modifie ni l'origine légale ni la propriété des fonds.
{% endhint %}

## Modèle de menace par couche

| Couche | Observateur | Divulgation courante |
|---|---|---|
| Acquisition/on-ramp | Exchange, banque, courtier, contrepartie P2P | Identité, compte de financement, destination, appareil, IP, heure |
| Registre | Toute personne exécutant des analyses | Adresses/sorties, montants et heures sur les chaînes transparentes ; métadonnées spécifiques au protocole ailleurs |
| Backend du wallet | Fournisseur RPC, explorer, nœud distant | Requêtes d'adresses, soldes, IP, diffusion des transactions |
| Réseau | FAI, pairs, point d'entrée d'un réseau d'anonymat | IP, timing, volume et utilisation du protocole |
| Contrepartie | Payeur/bénéficiaire | Facture/adresse, livraison, conversation, compte et timing |
| Endpoint | Malware, sauvegarde cloud, saisie physique | Seed, clés, libellés, historique, captures d'écran et presse-papiers |

L'auto-conservation peut retirer un dépositaire du chemin de contrôle, mais n'efface ni le registre, ni l'historique d'acquisition, ni les métadonnées réseau, ni les preuves présentes sur l'endpoint.

## Comparaison des protocoles

| Méthode | Propriété de confidentialité utile | Limites importantes |
|---|---|---|
| Bitcoin on-chain | Auto-conservation ; les adresses nouvelles évitent la simple réutilisation d'adresse | Graphe public et permanent des transactions ; heuristiques fondées sur les montants, le timing et les dépenses |
| Bitcoin PayJoin | L'input du bénéficiaire peut contrecarrer l'heuristique de propriété commune des inputs | Les deux wallets doivent être compatibles ; la transaction reste publique ; prise en charge inégale |
| Bitcoin CoinJoin | Crée une ambiguïté entre les participants coordonnés | Schémas reconnaissables, liens avant/après, consolidation, risques liés aux politiques, au droit et aux fournisseurs |
| Lightning | Les paiements routés par onion ne sont pas publiés mondialement comme des transferts ordinaires | Les canaux sont ouverts/fermés on-chain ; les endpoints, pairs, probes ou dépositaires peuvent déduire des données |
| Monero | Confidentialité on-chain par défaut plus forte pour le bénéficiaire, le montant et l'ensemble des expéditeurs | Les liens avec l'exchange, le nœud, le timing, l'endpoint et la contrepartie subsistent |
| Ethereum/stablecoins | Large disponibilité et interopérabilité avec les smart contracts | État/actions publics ; métadonnées RPC ; les émetteurs centralisés peuvent bloquer/geler/signaler |

## Bitcoin : baseline préservant la confidentialité

Bitcoin est pseudonyme, pas anonyme. Les transactions confirmées sont publiques et durables ; la réutilisation d'adresses, la propriété commune des inputs, la détection du change et les adresses publiquement identifiées peuvent former des clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Choisissez un wallet d'auto-conservation maintenu.** Téléchargez-le depuis le projet officiel, vérifiez les signatures/hash lorsqu'ils sont proposés et appliquez les mises à jour de sécurité.
2. **Créez le wallet sur un endpoint de confiance.** Notez la seed de récupération hors ligne ; ne la placez jamais dans un e-mail, un chat, des captures d'écran ou des notes cloud ordinaires. Testez la récupération avant d'y déposer une valeur importante.
3. **Ne gardez en hot wallet que la valeur opérationnelle.** Utilisez une conservation offline/hardware adaptée pour la valeur à long terme, avec un plan de récupération qui n'expose pas la seed à un seul emplacement fragile.
4. **Générez une nouvelle adresse de réception/facture pour chaque transaction.** Ne publiez pas d'adresse statique lorsqu'un serveur de factures ou une remise privée authentifiée est possible.
5. **Utilisez votre propre full node lorsque c'est possible.** Un explorer/serveur electrum tiers peut apprendre les adresses interrogées et les métadonnées IP. Configurez uniquement le comportement Tor/proxy pris en charge par le wallet ; Tor masque un bord du réseau, pas le graphe de la blockchain.
6. **Étiquetez chaque UTXO en privé** avec sa source, son propriétaire, son objectif et son état de conformité. Activez le coin control afin que des contextes d'identité sans rapport ne soient pas dépensés ensemble.
7. **Prévisualisez la transaction :** inputs sélectionnés, destination du change, montant, frais, contrepartie et éventuelle fusion de compartiments par la dépense. Évitez les consolidations inutiles.
8. **Conservez séparément les documents légaux et chiffrez-les.** Préservez la base d'acquisition, les factures, les autorisations et les informations fiscales/déclaratives sans publier la correspondance.
9. **Considérez les dépenses ultérieures comme faisant partie de la même décision de confidentialité.** Une réception correctement séparée peut être reliée lorsque sa sortie est dépensée avec des fonds identifiés.

La documentation de confidentialité de Bitcoin Core explique qu'un full node évite de révéler les requêtes du wallet à des serveurs tiers, mais que la diffusion des transactions et l'historique public nécessitent toujours une analyse.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin est un paiement collaboratif dans lequel le bénéficiaire ajoute un input. Cela contrecarrer l'hypothèse simpliste selon laquelle tous les inputs appartiennent à l'expéditeur. Le BIP 78 décrit le protocole interactif original ; le draft BIP 77 définit une conception v2 asynchrone utilisant une mailbox chiffrée/OHTTP.<sup>[[3]](#references)</sup>

Utilisation sûre :

1. Confirmez que les deux wallets maintenus prennent en charge la même version de PayJoin.
2. Obtenez la facture compatible PayJoin via un canal authentifié ; protégez-la comme toute demande de paiement.
3. Vérifiez le montant et la destination d'origine, puis laissez le wallet valider la proposition/PSBT, la contribution aux frais et les substitutions interdites.
4. Confirmez le résumé final du wallet. N'approuvez pas manuellement une sortie, un montant ou des frais excessifs inattendus.
5. Si la négociation échoue, vérifiez si le wallet revient sans danger à un paiement ordinaire ou exige une nouvelle facture.
6. Conservez les reçus/documents privés nécessaires à la propriété, à la comptabilité et aux litiges.

PayJoin améliore une heuristique d'analyse de chaîne ; il ne masque pas le paiement aux parties, à la plateforme d'acquisition, aux endpoints ou au registre public.

## CoinJoin : avantages et limites

CoinJoin coordonne plusieurs utilisateurs dans une même transaction afin de rendre la correspondance entre inputs et sorties moins certaine. Des recherches sur certaines conceptions historiques de Wasabi et Samourai ont trouvé des transactions très reconnaissables et montré que le comportement avant/après le mixage pouvait réduire considérablement l'anonymat.<sup>[[4]](#references)</sup> Ce résultat ne doit pas être généralisé à chaque implémentation ou version future, mais il montre pourquoi un nombre d'« ensemble d'anonymat » ne constitue pas une garantie.

Avant toute utilisation légale :

- vérifiez le droit local en vigueur, le statut des sanctions, la politique de l'exchange/dépositaire et les obligations fiscales/déclaratives ;
- utilisez un software maintenu et non custodial obtenu auprès de son projet officiel ;
- comprenez le modèle du coordinateur, les frais, les contrôles contre le déni de service et vérifiez si le service actuel fonctionne encore — zkSNACKs a arrêté son coordinateur en 2024, bien que d'autres coordinateurs Wasabi puissent exister ;
- conservez en privé les documents relatifs à l'origine des fonds et aux transactions ;
- n'acceptez jamais des fonds inconnus pour le compte d'une autre personne et n'utilisez pas un « mixer » custodial promettant des retraits intraçables ;
- gardez les sorties séparées par source/contexte et évitez toute consolidation ultérieure qui détruirait l'ambiguïté recherchée.

Les conséquences juridiques dépendent des faits et de la juridiction. Les plaidoyers de culpabilité de Samourai en 2025 concernaient l'exploitation consciente d'un transmetteur de fonds sans licence ayant déplacé des produits criminels ; ils n'établissent pas que toute transaction collaborative ou tout utilisateur recherchant la confidentialité soit criminel.<sup>[[5]](#references)</sup>

## Lightning Network

Le routage onion Sphinx de Lightning est conçu pour qu'un relais intermédiaire connaisse son prédécesseur et son successeur plutôt que l'intégralité de la route.<sup>[[6]](#references)</sup> Il ne s'agit pas d'un anonymat général : le financement/la fermeture des canaux est public, les nœuds annoncent la topologie, les contreparties connaissent les endpoints, le routage/le probing peut déduire les soldes ou les parties, et un wallet custodial voit l'activité du compte de son utilisateur.

Pour une meilleure confidentialité :

1. Préférez un wallet non custodial maintenu si la confidentialité vis-à-vis de l'intermédiaire est importante ; planifiez d'abord la sauvegarde/récupération des canaux.
2. Utilisez une nouvelle facture ou une nouvelle offer pour chaque paiement. Vérifiez si le wallet exact prend en charge BOLT 12/route blinding au lieu de le supposer.
3. Évitez de publier des alias de nœud, coordonnées et endpoints réseau stables inutiles.
4. Connectez-vous via un réseau de confidentialité pris en charge si cela est approprié, en comprenant que les schémas de disponibilité et de timing peuvent toujours être corrélés.
5. Ne déduisez pas qu'un paiement off-chain ne laisse aucune trace : l'expéditeur, le bénéficiaire, les pairs, les watchtowers, les fournisseurs de liquidité et les services de wallet peuvent conserver des observations.

Des recherches publiées ont démontré qu'il était possible de déduire l'expéditeur/le bénéficiaire et le solde des canaux à partir de données publiques et de probing actif, bien que les attaques et les mesures d'atténuation évoluent.<sup>[[7]](#references)</sup>

## Monero

Monero utilise des adresses stealth à usage unique pour les sorties, RingCT pour masquer les montants et des signatures en anneau pour fournir une ambiguïté probabiliste de l'expéditeur ; ses spécifications techniques actuelles indiquent une taille d'anneau de 16 (15 leurres).<sup>[[8]](#references)</sup> Il s'agit de paramètres par défaut plus robustes pour la confidentialité on-chain que ceux des registres transparents, et non d'une protection magique contre les erreurs liées aux endpoints ou aux opérations.

### Workflow légal

1. **Acquérez légalement.** Un exchange réglementé peut connaître l'achat et le retrait même lorsque les détails on-chain ultérieurs sont confidentiels. Conservez les documents relatifs à la source, à la base et aux déclarations.
2. **Installez le wallet officiel maintenu** et vérifiez son téléchargement conformément aux instructions du projet. Sauvegardez la seed hors ligne et testez la restauration avec un petit montant.
3. **Préférez un nœud local** pour une confidentialité maximale des requêtes du wallet. Si cela n'est pas pratique, choisissez un nœud distant de confiance accessible via une configuration onion/I2P officiellement prise en charge. Un nœud distant peut journaliser l'IP, les requêtes, le timing et les identifiants de transaction ; certaines conceptions lightweight divulguent une view key.
4. **Utilisez une nouvelle sous-adresse pour chaque payeur, campagne ou facture.** Un payeur peut corréler l'utilisation répétée de la même sous-adresse.<sup>[[9]](#references)</sup>
5. **Étiquetez localement les contextes entrants.** Évitez de fusionner opérationnellement des réceptions séparées lorsqu'un payeur averti pourrait reconnaître le comportement ultérieur.
6. **Protégez les métadonnées réseau.** Suivez la configuration officielle du réseau d'anonymat ; tenez compte des leaks documentés liés aux timestamps, à la synchronisation intermittente, à la forme de la bande passante et à la réutilisation des flux.<sup>[[10]](#references)</sup>
7. **Conservez privées les données de conformité/audit.** Ne divulguez une view key ou une preuve de transaction que délibérément, à l'auditeur/partie concerné, et comprenez exactement ce qu'elle révèle.

Les études historiques de traçabilité comprennent des bugs et des périodes de sélection des leurres qui ont depuis changé ; n'appliquez pas les anciens pourcentages de réussite aux transactions actuelles. De même, FCMP++ reste un travail de roadmap à la date de référence de recherche de septembre 2026 de ce chapitre, et non une protection déployée.<sup>[[11]](#references)</sup>

## Ethereum et stablecoins

Les ressources d'Ethereum consacrées à la confidentialité indiquent que les actions on-chain sont visibles et que l'infrastructure wallet/RPC ajoute une exposition de l'IP et des métadonnées.<sup>[[12]](#references)</sup> Les transferts de tokens, approbations, interactions avec les smart contracts, services de noms et financements du gas peuvent tous relier des identités.

Les stablecoins centralisés ajoutent le contrôle de l'émetteur. Les conditions actuelles d'USDC et de Tether se réservent le pouvoir de bloquer/geler des adresses ou des actifs et de se conformer aux obligations légales et procédurales.<sup>[[13]](#references)</sup> Ils peuvent être utiles comme instruments de paiement, mais constituent de mauvais choix lorsque l'exigence est la résistance à la censure ou l'anonymat on-chain.

## Limites de conformité

- Les recommandations du FATF sont mises en œuvre par le droit national et évoluent avec le temps ; sa mise à jour de 2026 insiste sur l'octroi de licences/l'enregistrement des VASP et la mise en œuvre de la Travel Rule.<sup>[[14]](#references)</sup>
- Aux États-Unis, FinCEN distingue une personne utilisant une monnaie virtuelle convertible pour ses propres biens/services d'une entreprise qui l'accepte et la transmet ou l'échange ; les faits et les règles ultérieures sont importants.<sup>[[15]](#references)</sup>
- Le règlement européen sur les transferts de fonds exige les informations relatives à l'initiateur/au bénéficiaire lorsqu'un prestataire de services sur crypto-actifs intervient et ajoute des règles de vérification pour certains transferts depuis/vers des adresses auto-hébergées.<sup>[[16]](#references)</sup>
- Les sanctions et obligations fiscales continuent de s'appliquer. Effectuez les vérifications requises, refusez les parties interdites et conservez les documents ; les listes et le statut juridique peuvent changer rapidement.<sup>[[17]](#references)</sup>

Avant toute opération impliquant une valeur importante, une activité transfrontalière, une coordination améliorant la confidentialité ou un échange/une transmission de nature commerciale, obtenez un conseil professionnel à jour pour les juridictions concernées.

Pour Bitcoin Silent Payments, Zcash entièrement shielded, GNU Taler, l'e-cash Chaumian fédéré et BOLT 12, consultez [Protocoles de paiement préservant la confidentialité](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Protégez votre confidentialité](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Fonctionnalités de confidentialité](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Proposition Payjoin simple](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoption et confidentialité réelle des implémentations CoinJoin décentralisées dans Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Les fondateurs de Samourai Wallet plaident coupable (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocole de routage Onion](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Analyse empirique de la confidentialité dans le Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Projet Monero — [Adresses stealth](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Signatures en anneau](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) et [Spécifications techniques](https://docs.getmonero.org/technical-specs/)
- [9] [Documentation Monero — Sous-adresse](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Documentation Monero — Réseaux](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad et Victor — Étude de l'évolution de la confidentialité de Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Confidentialité sur Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Conditions USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Mise à jour ciblée 2026 sur les actifs virtuels et les VASP](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Application des réglementations de FinCEN aux personnes administrant, échangeant ou utilisant des monnaies virtuelles](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Règlement (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Guide de conformité aux sanctions pour le secteur des monnaies virtuelles](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
