# Techniques d’obfuscation financière

La confidentialité des paiements relève de l’attribution, et non de la marque de paiement. Une opération laisse des preuves lorsque la valeur est acquise, déplacée, convertie, dépensée et livrée. Une adresse sur une chaîne publique peut être pseudonyme, tandis qu’un exchange, un émetteur de carte, un commerçant, un appareil mobile ou une caméra d’expédition identifie la personne qui se cache derrière.

Cette page explique les patterns d’obfuscation financière utilisés dans la cybercriminalité et les opérations liées à des États, afin que les défenseurs puissent les reconnaître. Elle ne fournit pas de procédure de blanchiment, de contournement des sanctions, de fausse identité ou de KYC-bypass.

## Le graphe de valeur de bout en bout
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Un acteur tente d’empêcher tout observateur de voir les deux extrémités. Les enquêteurs font l’inverse : ils préservent les enregistrements à chaque frontière, normalisent le temps, la valeur et les frais, puis identifient le **point de reconvergence** où des personas distinctes réutilisent un même facilitateur, appareil, compte, commerçant ou destination.

## Instruments et leurs véritables observateurs

| Instrument | Masqué au commerçant/public | Reste visible pour |
|---|---|---|
| Carte virtuelle/token de l’émetteur | numéro de carte sous-jacent | émetteur, réseau/fournisseur de token, wallet, compte commerçant et systèmes de livraison |
| Valeur prépayée/cadeau | parfois le nom légal lors d’un achat ordinaire | détaillant/rail de paiement, service d’activation/échange, caméras, appareil et livraison |
| Espèces | registre public et émetteur distant | contreparties, caméras, contrôles des retraits/séries lorsqu’ils s’appliquent, fouille physique |
| Bitcoin/nouvelle adresse | nom légal direct | tout observateur de la blockchain ; pairs du wallet/réseau ; services d’acquisition/de sortie |
| CoinJoin/PayJoin | heuristiques simples des entrées communes/de paiement | transaction publique, métadonnées du coordinateur/pair/réseau et comportement de dépense ultérieur |
| Privacy coin | expéditeur/destinataire/montant publics, selon le protocole | acquisition/sortie, endpoint du wallet, observateur réseau et contrepartie |
| Centralized mixer | lien direct entre dépôt et retrait | opérateur/journaux du mixer, ensembles d’entrée/sortie de la blockchain et contreparties |
| Bridge/swap cross-chain | continuité sur une seule chaîne | les deux chaînes, service de bridge/swap, contraintes de temps/valeur et de liquidité |
| Courtier OTC/P2P | compte d’échange direct dans certains cas | courtier, communications, mouvements bancaires/d’espèces, contreparties et appareils |

## Cartes, valeur prépayée, prête-noms et mules

### Cartes virtuelles et masquées

Un émetteur peut créer un numéro de carte limité à un commerçant ou à usage unique. Cela réduit l’exposition du commerçant et la réutilisation du numéro entre commerçants. L’émetteur le relie toujours au client, au compte de financement, à l’appareil, à l’adresse IP et à la transaction. Les libellés de facturation, le compte commerçant, l’adresse d’expédition et les données du navigateur restent corrélables.

La promotion de cartes « sans nom » n’implique pas un règlement anonyme. Les émetteurs et distributeurs réglementés peuvent effectuer des contrôles d’identité, conserver des enregistrements, imposer des limites géographiques/de montant et répondre aux demandes légales. Une carte obtenue au moyen d’une identité volée constitue un vol d’identité ; elle ne supprime pas les données de télémétrie de l’émetteur, de l’appareil et du commerçant.

### Valeur prépayée et cartes-cadeaux

Les cartes prépayées et les codes-cadeaux séparent un échange ultérieur de l’instrument de paiement initial, mais créent un objet numéroté avec des événements d’achat, d’activation, de consultation du solde et d’échange. Les schémas importants comprennent les achats en volume, les dénominations répétées juste en dessous des contrôles, un échange rapide à distance, un appareil consultant les soldes de nombreuses cartes, ou de nombreuses cartes convergeant vers un même commerçant/compte.

### Prête-noms, mules financières et façades commerciales

Un prête-nom ou une mule fournit un compte et une identité légale qui s’interposent entre l’opérateur et un service. Les réseaux peuvent superposer recruteurs, titulaires de comptes, processeurs de paiement, commerçants-écrans et courtiers de retrait. Cela crée une distance, mais chaque participant ajoute des communications, des frais, des incohérences comportementales et un témoin potentiel susceptible de coopérer. Les sociétés-écrans ajoutent des registres de constitution, fiscaux, bancaires, de dirigeants, de factures, d’hébergement et d’expédition.

Les défenseurs devraient examiner les appareils/adresses IP partagés, la réutilisation des bénéficiaires, les contradictions de géolocalisation, une vélocité incohérente avec l’historique du compte, les transferts circulaires, plusieurs expéditeurs sans lien convergeant, ainsi que les mouvements sortants immédiats. Ne supposez pas que le titulaire nommé du compte est l’acteur qui le contrôle ; traitez-le comme un nœud dont le rôle doit être déterminé.

## Schémas d’obfuscation des transactions sur une chaîne publique

### Rotation des adresses et Coin control

Créer une nouvelle adresse pour chaque réception empêche la simple réutilisation d’adresse, mais les transactions peuvent toujours être rattachées par les entrées communes, la détection de la monnaie rendue, la valeur exacte et le temps, ainsi que par une consolidation ultérieure. **Coin control** permet à un wallet de choisir les outputs à dépenser et d’éviter de réunir des compartiments. Cela améliore l’hygiène ; cela ne peut pas supprimer un lien déjà public.

### Peel chains

Une Peel chain dépense à plusieurs reprises un solde important, en envoyant un montant plus faible vers l’extérieur et en renvoyant le reste vers une nouvelle adresse :
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
L’adresse change à chaque étape, mais la continuité de la valeur, la cadence et la structure des transactions forment souvent une chaîne reconnaissable. Les hot wallets légitimes d’exchanges peuvent se comporter de manière similaire ; l’attribution nécessite donc des éléments de preuve liés au service et au contexte. Le DOJ a utilisé l’analyse des peel-chains dans des affaires de confiscation liées à la RPDC.<sup>[[1]](#references)</sup>

### Structuring et fan-out/fan-in

- **Fan-out :** une source se divise entre de nombreuses adresses afin d’augmenter la charge de travail de l’enquête ou de préparer une conversion parallèle.
- **Fan-in :** de nombreuses sources se regroupent vers un collecteur unique, révélant un contrôle commun ou un service.
- **Structuring :** des transferts répétés de faible montant cherchent à éviter les seuils de contrôle ou à se fondre dans un volume ordinaire.
- **Commingling :** des fonds illicites et sans lien partagent des wallets, des pools ou des services, ce qui rend risquées les conclusions proportionnelles simplistes.

La forme du graphe constitue un indice, pas une preuve. Les analystes doivent tenir compte des frais, du modèle UTXO/account, du comportement du service et des conventions de change.

### CoinJoin et PayJoin

Dans un CoinJoin classique, plusieurs participants fournissent des inputs et reçoivent des outputs dans une transaction collaborative, souvent avec des dénominations d’outputs identiques. Cela invalide l’hypothèse selon laquelle chaque input et chaque output d’une transaction appartient à un seul propriétaire. L’anonymity set est limité par le nombre de participants et par les comportements ultérieurs : change inégal, toxic change, consolidation ou passage par un service connu peuvent réintroduire des liens.

PayJoin modifie un paiement ordinaire afin que le payeur et le bénéficiaire fournissent tous deux des inputs, invalidant directement l’heuristique de propriété commune des inputs pour cette transaction. Il s’agit principalement d’un protocole de confidentialité des paiements, et non d’un service de laundering à grande échelle. La détection doit éviter de déclarer que tous les inputs appartiennent au même propriétaire et doit exprimer l’incertitude plutôt que d’imposer un faux cluster.

### Mixers et tumblers centralisés

Un mixer centralisé accepte des dépôts, puis verse ultérieurement des coins différents depuis une réserve mutualisée, souvent après application de frais et de délais. Sa confidentialité dépend de la taille du pool, de la politique de retrait, des logs, de l’honnêteté de l’opérateur et de sa résistance à la saisie. L’analyse des horaires et des valeurs d’entrée et de sortie, des adresses de dépôt, du clustering des wallets du service et des données conservées peut réduire l’ensemble des possibilités. Les opérateurs peuvent voler les fonds ou conserver une correspondance complète.

L’exposition juridique est importante et dépend de la juridiction. Les affaires du DOJ contre ChipMixer, Samourai Wallet ainsi que les développeurs et opérateurs de Tornado Cash, et l’évolution du contentieux relatif aux sanctions, montrent que les faits liés au protocole, à la garde, au contrôle et à la transmission monétaire sont déterminants ; l’étiquette « décentralisé » ne constitue pas une conclusion juridique.<sup>[[2]](#references)</sup>

### Chain hopping, swaps et bridges

Le chain hopping convertit un asset ou le fait transiter par un bridge, interrompant une requête sur un seul ledger, mais pas la continuité économique :
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Les analystes corrèlent les contrats de bridge/adresses de dépôt des services, l’ordre des transactions, la fenêtre temporelle, le taux de change, les frais, la liquidité et les montants uniques. Des swaps répétés peuvent accroître l’ambiguïté tout en ajoutant la télémétrie des fournisseurs, des API et des wallets. Le FATF identifie spécifiquement le chain hopping, les mixers, les services peer-to-peer et les monnaies renforçant l’anonymat comme des indicateurs de risque lorsqu’ils sont associés à un contexte suspect.<sup>[[3]](#references)</sup>

### NFTs, jeux d’argent et achats auprès de commerçants

Les transactions NFT avec auto-achat ou collusion peuvent donner aux fonds une apparence de vente légitime ; les jeux d’argent peuvent échanger des dépôts contre des retraits ; les biens peuvent convertir une valeur numérique en inventaire revendable. Ces voies laissent des comptes de marketplace, des liens avec les créateurs et les royalties, des graphes de wash-trading, l’historique des cotes et des parties, des journaux d’appareils, ainsi que des éléments de livraison et de revente. Une perte ou des frais ne prouvent pas que la provenance a disparu.

## Cryptomonnaies préservant la confidentialité

Les privacy protocols diffèrent techniquement :

- **Monero** utilise des adresses à usage unique, des ring signatures et des montants confidentiels, réduisant la visibilité publique de l’expéditeur, du destinataire et du montant. L’observation du réseau, la compromission du wallet, l’acquisition/off-ramp et les données des contreparties restent en dehors de ces protections on-chain.
- Les **shielded pools de Zcash** peuvent dissimuler l’expéditeur, le destinataire et le montant lorsque des transactions shielded sont utilisées ; les adresses transparentes et les transitions entre pools restent publiques, et les habitudes d’utilisation affectent la taille effective de l’ensemble d’anonymat.
- **Bitcoin** est transparent par défaut. Les nouvelles adresses, CoinJoin, PayJoin et Lightning modifient certaines hypothèses de liaison, mais ne rendent pas toutes les couches privées.

La privacy technology a des usages légitimes en matière de sécurité et d’activité commerciale. Du point de vue de l’enquête, lorsque le ledger fournit moins d’informations, les éléments liés aux endpoints, aux services, au réseau et aux personnes deviennent plus importants. Ne déduisez jamais la criminalité du seul choix d’un privacy protocol.

## Modèle de cas multi-couches de la DPRK

Les allégations publiques du DOJ et les actions en confiscation décrivent un processus composé, et non une seule astuce :<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. des travailleurs ont utilisé des documents d’identité fictifs ou volés et des VPN pour obtenir des emplois à distance ;
2. les employeurs ont payé en cryptomonnaie, notamment en stablecoins ;
3. les fonds ont circulé en montants plus faibles, ont traversé différentes chains ou différents tokens, ont servi à acheter des NFTs ou ont été mélangés ;
4. d’autres fonds volés sont entrés dans des mixers ;
5. des traders OTC et des sociétés-écrans ont converti la valeur en paiements fiat ou en biens ;
6. la répétition des facilitateurs, des comptes et des chemins blockchain a permis aux enquêteurs de reconnecter les couches.

Le Treasury a déclaré que Lazarus avait utilisé Blender.io pour traiter une partie du vol d’Axie Infinity/Ronin, tandis que le FBI a publié des adresses et exhorté les bridges, les exchanges, les opérateurs RPC et les entreprises d’analytics à bloquer les fonds liés à des vols ultérieurs de TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

La leçon est bidirectionnelle : les acteurs étatiques utilisent des services commerciaux/criminels ordinaires, et les blockchains publiques permettent aux défenseurs de suivre la valeur même lorsque les noms sont initialement inconnus.

## Workflow de détection

1. **Préservez les identifiants et les enregistrements bruts des transactions.** Les captures d’écran et les valeurs fiat arrondies sont insuffisantes.
2. **Normalisez les actifs et le temps.** Enregistrez la chain, le contrat du token, les unités, l’heure du bloc, le fuseau horaire du service, les frais et la source du taux de change.
3. **Indiquez le niveau de confiance des éléments.** Distinguez une adresse publiée par un service, un événement de contrat déterministe, une heuristique de clustering et des renseignements externes.
4. **Suivez les deux directions.** Recherchez l’origine du financement, la dispersion immédiate, la reconvergence, les sorties de bridge, les dépôts auprès de services et les dépenses/livraisons.
5. **Joignez les éléments off-chain.** Les données KYC des comptes, des appareils, des IP, des tickets de support, des clés API, des banques/paiements, des expéditions et des communications résolvent souvent l’ambiguïté.
6. **Testez les explications alternatives.** Les exchanges, les custodians, la paie et les privacy protocols peuvent produire des fan-in/out ou des co-spends sans propriété bénéficiaire commune.
7. **Surveillez plutôt que de conclure prématurément.** Un output dormant peut devenir attribuable lorsqu’il atteint ultérieurement un service.
8. **Appliquez les obligations actuelles en matière de sanctions/AML avec l’aide d’un conseil juridique.** Les règles et les désignations évoluent ; une association historique ne remplace pas une analyse juridique actuelle.

## Modèle d’approvisionnement safe red-team

Une équipe autorisée peut avoir besoin que le SOC cible ne reconnaisse pas le paiement de son hébergement, tandis que le responsable de l’engagement conserve la responsabilité :

- utilisez une carte d’organisation dédiée à l’engagement ou un wallet corporate documenté ;
- conservez des informations exactes de facturation, fiscales et relatives au fournisseur ;
- séparez l’opérateur des tâches d’approvisionnement et limitez l’accès à la cartographie d’attribution ;
- n’utilisez jamais de mule, de fausse identité, de carte volée, de contournement de sanctions ou d’exchange sans licence ;
- consignez l’actif, le montant, le propriétaire, le service, la date, le chemin de remboursement et les éléments de teardown ;
- communiquez au responsable les indicateurs pertinents de paiement/fournisseur après l’exercice.

Cela crée une **absence de visibilité sur le participant à l’exercice**, et non une absence de visibilité pour la loi, le fournisseur ou la gouvernance.

## References

- [1] [US DOJ — Cadre de lutte contre l’application criminelle des règles relatives aux cryptomonnaies (exemple de peel-chain et enquêtes sur la DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Démantèlement de ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indicateurs de signaux d’alerte liés aux Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Représentant de la Foreign Trade Bank de la DPRK inculpé dans des conspirations de crypto-laundering](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Plainte en confiscation concernant 7,74 millions de dollars prétendument blanchis pour la DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanctions contre Blender.io et fonds de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — La Corée du Nord est responsable du vol de Bybit en 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application des réglementations aux utilisateurs, administrateurs et exchangers de virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
