# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** s'appuient sur les Smart Contracts, avec un front-end convivial et un back-end transparent et auditable.
- **Tokens & Coins** : les coins servent de monnaie numérique, tandis que les tokens représentent de la valeur ou un droit de propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et **Security Tokens** représentent la propriété d'un actif.
- **DeFi** signifie Decentralized Finance (finance décentralisée), offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** se réfèrent respectivement à Decentralized Exchange Platforms et Decentralized Autonomous Organizations.

## Mécanismes de consensus

Les mécanismes de consensus assurent des validations de transactions sécurisées et consensuelles sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent un certain montant de tokens, réduisant la consommation d'énergie comparée au PoW.

## Fondamentaux de Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier un transfert.

#### Composants clés :

- **Multisignature Transactions** nécessitent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent d'**inputs** (source des fonds), d'**outputs** (destination), de **fees** (payés aux mineurs) et de **scripts** (règles de transaction).

### Lightning Network

Le Lightning Network vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un channel, ne diffusant sur la blockchain que l'état final.

## Problèmes de confidentialité de Bitcoin

Les attaques de confidentialité, comme **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les motifs de transaction. Des stratégies telles que **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquisition de Bitcoins de façon anonyme

Les méthodes incluent les échanges en espèces, le mining et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguises les CoinJoins en transactions ordinaires pour accroître la confidentialité.

# Attaques de confidentialité sur Bitcoin

# Résumé des attaques de confidentialité sur Bitcoin

Dans l'univers de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent sources d'inquiétude. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant d'utilisateurs différents soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses en tant qu'inputs dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si une partie seulement est envoyée à une autre adresse, le reste est envoyé vers une nouvelle change address. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Exemple

Pour atténuer cela, les services de mixing ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Social Networks & Forums Exposure**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui facilite le lien entre l'adresse et son propriétaire.

## **Transaction Graph Analysis**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs basées sur les flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique repose sur l'analyse de transactions avec plusieurs inputs et outputs pour deviner quel output est la change retournant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plus d'inputs fait que la sortie change est plus grande que n'importe quel input individuel, cela peut perturber l'heuristique.

## **Forced Address Reuse**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d'autres inputs dans des transactions futures, liant ainsi les adresses entre elles.

### Correct Wallet Behavior

Les Wallets doivent éviter d'utiliser des coins reçus sur des adresses déjà utilisées et vides pour prévenir cette privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts :** Les transactions sans change sont probablement entre deux adresses appartenant au même utilisateur.
- **Round Numbers :** Un nombre rond dans une transaction suggère un paiement, la sortie non ronde étant probablement le change.
- **Wallet Fingerprinting :** Différents wallets ont des patterns uniques de création de transaction, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Amount & Timing Correlations :** Révéler les heures ou montants des transactions peut rendre les transactions traçables.

## **Traffic Analysis**

En surveillant le trafic réseau, les attaquants peuvent potentiellement lier des transactions ou des blocs à des adresses IP, compromettant la vie privée des utilisateurs. C'est particulièrement vrai si une entité opère de nombreux nœuds Bitcoin, augmentant sa capacité à surveiller les transactions.

## More

Pour une liste complète des privacy attacks et defenses, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions** : Acquérir des bitcoin en espèces.
- **Cash Alternatives** : Acheter des gift cards et les échanger en ligne contre des bitcoin.
- **Mining** : La méthode la plus privée pour gagner des bitcoins est le mining, surtout lorsqu'il est effectué en solo parce que les mining pools peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft** : Théoriquement, voler du bitcoin pourrait être une autre méthode pour l'obtenir anonymement, bien que ce soit illégal et non recommandé.

## Mixing Services

En utilisant un mixing service, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend difficile de retracer le propriétaire originel. Pourtant, cela nécessite de faire confiance au service pour qu'il ne conserve pas de logs et qu'il rende effectivement les bitcoins. Des alternatives de mixing incluent les casinos Bitcoin.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant le travail de quiconque tente d'apparier inputs et outputs. Malgré son efficacité, les transactions avec des tailles d'input et d'output uniques peuvent toujours être potentiellement tracées.

Des transactions exemples qui ont pu utiliser CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), déguisе la transaction entre deux parties (par ex. un customer et un merchant) en une transaction ordinaire, sans les outputs égaux caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et peut invalider l'heuristique common-input-ownership utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Des transactions comme celles ci‑dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes de surveillance traditionnelles**, en faisant une avancée prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour la confidentialité dans les cryptomonnaies

## **Wallet Synchronization Techniques**

Pour préserver la confidentialité et la sécurité, synchroniser les portefeuilles avec la blockchain est crucial. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l'entièreté de la blockchain, un full node garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres, ne récupérant les blocs complets que lorsqu'un filtre correspond aux adresses de l'utilisateur.

## **Utilizing Tor for Anonymity**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, l'utilisation de Tor est recommandée pour masquer votre adresse IP, améliorant la confidentialité lors des interactions avec le réseau.

## **Preventing Address Reuse**

Pour protéger la confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation d'adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les portefeuilles modernes découragent la réutilisation d'adresses par leur conception.

## **Strategies for Transaction Privacy**

- **Multiple transactions** : Fractionner un paiement en plusieurs transactions peut obscurcir le montant, contrant les attaques visant la confidentialité.
- **Change avoidance** : Choisir des transactions qui n'exigent pas de change outputs renforce la confidentialité en perturbant les méthodes de détection du change.
- **Multiple change outputs** : Si éviter le change n'est pas possible, générer plusieurs change outputs peut néanmoins améliorer la confidentialité.

# **Monero: A Beacon of Anonymity**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée pour la confidentialité.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Le Gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique une gas limit et une base fee, avec un tip pour inciter les mineurs. Les utilisateurs peuvent définir un max fee pour s'assurer de ne pas trop payer, l'excédent étant remboursé.

## **Executing Transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses utilisateur ou des adresses de smart contract. Elles requièrent des frais et doivent être minées. Les informations essentielles d'une transaction comprennent le destinataire, la signature de l'expéditeur, la valeur, des données optionnelles, la gas limit et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, ce qui évite de l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite interagir avec les cryptomonnaies tout en privilégiant la confidentialité et la sécurité.

## Value-Centric Web3 Red Teaming

- Inventorier les composants porteurs de valeur (signers, oracles, bridges, automation) pour comprendre qui peut déplacer des fonds et comment.
- Mapper chaque composant aux tactiques MITRE AADAPT pertinentes pour exposer des chemins d'escalade de privilèges.
- Répéter des chaînes d'attaques flash-loan/oracle/credential/cross-chain pour valider l'impact et documenter les préconditions exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing pour trouver les angles morts dans les suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Références

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
