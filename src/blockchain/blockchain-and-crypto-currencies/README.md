# Blockchain et Crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** reposent sur les smart contracts, offrant un front-end convivial et un back-end transparent et auditable.
- **Tokens & Coins** font la distinction entre coins servant de monnaie numérique, tandis que les tokens représentent de la valeur ou la propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et **Security Tokens** représentent la propriété d'actifs.
- **DeFi** signifie Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** désignent respectivement Decentralized Exchange Platforms et Decentralized Autonomous Organizations.

## Mécanismes de consensus

Les mécanismes de consensus assurent des validations de transaction sûres et consensuelles sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, réduisant la consommation d'énergie comparé au PoW.

## Essentiels de Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées via des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** requièrent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent d'**inputs** (source des fonds), d'**outputs** (destination), de **fees** (payés aux miners) et de **scripts** (règles de la transaction).

### Lightning Network

Le Lightning Network vise à améliorer l'évolutivité de Bitcoin en permettant plusieurs transactions au sein d'un canal, n'en diffusant que l'état final sur la blockchain.

## Problèmes de confidentialité de Bitcoin

Les attaques contre la confidentialité, comme **Common Input Ownership** et **UTXO Change Address Detection**, exploitent des motifs de transaction. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquérir des Bitcoins de manière anonyme

Les méthodes incluent les échanges en espèces, le mining et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguise les CoinJoins en transactions ordinaires pour une confidentialité renforcée.

# Attaques de confidentialité Bitcoin

# Résumé des attaques de confidentialité Bitcoin

Dans l'univers de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses en input dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, or Unspent Transaction Output, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle change address. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Exemple

Pour atténuer cela, les services de mixing ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition via réseaux sociaux et forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile de lier l'adresse à son propriétaire**.

## **Analyse du graphe de transactions**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs basées sur le flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique se base sur l'analyse des transactions avec plusieurs inputs et outputs pour deviner quel output est le change retournant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plusieurs entrées rend la sortie de change plus grande que n'importe quelle entrée individuelle, cela peut perturber l'heuristique.

## **Forced Address Reuse**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d'autres entrées dans de futures transactions, liant ainsi les adresses entre elles.

### Comportement correct des portefeuilles

Les portefeuilles doivent éviter d'utiliser les coins reçus sur des adresses déjà utilisées et vides afin de prévenir cette privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Les transactions sans change sont probablement entre deux adresses appartenant au même utilisateur.
- **Round Numbers:** Un montant rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement le change.
- **Wallet Fingerprinting:** Différents wallets ont des schémas uniques de création de transactions, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Amount & Timing Correlations:** La divulgation des heures ou des montants de transaction peut rendre les transactions traçables.

## **Traffic Analysis**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant la vie privée des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, augmentant sa capacité à surveiller les transactions.

## Plus

Pour une liste complète des attaques et des défenses en matière de vie privée, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions:** Acquérir des bitcoins en espèces.
- **Cash Alternatives:** Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining:** La méthode la plus privée pour gagner des bitcoins est le mining, surtout en solo, car les mining pools peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft:** Théoriquement, voler des bitcoins pourrait être une autre méthode pour les acquérir anonymement, bien que ce soit illégal et non recommandé.

## Mixing Services

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend difficile le traçage du propriétaire initial. Cependant, cela exige de faire confiance au service pour qu'il ne conserve pas de logs et qu'il rende effectivement les bitcoins. Des alternatives de mixage incluent les casinos Bitcoin.

## CoinJoin

CoinJoin fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant le travail de quiconque tente d'associer entrées et sorties. Malgré son efficacité, les transactions avec des tailles d'entrées et de sorties uniques peuvent encore potentiellement être tracées.

Des transactions exemples qui ont pu utiliser CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant des mineurs.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), dissimule la transaction entre deux parties (par ex. un client et un commerçant) en la présentant comme une transaction ordinaire, sans les sorties égales distinctives caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider la common-input-ownership heuristic utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Les transactions comme celle ci‑dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes de surveillance traditionnelles**, en faisant une évolution prometteuse dans la recherche de la confidentialité des transactions.

# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Techniques de synchronisation de portefeuille**

Pour préserver la confidentialité et la sécurité, la synchronisation des portefeuilles avec la blockchain est cruciale. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l'intégralité de la blockchain, un full node assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres, ne récupérant les blocs complets que lorsqu'une correspondance est trouvée avec les adresses de l'utilisateur.

## **Utiliser Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau pair-à-pair, il est recommandé d'utiliser Tor pour masquer votre adresse IP, renforçant la confidentialité lors des interactions avec le réseau.

## **Éviter la réutilisation d'adresses**

Pour protéger la confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation d'adresses peut compromettre la confidentialité en liant des transactions à la même entité. Les portefeuilles modernes découragent la réutilisation d'adresses par conception.

## **Stratégies pour la confidentialité des transactions**

- **Multiples transactions** : Diviser un paiement en plusieurs transactions peut obscurcir le montant de la transaction, contrant les attaques visant la confidentialité.
- **Éviter les sorties de change** : Opter pour des transactions n'exigeant pas de sorties de change améliore la confidentialité en perturbant les méthodes de détection de change.
- **Multiples sorties de change** : Si éviter le change n'est pas faisable, générer plusieurs sorties de change peut tout de même améliorer la confidentialité.

# **Monero : un phare d'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée en matière de confidentialité.

# **Ethereum : Gas et transactions**

## **Comprendre le gas**

Le gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) implique une gas limit et une base fee, avec un tip pour inciter les mineurs. Les utilisateurs peuvent définir un max fee pour s'assurer de ne pas surpayer ; l'excédent est remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses utilisateur ou des smart contracts. Elles nécessitent des frais et doivent être minées. Les informations essentielles d'une transaction incluent le destinataire, la signature de l'expéditeur, la valeur, les données optionnelles, la gas limit et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, ce qui élimine la nécessité de l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite interagir avec les cryptomonnaies tout en privilégiant la confidentialité et la sécurité.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

{{#include ../../banners/hacktricks-training.md}}
