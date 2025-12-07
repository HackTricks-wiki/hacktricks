# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution des accords sans intermédiaires.
- **Decentralized Applications (dApps)** s'appuient sur les smart contracts, avec une interface frontale conviviale et un back-end transparent et auditable.
- **Tokens & Coins** distinguent où les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
- **Utility Tokens** accordent l'accès à des services, et **Security Tokens** signifient la propriété d'un actif.
- **DeFi** signifie Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** se réfèrent respectivement aux Decentralized Exchange Platforms et Decentralized Autonomous Organizations.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et convenue des transactions sur la blockchain :

- **Proof of Work (PoW)** s'appuie sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, réduisant la consommation d'énergie par rapport au PoW.

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le détenteur de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** nécessitent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent de **inputs** (source des fonds), **outputs** (destination), **fees** (payés aux miners), et **scripts** (règles de transaction).

### Lightning Network

A pour objectif d'améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un channel, ne diffusant que l'état final sur la blockchain.

## Problèmes de confidentialité de Bitcoin

Les attaques contre la confidentialité, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les motifs des transactions. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquérir des Bitcoins anonymement

Les méthodes incluent les échanges en espèces, le mining, et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguise les CoinJoins en transactions ordinaires pour une confidentialité accrue.

# Attaques de confidentialité Bitcoin

# Résumé des attaques de confidentialité contre Bitcoin

Dans le monde de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité sur Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **on suppose souvent que deux adresses input présentes dans la même transaction appartiennent au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, or **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'envoyeur, compromettant la confidentialité.

### Exemple

Pour atténuer cela, les services de mixing ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition sur les réseaux sociaux & forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile l'association de l'adresse à son propriétaire**.

## **Analyse du graphe de transactions**

Les transactions peuvent être visualisées sous forme de graphes, révélant des liens potentiels entre utilisateurs basés sur le flux des fonds.

## **Heuristique des entrées inutiles (Optimal Change Heuristic)**

Cette heuristique se base sur l'analyse de transactions comportant plusieurs entrées et sorties pour deviner quelle sortie est la sortie de change revenant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plusieurs entrées fait que la sortie de change devient plus grande que n'importe quelle entrée individuelle, cela peut perturber l'heuristique.

## **Réutilisation forcée d'adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d'autres entrées dans des transactions futures, liant ainsi les adresses entre elles.

### Comportement correct du wallet

Les wallets devraient éviter d'utiliser des coins reçus sur des adresses déjà utilisées et vides pour prévenir ce privacy leak.

## **Autres techniques d'analyse de la blockchain**

- **Montants de paiement exacts :** Les transactions sans change sont probablement entre deux adresses appartenant au même utilisateur.
- **Nombres ronds :** Un nombre rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement la sortie de change.
- **Empreinte des wallets :** Différents wallets ont des schémas uniques de création de transactions, ce qui permet aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Corrélations montant et horaire :** La divulgation des heures ou des montants des transactions peut les rendre traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, des attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant la vie privée des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, améliorant sa capacité à surveiller les transactions.

## En savoir plus

Pour une liste complète des attaques et défenses en matière de confidentialité, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d'obtenir des Bitcoins anonymement

- **Transactions en espèces :** Acquérir des bitcoins en espèces.
- **Alternatives au cash :** Acheter des cartes-cadeaux et les échanger en ligne contre du bitcoin.
- **Minage :** La méthode la plus privée pour gagner des bitcoins est le minage, surtout en solo car les mining pools peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol :** Théoriquement, voler des bitcoins pourrait être une autre méthode pour les obtenir anonymement, bien que ce soit illégal et déconseillé.

## Services de mixing

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend difficile de retracer le propriétaire initial. Toutefois, cela nécessite de faire confiance au service pour qu'il ne conserve pas de logs et qu'il rende effectivement les bitcoins. Des alternatives de mixing incluent les casinos Bitcoin.

## CoinJoin

CoinJoin combine plusieurs transactions de différents utilisateurs en une seule, compliquant le travail de quiconque tente d'associer des entrées avec des sorties. Malgré son efficacité, des transactions avec des tailles d'entrée et de sortie uniques peuvent encore potentiellement être retracées.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), dissimule la transaction entre deux parties (par ex., un client et un commerçant) en la présentant comme une transaction normale, sans les sorties égales distinctives caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider la common-input-ownership heuristic utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Des transactions comme ci‑dessus pourraient être PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber de façon significative les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse pour la confidentialité des transactions.

# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Techniques de synchronisation de portefeuilles**

Pour préserver la confidentialité et la sécurité, synchroniser les portefeuilles avec la blockchain est crucial. Deux méthodes se distinguent :

- **Full node**: En téléchargeant l'intégralité de la blockchain, un Full node assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering**: Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utiliser Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, il est recommandé d'utiliser Tor pour masquer votre adresse IP, renforçant la confidentialité lors des interactions avec le réseau.

## **Éviter la réutilisation d'adresses**

Pour protéger la confidentialité, il est vital d'utiliser une nouvelle adresse pour chaque transaction. Réutiliser des adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les portefeuilles modernes découragent la réutilisation des adresses par conception.

## **Stratégies pour la confidentialité des transactions**

- **Multiple transactions**: Diviser un paiement en plusieurs transactions peut obscurcir le montant de la transaction, contrecarrant les attaques visant la vie privée.
- **Change avoidance**: Opter pour des transactions qui n'exigent pas de change outputs améliore la confidentialité en perturbant les méthodes de détection de change.
- **Multiple change outputs**: Si éviter le change n'est pas réalisable, générer plusieurs change outputs peut quand même améliorer la confidentialité.

# **Monero : un phare de l'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée en matière de confidentialité.

# **Ethereum : Gas et transactions**

## **Comprendre le Gas**

Le Gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0,00231 ETH) implique une gas limit et une base fee, avec un tip pour inciter les mineurs. Les utilisateurs peuvent fixer un max fee pour s'assurer de ne pas trop payer ; l'excédent est remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses utilisateur ou des smart contract. Elles nécessitent des frais et doivent être minées. Les informations essentielles d'une transaction comprennent le destinataire, la signature de l'expéditeur, la valeur, des données optionnelles, le gas limit et les fees. Notamment, l'adresse de l'expéditeur est dérivée de la signature, ce qui évite son inclusion dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour toute personne souhaitant interagir avec les cryptomonnaies tout en priorisant la confidentialité et la sécurité.

## Smart Contract Security

- Mutation testing pour trouver des angles morts dans les suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

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
