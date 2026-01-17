# Blockchain et Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** reposent sur les smart contracts, avec une interface front-end conviviale et un back-end transparent et auditable.
- **Tokens & Coins** font la distinction entre les coins servant de monnaie numérique, tandis que les tokens représentent de la valeur ou la propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et **Security Tokens** signifient la propriété d'actifs.
- **DeFi** signifie Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** désignent respectivement Decentralized Exchange Platforms et Decentralized Autonomous Organizations.

## Mécanismes de consensus

Les mécanismes de consensus garantissent des validations de transactions sécurisées et acceptées sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, réduisant la consommation d'énergie par rapport au PoW.

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées via des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** requièrent plusieurs signatures pour autoriser une transaction.
- Les transactions sont constituées d'**inputs** (source des fonds), d'**outputs** (destination), de **fees** (payées aux mineurs) et de **scripts** (règles de transaction).

### Lightning Network

Le Lightning Network vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions à l'intérieur d'un canal, ne diffusant à la blockchain que l'état final.

## Problèmes de confidentialité de Bitcoin

Les attaques contre la confidentialité, comme **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les schémas de transaction. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquérir des Bitcoins de façon anonyme

Les méthodes incluent des échanges en espèces, le mining et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguise les CoinJoins en transactions ordinaires pour une confidentialité accrue.

# Attaques de confidentialité Bitcoin

# Résumé des attaques de confidentialité sur Bitcoin

Dans l'univers de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent sujets à préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité sur Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses input dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si une partie seulement est envoyée à une autre adresse, le reste est renvoyé vers une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Exemple

Pour atténuer cela, les services de mixing ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition sur les réseaux sociaux et forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile de lier l'adresse à son propriétaire**.

## **Transaction Graph Analysis**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs basées sur le flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique se base sur l'analyse de transactions avec plusieurs inputs et outputs pour deviner quel output est la change retournée à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Réutilisation forcée d'adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combinera avec d'autres inputs dans de futures transactions, liant ainsi les adresses entre elles.

### Comportement correct des wallets

Les wallets devraient éviter d'utiliser des coins reçus sur des adresses déjà utilisées et vides afin de prévenir ce privacy leak.

## **Autres techniques d'analyse de la blockchain**

- **Exact Payment Amounts:** Les transactions sans change sont probablement entre deux adresses appartenant au même utilisateur.
- **Round Numbers:** Un montant rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement le change.
- **Wallet Fingerprinting:** Différents wallets ont des schémas uniques de création de transaction, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Amount & Timing Correlations:** La divulgation des heures ou des montants des transactions peut rendre les transactions traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocks à des adresses IP, compromettant la vie privée des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux noeuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## Plus

Pour une liste complète des attaques et des défenses en matière de confidentialité, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Façons d'obtenir des Bitcoins anonymement

- **Cash Transactions**: Acquérir des bitcoins en espèces.
- **Cash Alternatives**: Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining**: La méthode la plus privée pour gagner des bitcoins est le mining, surtout en solo, car les mining pools peuvent connaître l'IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Théoriquement, voler des bitcoins pourrait être une autre façon de les acquérir anonymement, bien que ce soit illégal et non recommandé.

## Services de mixage

En utilisant un service de mixage, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend difficile la traçabilité du propriétaire initial. Cependant, cela nécessite de faire confiance au service pour ne pas conserver de logs et pour effectivement renvoyer les bitcoins. D'autres options de mixage incluent les casinos Bitcoin.

## CoinJoin

CoinJoin fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant la tâche de quiconque essaie d'associer inputs et outputs. Malgré son efficacité, les transactions avec des tailles d'inputs et d'outputs uniques peuvent encore potentiellement être retracées.

Des transactions exemples ayant peut-être utilisé CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant des mineurs.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), déguises la transaction entre deux parties (par ex., un client et un commerçant) en une transaction ordinaire, sans les sorties égales distinctives caractéristiques de CoinJoin. Ceci la rend extrêmement difficile à détecter et pourrait invalider la common-input-ownership heuristic utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions comme celle ci‑dessous pourraient être PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes de surveillance traditionnelles**, en en faisant une avancée prometteuse dans la recherche de la confidentialité transactionnelle.

# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Wallet Synchronization Techniques**

Pour préserver la confidentialité et la sécurité, la synchronisation des wallets avec la blockchain est cruciale. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l'intégralité de la blockchain, un full node garantit une confidentialité maximale. Toutes les transactions effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque block de la blockchain, permettant aux wallets d'identifier les transactions pertinentes sans exposer d'intérêts spécifiques aux observateurs du réseau. Les lightweight wallets téléchargent ces filtres, ne récupérant les blocks complets que lorsqu'il y a une correspondance avec les adresses de l'utilisateur.

## **Utilizing Tor for Anonymity**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, l'utilisation de Tor est recommandée pour masquer votre adresse IP, améliorant la confidentialité lors des interactions avec le réseau.

## **Preventing Address Reuse**

Pour protéger la confidentialité, il est vital d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation d'adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les wallets modernes découragent la réutilisation d'adresses par leur conception.

## **Strategies for Transaction Privacy**

- **Multiple transactions** : Fractionner un paiement en plusieurs transactions peut obscurcir le montant transmis, contrant les attaques ciblant la confidentialité.
- **Change avoidance** : Opter pour des transactions qui n'exigent pas d'outputs de change améliore la confidentialité en perturbant les méthodes de détection de change.
- **Multiple change outputs** : Si éviter le change n'est pas faisable, générer plusieurs outputs de change peut tout de même améliorer la confidentialité.

# **Monero: A Beacon of Anonymity**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée pour la confidentialité.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique un gas limit et une base fee, avec un tip pour inciter les mineurs. Les utilisateurs peuvent définir un max fee pour éviter de surpayer, l'excédent étant remboursé.

## **Executing Transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être soit des adresses utilisateur soit des adresses de smart contract. Elles requièrent des frais et doivent être minées. Les informations essentielles d'une transaction incluent le destinataire, la signature de l'expéditeur, la valeur, les données optionnelles, le gas limit et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, ce qui élimine le besoin de l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite interagir avec les cryptomonnaies tout en priorisant la confidentialité et la sécurité.

## Value-Centric Web3 Red Teaming

- Inventorier les composants porteurs de valeur (signers, oracles, bridges, automation) pour comprendre qui peut déplacer des fonds et comment.
- Mapper chaque composant aux tactiques MITRE AADAPT pertinentes pour exposer des chemins d'escalade de privilèges.
- Répéter des chaînes d'attaque flash-loan/oracle/credential/cross-chain pour valider l'impact et documenter les préconditions exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- L'altération de la supply-chain des wallet UIs peut modifier les payloads EIP-712 juste avant la signature, récoltant des signatures valides pour des prises de contrôle de proxy basées sur delegatecall (p.ex., overwrite slot-0 du Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing pour détecter les angles morts dans les suites de test :

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

Si vous recherchez l'exploitation pratique des DEXes et AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools multi‑actifs pondérés qui mettent en cache des soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, étudiez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
