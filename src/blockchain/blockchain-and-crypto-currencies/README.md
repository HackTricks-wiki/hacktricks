# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** s'appuient sur les Smart Contracts, offrant un front-end convivial et un back-end transparent et auditable.
- **Tokens & Coins** font la distinction : les coins servent de monnaie numérique, tandis que les tokens représentent de la valeur ou la propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et les **Security Tokens** signifient la propriété d'actifs.
- **DeFi** signifie Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** se réfèrent respectivement aux plateformes d'échange décentralisées et aux organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus assurent des validations de transactions sécurisées et consensuelles sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, réduisant la consommation d'énergie par rapport au PoW.

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** requièrent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent d'**inputs** (source des fonds), d'**outputs** (destination), de **fees** (payés aux miners), et de **scripts** (règles de transaction).

### Lightning Network

Le **Lightning Network** vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un canal, ne diffusant à la blockchain que l'état final.

## Problèmes de confidentialité de Bitcoin

Des attaques contre la vie privée, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les schémas de transaction. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquérir des Bitcoins anonymement

Les méthodes incluent les échanges en espèces, le mining, et l'utilisation de Mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** dissimule les CoinJoins en tant que transactions ordinaires pour une confidentialité renforcée.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Dans l'univers de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent sujets à préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes que les attaquants peuvent utiliser pour compromettre la confidentialité sur Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une même transaction en raison de la complexité impliquée. Ainsi, **deux adresses d'entrée dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste revient à une nouvelle change address. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Example

Pour atténuer cela, les services de Mixers ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Social Networks & Forums Exposure**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile de lier l'adresse à son propriétaire**.

## **Transaction Graph Analysis**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs basées sur le flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique se base sur l'analyse des transactions avec plusieurs inputs et outputs pour deviner quelle sortie est la change retournant à l'expéditeur.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plusieurs inputs rend le change output plus grand que n'importe quel input individuel, cela peut perturber l'heuristique.

## **Forced Address Reuse**

Les attaquants peuvent envoyer de petites sommes à des addresses déjà utilisées, en espérant que le destinataire les combine avec d'autres inputs dans de futures transactions, reliant ainsi les addresses entre elles.

### Correct Wallet Behavior

Les Wallets devraient éviter d'utiliser des coins reçus sur des addresses déjà utilisées et vides afin de prévenir cette privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Les transactions sans change sont probablement effectuées entre deux addresses appartenant au même utilisateur.
- **Round Numbers:** Un montant rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement le change.
- **Wallet Fingerprinting:** Différents wallets ont des modèles uniques de création de transactions, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Amount & Timing Correlations:** La divulgation des heures ou des montants des transactions peut rendre celles-ci traçables.

## **Traffic Analysis**

En surveillant le network traffic, des attaquants peuvent potentiellement lier des transactions ou des blocks à des IP addresses, compromettant la vie privée des utilisateurs. C'est particulièrement vrai si une entité opère de nombreux Bitcoin nodes, améliorant ainsi sa capacité à surveiller les transactions.

## More

Pour une liste complète des attaques et des défenses liées à la privacy, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquérir du bitcoin en espèces.
- **Cash Alternatives**: Acheter des gift cards et les échanger en ligne contre du bitcoin.
- **Mining**: La méthode la plus privée pour gagner des bitcoins est le minage, surtout en solo car les mining pools peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Théoriquement, voler du bitcoin pourrait être une autre méthode pour l'acquérir anonymement, bien que ce soit illégal et fortement déconseillé.

## Mixing Services

En utilisant un mixing service, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui complique la traçabilité du propriétaire initial. Pourtant, cela nécessite de faire confiance au service pour qu'il ne conserve pas de logs et qu'il restitue effectivement les bitcoins. Des alternatives de mixing incluent les casinos Bitcoin.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions provenant d'utilisateurs différents en une seule, compliquant la tâche de quiconque tente d'apparier inputs et outputs. Malgré son efficacité, les transactions avec des tailles d'input et d'output uniques peuvent encore potentiellement être retracées.

Exemples de transactions ayant pu utiliser CoinJoin : `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, voyez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant des miners.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou **P2EP**), dissimule la transaction entre deux parties (par ex. un client et un marchand) comme une transaction normale, sans les sorties égales distinctives caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et peut invalider la common-input-ownership heuristic utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Des transactions comme ci‑dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes de surveillance traditionnelles**, faisant de cette technique un développement prometteur dans la recherche de la confidentialité transactionnelle.

# Bonnes pratiques pour la confidentialité dans les cryptomonnaies

## **Techniques de synchronisation du Wallet**

Pour préserver la confidentialité et la sécurité, synchroniser les wallets avec la blockchain est crucial. Deux méthodes se distinguent :

- **Full node**: En téléchargeant la blockchain complète, un full node assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering**: Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux wallets d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres, ne récupérant les blocs complets que lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utiliser Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, l'utilisation de Tor est recommandée pour masquer votre adresse IP, renforçant la confidentialité lors des interactions avec le réseau.

## **Prévenir la réutilisation des adresses**

Pour protéger la confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les wallets modernes découragent la réutilisation d'adresses par conception.

## **Stratégies pour la confidentialité des transactions**

- **Multiple transactions**: Fractionner un paiement en plusieurs transactions peut obscurcir le montant, contrecarrant les attaques sur la vie privée.
- **Change avoidance**: Opter pour des transactions qui n'exigent pas d'outputs de change améliore la confidentialité en perturbant les méthodes de détection de change.
- **Multiple change outputs**: Si éviter le change n'est pas possible, générer plusieurs outputs de change peut toujours améliorer la confidentialité.

# **Monero : un phare de l'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée en matière de confidentialité.

# **Ethereum : Gas et Transactions**

## **Comprendre le Gas**

Le Gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique un gas limit et des frais de base, avec un tip pour inciter les mineurs. Les utilisateurs peuvent fixer un max fee pour éviter de trop payer ; l'excédent est remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses utilisateur ou des smart contracts. Elles nécessitent des frais et doivent être minées. Les informations essentielles d'une transaction incluent le destinataire, la signature de l'expéditeur, la valeur, des données optionnelles, le gas limit et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, supprimant le besoin de l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite interagir avec les cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## Value-Centric Web3 Red Teaming

- Lister les composants porteurs de valeur (signers, oracles, bridges, automation) pour comprendre qui peut déplacer des fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes pour révéler les chemins d'escalade de privilèges.
- Répéter des chaînes d'attaque flash-loan/oracle/credential/cross-chain pour valider l'impact et documenter les préconditions exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- La compromission de la supply-chain des UIs de wallet peut muter les payloads EIP-712 juste avant la signature, récoltant des signatures valides pour des proxy takeovers basés sur delegatecall (par ex., slot-0 overwrite du Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Les modes de défaillance courants des smart accounts incluent le contournement du contrôle d'accès `EntryPoint`, des champs gas non signés, la validation stateful, le replay ERC-1271, et le vidage de frais via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
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

## Exploitation DeFi/AMM

Si vous recherchez l'exploitation pratique des DEXes et AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache des balances virtuelles et peuvent être empoisonnés lorsque `supply == 0`, étudiez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
