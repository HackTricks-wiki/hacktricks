# Blockchain et Crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** reposent sur les smart contracts, avec une interface front-end conviviale et un back-end transparent et auditable.
- **Tokens & Coins** différencient les rôles : les coins servent de monnaie numérique, tandis que les tokens représentent de la valeur ou une propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et **Security Tokens** signifient la propriété d'actifs.
- **DeFi** désigne Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** se réfèrent respectivement aux Decentralized Exchange Platforms et aux Decentralized Autonomous Organizations.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et convenue des transactions sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certain nombre de tokens, réduisant la consommation d'énergie par rapport au PoW.

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées via des signatures numériques, garantissant que seul le détenteur de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** requièrent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent d'**inputs** (origine des fonds), d'**outputs** (destination), de **fees** (frais payés aux mineurs) et de **scripts** (règles de la transaction).

### Lightning Network

Vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un canal, en ne diffusant sur la blockchain que l'état final.

## Problèmes de confidentialité de Bitcoin

Les attaques sur la confidentialité, telles que **Common Input Ownership** et la **détection d'adresses de change UTXO**, exploitent les motifs transactionnels. Des stratégies comme les **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre utilisateurs.

## Acquérir des Bitcoins de façon anonyme

Les méthodes incluent les transactions en espèces, le mining et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** camoufle les CoinJoin en transactions régulières pour une confidentialité accrue.

# Attaques de confidentialité Bitcoin

# Résumé des attaques contre la confidentialité Bitcoin

Dans l'univers de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent préoccupants. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité sur Bitcoin.

## **Hypothèse d'appartenance commune des inputs**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une seule transaction à cause de la complexité impliquée. Ainsi, **deux adresses en tant qu'inputs dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **Détection d'adresse de change UTXO**

Un UTXO, ou Unspent Transaction Output (sortie de transaction non dépensée), doit être dépensé intégralement dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est renvoyé à une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Exemple

Pour atténuer cela, les services de mixing ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition via les réseaux sociaux & forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile de lier l'adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs basées sur le flux de fonds.

## **Heuristique de l'input inutile (Optimal Change Heuristic)**

Cette heuristique se base sur l'analyse des transactions avec plusieurs inputs et outputs pour deviner quel output est la monnaie de retour (change) revenant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout d'inputs rend la sortie de change plus grande que n'importe quel input individuel, cela peut tromper l'heuristique.

## **Forced Address Reuse**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d'autres inputs dans des transactions futures, liant ainsi les adresses entre elles.

### Correct Wallet Behavior

Les wallets doivent éviter d'utiliser les coins reçus sur des adresses déjà utilisées et vides pour prévenir cette privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Les transactions sans change sont probablement entre deux adresses appartenant au même utilisateur.
- **Round Numbers:** Un nombre rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement la sortie de change.
- **Wallet Fingerprinting:** Différents wallets ont des schémas uniques de création de transactions, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de change.
- **Amount & Timing Correlations:** La divulgation des heures ou des montants des transactions peut rendre les transactions traçables.

## **Traffic Analysis**

En surveillant le trafic réseau, des attaquants peuvent potentiellement lier des transactions ou des blocs à des adresses IP, compromettant la confidentialité des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, renforçant sa capacité à surveiller les transactions.

## More

Pour une liste complète des attaques et des défenses en matière de confidentialité, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquérir du bitcoin en espèces.
- **Cash Alternatives**: Acheter des cartes-cadeaux et les échanger en ligne contre du bitcoin.
- **Mining**: La méthode la plus privée pour gagner des bitcoins est le mining, surtout en solo car les mining pools peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Théoriquement, voler des bitcoins pourrait être une autre méthode pour les obtenir anonymement, bien que ce soit illégal et non recommandé.

## Mixing Services

En utilisant un mixing service, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend la traçabilité du propriétaire initial difficile. Cependant, cela nécessite de faire confiance au service pour ne pas conserver de logs et pour renvoyer effectivement les bitcoins. D'autres options de mixing incluent les casinos Bitcoin.

## CoinJoin

CoinJoin fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant le travail de quiconque essaie d'associer inputs et outputs. Malgré son efficacité, des transactions ayant des tailles d'input et d'output uniques peuvent encore potentiellement être retracées.

Exemples de transactions qui ont peut‑être utilisé CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant des mineurs.

## PayJoin

Un variant de CoinJoin, **PayJoin** (ou P2EP), déguisent la transaction entre deux parties (par ex. un client et un commerçant) en une transaction ordinaire, sans les sorties égales distinctives caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et peut invalider la common-input-ownership heuristic utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Des transactions comme celles ci‑dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes traditionnelles de surveillance**, en faisant un développement prometteur dans la recherche de la confidentialité des transactions.

# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Wallet Synchronization Techniques**

Pour préserver la confidentialité et la sécurité, synchroniser les wallets avec la blockchain est crucial. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l'intégralité de la blockchain, un full node garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour des adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux wallets d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres, ne récupérant les blocs complets que lorsqu'il y a une correspondance avec les adresses de l'utilisateur.

## **Utiliser Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, il est recommandé d'utiliser Tor pour masquer votre adresse IP, renforçant la confidentialité lors des interactions avec le réseau.

## **Prévenir la réutilisation d'adresses**

Pour protéger la confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation d'adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les wallets modernes découragent la réutilisation d'adresses par leur conception.

## **Stratégies pour la confidentialité des transactions**

- **Multiple transactions** : Fractionner un paiement en plusieurs transactions peut obscurcir le montant, contrecarrant les attaques visant la confidentialité.
- **Change avoidance** : Choisir des transactions qui n'exigent pas d'outputs de change améliore la confidentialité en perturbant les méthodes de détection du change.
- **Multiple change outputs** : Si éviter le change n'est pas faisable, générer plusieurs outputs de change peut quand même améliorer la confidentialité.

# **Monero : un phare de l'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée en matière de confidentialité.

# **Ethereum : Gas et transactions**

## **Comprendre le Gas**

Le Gas mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) implique une gas limit et une base fee, avec un tip pour inciter les mineurs. Les utilisateurs peuvent définir un max fee pour s'assurer de ne pas trop payer, l'excédent étant remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un émetteur et un destinataire, qui peuvent être des adresses utilisateur ou des contrats intelligents. Elles requièrent des frais et doivent être minées. Les informations essentielles d'une transaction incluent le destinataire, la signature de l'émetteur, la valeur, des données optionnelles, la gas limit et les frais. Notamment, l'adresse de l'émetteur est déduite de la signature, ce qui évite d'avoir à l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite interagir avec les cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## References

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

{{#include ../../banners/hacktricks-training.md}}
