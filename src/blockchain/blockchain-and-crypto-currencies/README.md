{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution des accords sans intermédiaires.
- **Decentralized Applications (dApps)** s'appuient sur des smart contracts, présentant une interface conviviale et un back-end transparent et auditable.
- **Tokens & Coins** différencient où les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et **Security Tokens** signifient la propriété d'actifs.
- **DeFi** signifie Finance Décentralisée, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** font référence aux plateformes d'échange décentralisées et aux organisations autonomes décentralisées, respectivement.

## Mécanismes de consensus

Les mécanismes de consensus garantissent des validations de transactions sécurisées et convenues sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent un certain montant de tokens, réduisant la consommation d'énergie par rapport au PoW.

## Essentiels de Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Composants clés :

- **Multisignature Transactions** nécessitent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent d'**inputs** (source de fonds), **outputs** (destination), **fees** (payées aux mineurs) et **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un canal, ne diffusant l'état final que sur la blockchain.

## Préoccupations en matière de confidentialité de Bitcoin

Les attaques sur la vie privée, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les modèles de transaction. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre les utilisateurs.

## Acquisition de Bitcoins de manière anonyme

Les méthodes incluent les échanges en espèces, le minage et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** dissimule les CoinJoins en tant que transactions régulières pour une confidentialité accrue.

# Attaques sur la vie privée de Bitcoin

# Résumé des attaques sur la vie privée de Bitcoin

Dans le monde de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles les attaquants peuvent compromettre la vie privée de Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses d'input dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste va à une nouvelle adresse de changement. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la vie privée.

### Exemple

Pour atténuer cela, les services de mixage ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition sur les réseaux sociaux et forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, rendant **facile de lier l'adresse à son propriétaire**.

## **Analyse des graphes de transactions**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre les utilisateurs en fonction du flux de fonds.

## **Heuristique d'input inutile (Heuristique de changement optimal)**

Cette heuristique est basée sur l'analyse des transactions avec plusieurs inputs et outputs pour deviner quel output est le changement retournant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plus d'entrées rend la sortie de changement plus grande que n'importe quelle entrée unique, cela peut confondre l'heuristique.

## **Réutilisation d'Adresse Forcée**

Les attaquants peuvent envoyer de petites sommes à des adresses précédemment utilisées, espérant que le destinataire les combine avec d'autres entrées dans de futures transactions, reliant ainsi les adresses ensemble.

### Comportement Correct du Portefeuille

Les portefeuilles devraient éviter d'utiliser des pièces reçues sur des adresses déjà utilisées et vides pour prévenir cette fuite de confidentialité.

## **Autres Techniques d'Analyse de Blockchain**

- **Montants de Paiement Exactes :** Les transactions sans changement sont probablement entre deux adresses appartenant au même utilisateur.
- **Nombres Ronds :** Un nombre rond dans une transaction suggère qu'il s'agit d'un paiement, avec la sortie non ronde étant probablement le changement.
- **Empreinte de Portefeuille :** Différents portefeuilles ont des modèles de création de transactions uniques, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de changement.
- **Corrélations de Montant & Timing :** La divulgation des heures ou des montants de transaction peut rendre les transactions traçables.

## **Analyse de Trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement lier des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, améliorant sa capacité à surveiller les transactions.

## Plus

Pour une liste complète des attaques sur la confidentialité et des défenses, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin Anonymes

## Façons d'Obtenir des Bitcoins de Manière Anonyme

- **Transactions en Espèces :** Acquérir des bitcoins par le biais d'espèces.
- **Alternatives en Espèces :** Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Minage :** La méthode la plus privée pour gagner des bitcoins est le minage, surtout lorsqu'il est effectué seul, car les pools de minage peuvent connaître l'adresse IP du mineur. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol :** Théoriquement, voler des bitcoins pourrait être une autre méthode pour les acquérir anonymement, bien que cela soit illégal et non recommandé.

## Services de Mixage

En utilisant un service de mixage, un utilisateur peut **envoyer des bitcoins** et recevoir **des bitcoins différents en retour**, ce qui rend difficile la traçabilité du propriétaire d'origine. Cependant, cela nécessite de faire confiance au service pour ne pas conserver de journaux et pour réellement retourner les bitcoins. Des options de mixage alternatives incluent les casinos Bitcoin.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant le processus pour quiconque essaie d'associer des entrées avec des sorties. Malgré son efficacité, les transactions avec des tailles d'entrée et de sortie uniques peuvent encore potentiellement être tracées.

Des transactions d'exemple qui ont pu utiliser CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant de mineurs.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), dissimule la transaction entre deux parties (par exemple, un client et un commerçant) comme une transaction régulière, sans les caractéristiques distinctives de sorties égales de CoinJoin. Cela rend extrêmement difficile la détection et pourrait invalider l'heuristique de propriété d'entrée commune utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Les transactions comme celles-ci pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber considérablement les méthodes de surveillance traditionnelles**, en faisant un développement prometteur dans la quête de la confidentialité transactionnelle.

# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Techniques de synchronisation des portefeuilles**

Pour maintenir la confidentialité et la sécurité, la synchronisation des portefeuilles avec la blockchain est cruciale. Deux méthodes se distinguent :

- **Nœud complet** : En téléchargeant l'intégralité de la blockchain, un nœud complet garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour les adversaires d'identifier quelles transactions ou adresses intéressent l'utilisateur.
- **Filtrage de blocs côté client** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans exposer d'intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres, ne récupérant des blocs complets que lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utilisation de Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau pair-à-pair, il est recommandé d'utiliser Tor pour masquer votre adresse IP, améliorant la confidentialité lors de l'interaction avec le réseau.

## **Prévention de la réutilisation des adresses**

Pour protéger la confidentialité, il est vital d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en liant les transactions à la même entité. Les portefeuilles modernes découragent la réutilisation des adresses par leur conception.

## **Stratégies pour la confidentialité des transactions**

- **Transactions multiples** : Diviser un paiement en plusieurs transactions peut obscurcir le montant de la transaction, contrecarrant les attaques sur la confidentialité.
- **Évitement du changement** : Opter pour des transactions qui ne nécessitent pas de sorties de changement améliore la confidentialité en perturbant les méthodes de détection du changement.
- **Multiples sorties de changement** : Si l'évitement du changement n'est pas faisable, générer plusieurs sorties de changement peut tout de même améliorer la confidentialité.

# **Monero : Un phare d'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée pour la confidentialité.

# **Ethereum : Gaz et transactions**

## **Comprendre le gaz**

Le gaz mesure l'effort computationnel nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) implique une limite de gaz et un frais de base, avec un pourboire pour inciter les mineurs. Les utilisateurs peuvent définir un frais maximum pour s'assurer de ne pas trop payer, l'excédent étant remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être soit des adresses d'utilisateur, soit des adresses de contrat intelligent. Elles nécessitent un frais et doivent être minées. Les informations essentielles dans une transaction incluent le destinataire, la signature de l'expéditeur, la valeur, des données optionnelles, la limite de gaz et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, éliminant le besoin de celle-ci dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque cherchant à s'engager avec les cryptomonnaies tout en priorisant la confidentialité et la sécurité.

## Références

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../../banners/hacktricks-training.md}}
