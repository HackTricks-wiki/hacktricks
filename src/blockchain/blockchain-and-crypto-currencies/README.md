# Blockchain et crypto-monnaies

## Concepts de base

- Les **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- Les **applications décentralisées (dApps)** reposent sur des smart contracts et disposent d'un front-end convivial ainsi que d'un back-end transparent et auditable.
- Les **Tokens et Coins** se distinguent par le fait que les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
- Les **Utility Tokens** accordent l'accès à des services, tandis que les **Security Tokens** représentent la propriété d'un actif.
- La **DeFi** signifie Decentralized Finance et propose des services financiers sans autorités centrales.
- **DEX** et **DAOs** désignent respectivement les plateformes d'échange décentralisées et les organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et acceptée des transactions sur la blockchain :

- La **Proof of Work (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- La **Proof of Stake (PoS)** exige des validateurs qu'ils détiennent une certaine quantité de tokens, ce qui réduit la consommation énergétique par rapport à la PoW.<sup>[[1]](#references)</sup>

## Principes essentiels de Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre des adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.<sup>[[2]](#references)</sup>

#### Composants clés :

- Les **transactions multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions se composent d'**inputs** (source des fonds), d'**outputs** (destination), de **fees** (versées aux miners) et de **scripts** (règles de la transaction).

### Lightning Network

Vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un channel, tout en ne diffusant que l'état final sur la blockchain.

## Problèmes de confidentialité de Bitcoin

Les attaques visant la confidentialité, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les modèles de transaction. Des stratégies comme les **Mixers** et **CoinJoin** améliorent l'anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des Bitcoins anonymement

Les méthodes comprennent les échanges en espèces, le mining et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions afin de compliquer la traçabilité, tandis que **PayJoin** dissimule les CoinJoins sous l'apparence de transactions ordinaires pour renforcer la confidentialité.

# Résumé des attaques visant la confidentialité de Bitcoin

Dans le monde de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets préoccupants. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses d'input dans une même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le montant restant est envoyé vers une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, ce qui compromet la confidentialité.

### Exemple

Pour atténuer ce problème, les services de mixing ou l'utilisation de plusieurs adresses peuvent contribuer à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **d'associer facilement l'adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des connexions potentielles entre les utilisateurs en fonction du flux des fonds.

## **Heuristique des inputs inutiles (heuristique du change optimal)**

Cette heuristique repose sur l'analyse des transactions comportant plusieurs inputs et outputs afin de déterminer quel output correspond au change retourné à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l’ajout de plusieurs inputs rend le change plus important que n’importe quel input individuel, cela peut perturber l’heuristique.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d’autres inputs dans de futures transactions, reliant ainsi les adresses entre elles.

### Comportement correct du wallet

Les wallets doivent éviter d’utiliser des coins reçus sur des adresses déjà utilisées et vides afin d’empêcher cette fuite de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants de paiement exacts :** Les transactions sans change sont probablement effectuées entre deux adresses appartenant au même utilisateur.
- **Nombres ronds :** Un nombre rond dans une transaction indique qu’il s’agit probablement d’un paiement, tandis que l’output non rond est probablement le change.
- **Empreinte du wallet :** Les différents wallets présentent des modèles uniques de création de transactions, permettant aux analystes d’identifier le logiciel utilisé et éventuellement l’adresse de change.
- **Corrélations de montant et de temps :** La divulgation des heures ou des montants des transactions peut rendre les transactions traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## Plus

Pour obtenir une liste complète des attaques visant la confidentialité et des défenses associées, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d’obtenir des bitcoins anonymement

- **Transactions en espèces :** Acquérir des bitcoins en espèces.
- **Alternatives aux espèces :** Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining :** La méthode la plus confidentielle pour gagner des bitcoins consiste à faire du mining, en particulier lorsque celui-ci est effectué seul, car les mining pools peuvent connaître l’adresse IP du miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol :** En théorie, voler des bitcoins pourrait être une autre méthode pour en acquérir anonymement, bien que cela soit illégal et déconseillé.

## Services de mixing

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **des bitcoins différents en retour**, ce qui rend difficile la traçabilité du propriétaire d’origine. Toutefois, cela nécessite de faire confiance au service pour qu’il ne conserve pas de logs et qu’il restitue effectivement les bitcoins. Les casinos Bitcoin constituent une autre option de mixing.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions provenant de différents utilisateurs en une seule, ce qui complique le processus pour quiconque tente d’associer les inputs aux outputs. Malgré son efficacité, les transactions présentant des tailles d’inputs et d’outputs uniques peuvent encore être potentiellement tracées.

Des transactions d’exemple ayant peut-être utilisé CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d’informations, consultez [CoinJoin](https://coinjoin.io/en). Pour un mixer basé sur un smart contract Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule la transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans la caractéristique distinctive des outputs égaux de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des inputs utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait considérablement perturber les méthodes traditionnelles de surveillance**, ce qui en fait une évolution prometteuse dans la recherche d'une meilleure confidentialité transactionnelle.

# Meilleures pratiques pour la confidentialité des cryptomonnaies

## **Techniques de synchronisation des wallets**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les wallets avec la blockchain. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l'intégralité de la blockchain, un full node garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui empêche les adversaires d'identifier les transactions ou adresses qui intéressent l'utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, afin que les wallets puissent identifier les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utilisation de Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, l'utilisation de Tor est recommandée pour masquer votre adresse IP et renforcer la confidentialité lors des interactions avec le réseau.

## **Prévention de la réutilisation des adresses**

Pour protéger la confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant les transactions à la même entité. Les wallets modernes découragent la réutilisation des adresses grâce à leur conception.

## **Stratégies pour la confidentialité des transactions**

- **Transactions multiples** : Diviser un paiement en plusieurs transactions peut masquer le montant de la transaction et contrecarrer les attaques visant la confidentialité.
- **Évitement de la monnaie rendue** : Opter pour des transactions qui ne nécessitent pas d'outputs de monnaie rendue améliore la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Outputs multiples de monnaie rendue** : S'il n'est pas possible d'éviter la monnaie rendue, générer plusieurs outputs de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un phare de l'anonymat**

Monero est conçu pour donner la priorité à la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l'effort de calcul nécessaire pour exécuter des opérations sur Ethereum, et son prix est exprimé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) implique une limite de gas et des frais de base, avec des frais de priorité destinés à inciter les validateurs à l'inclure. Les utilisateurs peuvent définir des frais maximaux afin de ne pas payer plus que nécessaire, l'excédent étant remboursé.<sup>[[5]](#references)</sup>

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d'utilisateurs ou de smart contracts. Elles nécessitent des frais et doivent être incluses dans un bloc. Les informations essentielles d'une transaction comprennent le destinataire, la signature de l'expéditeur, la valeur, les données facultatives, la limite de gas et les frais. Il est important de noter que l'adresse de l'expéditeur est déduite de la signature, ce qui élimine la nécessité de l'inclure dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont fondamentaux pour toute personne souhaitant utiliser des cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## Red Teaming Web3 centré sur la valeur

- Dresser l'inventaire des composants détenant de la valeur (signers, oracles, bridges, automation) afin de comprendre qui peut déplacer les fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes afin de révéler les chemins d'escalade de privilèges.
- Répéter les chaînes d'attaque flash-loan/oracle/credential/cross-chain afin de valider l'impact et de documenter les conditions préalables exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- La falsification de la supply chain des interfaces de wallets peut modifier les payloads EIP-712 juste avant la signature, en récoltant des signatures valides pour prendre le contrôle de proxies fondés sur delegatecall (par exemple, en écrasant le slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Les modes de défaillance courants des smart accounts incluent le contournement du contrôle d'accès de `EntryPoint`, des champs de gas non signés, une validation stateful, le replay ERC-1271 et le drainage des frais via un revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Tests de mutation pour identifier les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des guests zkVM

Lorsqu'un prover utilise une **zkVM** ou un circuit de preuve spécifique à une application pour attester une affirmation, le verifier apprend uniquement que le **guest program s'est exécuté comme prévu**. Si le guest contient une **désérialisation non sûre**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prover malveillant peut générer une preuve qui est vérifiée alors que les **métriques publiques ou l'invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sûre au sein des proof guests

- Traiter les octets privés du witness/circuit comme des **entrées contrôlées par un attaquant** même s'ils sont masqués par la preuve.
- Éviter de les désérialiser avec des helpers non vérifiés tels que `rkyv::access_unchecked`, sauf si les octets ont déjà été validés out-of-band.
- Les discriminants d'enum, les pointeurs relatifs, les longueurs et les index chargés depuis des données sérialisées non fiables doivent être validés avant d'influencer le flux de contrôle ou l'accès à la mémoire.

Méthode d'audit pratique :
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Si un champ tel que `op.kind` est un enum et qu'un attaquant peut injecter un **discriminant hors limites**, chaque `match` ultérieur portant sur cette valeur devient suspect.

### Contournement des compteurs via jump-table / UB

Si Rust transforme un grand `match` en **jump table**, un discriminant d'enum invalide peut produire un **flux de contrôle indéfini**. Un schéma dangereux est le suivant :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **sémantique réelle de l'instruction**.
3. Un discriminant hors limites indexe au-delà de la première jump table et aboutit dans le code associé à la seconde.

Résultat : l'opération est tout de même exécutée, mais le chemin de comptabilisation est ignoré. Dans une zkVM, cela peut forger des preuves indiquant des métriques impossibles, telles qu'un nombre inférieur de gates, moins d'opérations coûteuses ou d'autres ressources limitées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par l'attaquant et désérialisés depuis des entrées witness/private.
- Inspectez les instructions `match` répétées portant sur le même champ opcode/kind.
- Considérez la combinaison `unsafe` + désérialisation non vérifiée + dispatch d'opcodes volumineux comme présentant un risque élevé.
- Faites du reverse engineering du binaire généré si nécessaire ; la disposition de la jump table peut être plus importante que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne validez pas uniquement la sécurité mémoire ; validez également les **règles sémantiques** que la preuve est censée faire respecter.

Pour les jeux d'instructions réversibles/quantiques, assurez-vous que les opérandes qui doivent être distincts sont effectivement contraints à l'être. Une opération de type Toffoli/CCX implémentée comme suit :<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
devient dangereux si l’invité ne rejette pas :
```text
op.q_control1 == op.q_control2 == op.q_target
```
Dans ce cas, la transition se réduit à :
```text
q = q ^ (q & q) = 0
```
Cela crée une **primitive de réinitialisation déterministe**, qui rompt les hypothèses de réversibilité et permet des calculs non prévus à moindre coût. Dans les systèmes de preuve qui attestent de l'utilisation des ressources, cela peut permettre aux attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit imposer.

### Éléments à tester dans les systèmes ZK

- Fuzzer tous les parseurs guest avec des encodages malformés des witnesses/entrées privées.
- Vérifier la plage des enums avant la dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l'aliasing des opérandes et les autres formes d'instructions invalides.
- Comparer les compteurs rapportés/publics à une implémentation de référence indépendante.
- N'oubliez pas qu'une preuve valide peut tout de même prouver la **mauvaise assertion** si le programme guest est bogué.

## Exploitation DeFi/AMM

Si vous étudiez l'exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus des arrondis/de la précision, swaps avec franchissement de seuil amplifié par des flash loans), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache des soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, consultez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d'enjeu - Wikipédia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clé publique et clé privée expliquées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions multisignatures ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons contourné la preuve zero-knowledge de Google concernant la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécurisation des cryptomonnaies à courbes elliptiques contre les vulnérabilités quantiques : estimations des ressources et mesures d'atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
