# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** désigne des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l’exécution d’accords sans intermédiaires.
- Les **Decentralized Applications (dApps)** reposent sur des smart contracts et disposent d’une interface front-end conviviale et d’un back-end transparent et vérifiable.
- Les **Tokens & Coins** se distinguent par leur usage : les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
  - Les **Utility Tokens** donnent accès à des services, tandis que les **Security Tokens** représentent la propriété d’actifs.
- **DeFi** signifie Decentralized Finance et désigne des services financiers sans autorité centrale.
- **DEX** et **DAOs** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et concertée des transactions sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport au PoW.<sup>[[1]](#references)</sup>

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre des adresses. Elles sont validées par des signatures numériques, ce qui garantit que seul le propriétaire de la clé privée peut initier des transferts.<sup>[[2]](#references)</sup>

#### Éléments clés :

- Les **Multisignature Transactions** exigent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions comprennent des **inputs** (source des fonds), des **outputs** (destination), des **fees** (versés aux mineurs) et des **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer l’évolutivité de Bitcoin en permettant plusieurs transactions dans un canal, et en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité liés à Bitcoin

Les attaques contre la confidentialité, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les schémas de transaction. Des stratégies comme les **Mixers** et **CoinJoin** améliorent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins de manière anonyme

Les méthodes comprennent les échanges en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer leur traçabilité, tandis que **PayJoin** dissimule les CoinJoins en les faisant passer pour des transactions ordinaires afin d’améliorer la confidentialité.

# Résumé des attaques contre la confidentialité de Bitcoin

Dans le monde de Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes utilisées par les attaquants pour compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Hypothèse de propriété commune des inputs**

Il est généralement rare que des inputs appartenant à différents utilisateurs soient combinés dans une même transaction, en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’input dans une même transaction appartiennent au même propriétaire**.

## **Détection des adresses de change UTXO**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour limiter ce risque, les services de mixage ou l’utilisation de plusieurs adresses peuvent aider à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui facilite **l’association de l’adresse à son propriétaire**.

## **Analyse des graphes de transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs en fonction des flux de fonds.

## **Heuristique des inputs inutiles (heuristique de change optimal)**

Cette heuristique consiste à analyser les transactions comportant plusieurs inputs et outputs afin de déterminer quel output correspond au change renvoyé à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l’ajout d’autres entrées rend la sortie de monnaie supérieure à n’importe quelle entrée individuelle, cela peut perturber l’heuristique.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d’autres entrées lors de transactions ultérieures, reliant ainsi les adresses entre elles.

### Comportement correct du wallet

Les wallets devraient éviter d’utiliser des coins reçus sur des adresses déjà utilisées et vides afin d’éviter ce leak de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants de paiement exacts :** Les transactions sans monnaie rendue sont probablement effectuées entre deux adresses appartenant au même utilisateur.
- **Montants ronds :** Un montant rond dans une transaction suggère qu’il s’agit d’un paiement ; la sortie dont le montant n’est pas rond correspond probablement à la monnaie rendue.
- **Empreinte du wallet :** Les différents wallets ont des modèles de création de transactions qui leur sont propres, ce qui permet aux analystes d’identifier le logiciel utilisé et potentiellement l’adresse de monnaie rendue.
- **Corrélations entre montants et horaires :** La divulgation des heures ou des montants des transactions peut rendre celles-ci traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement associer des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C’est particulièrement vrai lorsqu’une entité exploite de nombreux nœuds Bitcoin, ce qui améliore sa capacité à surveiller les transactions.

## Plus

Pour consulter une liste complète des attaques visant la confidentialité et des défenses, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d’obtenir des bitcoins anonymement

- **Transactions en espèces** : Obtenir des bitcoins en payant en espèces.
- **Alternatives aux espèces** : Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining** : La méthode la plus privée pour gagner des bitcoins est le mining, surtout lorsqu’il est effectué seul, car les mining pools peuvent connaître l’adresse IP du mineur. [Informations sur les mining pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol** : En théorie, voler des bitcoins pourrait être un autre moyen d’en obtenir anonymement, bien que cela soit illégal et déconseillé.

## Services de mixing

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **d’autres bitcoins en retour**, ce qui rend difficile la traçabilité du propriétaire d’origine. Cela nécessite toutefois de faire confiance au service pour qu’il ne conserve pas de logs et renvoie effectivement les bitcoins. Les casinos Bitcoin constituent une autre option de mixing.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant la tâche de quiconque tente d’associer les entrées aux sorties. Malgré son efficacité, les transactions comportant des entrées et des sorties de tailles uniques peuvent encore potentiellement être tracées.

Parmi les transactions qui pourraient avoir utilisé CoinJoin figurent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d’informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un mixer basé sur un smart contract Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans les sorties égales caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des entrées utilisée par les entités qui surveillent les transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Des transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait perturber considérablement les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des wallets**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les wallets avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : en téléchargeant la blockchain entière, un nœud complet assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui empêche les adversaires de déterminer les transactions ou les adresses qui intéressent l’utilisateur.
- **Filtrage des blocs côté client** : cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, afin que les wallets puissent repérer les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu’une correspondance avec les adresses de l’utilisateur est trouvée.

## **Utiliser Tor pour l’anonymat**

Bitcoin fonctionnant sur un réseau pair-à-pair, il est recommandé d’utiliser Tor pour masquer votre adresse IP et améliorer votre confidentialité lorsque vous interagissez avec le réseau.

## **Éviter la réutilisation des adresses**

Pour protéger votre confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation d’adresses peut compromettre la confidentialité en reliant les transactions à la même entité. Les wallets modernes découragent la réutilisation des adresses par leur conception.

## **Stratégies pour préserver la confidentialité des transactions**

- **Transactions multiples** : diviser un paiement en plusieurs transactions peut dissimuler le montant de la transaction et contrer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : opter pour des transactions qui ne nécessitent pas de sortie de monnaie rendue améliore la confidentialité en perturbant les méthodes de détection de monnaie rendue.
- **Sorties de monnaie rendue multiples** : si éviter la monnaie rendue n’est pas possible, générer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un modèle d’anonymat**

Monero est conçu pour privilégier la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l’effort de calcul nécessaire pour exécuter des opérations sur Ethereum et est tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) comporte une limite de gas et des frais de base, auxquels s’ajoutent des frais de priorité pour inciter les validateurs à l’inclure. Les utilisateurs peuvent définir des frais maximums pour éviter de payer trop cher ; l’excédent leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d’utilisateur ou de smart contract. Elles nécessitent des frais et doivent être incluses dans un bloc. Une transaction contient notamment le destinataire, la signature de l’expéditeur, la valeur, des données facultatives, la limite de gas et les frais. À noter que l’adresse de l’expéditeur est déduite de la signature, il n’est donc pas nécessaire de l’inclure dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont essentiels pour toute personne souhaitant utiliser des cryptomonnaies tout en privilégiant la confidentialité et la sécurité.

## Red Teaming Web3 axé sur la valeur

- Répertoriez les composants qui détiennent de la valeur (signers, oracles, bridges, automatisation) pour déterminer qui peut transférer des fonds et comment.
- Associez chaque composant aux tactiques MITRE AADAPT pertinentes afin de révéler les voies d’escalade de privilèges.
- Répétez des chaînes d’attaque impliquant des flash loans, des oracles, des identifiants ou des interactions cross-chain afin de valider leur impact et de documenter les conditions préalables exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- La falsification de la chaîne d’approvisionnement des interfaces de wallet peut modifier les charges utiles EIP-712 juste avant la signature et récupérer des signatures valides pour des prises de contrôle de proxy basées sur `delegatecall` (par exemple, écrasement du slot 0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Les modes de défaillance courants des smart accounts comprennent le contournement du contrôle d’accès d’`EntryPoint`, les champs de gas non signés, la validation avec état, les attaques par rejeu ERC-1271 et le drainage des frais via une réversion après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Tests par mutation pour détecter les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des guests zkVM

Lorsqu’un prouveur utilise une **zkVM** ou un circuit de preuve spécifique à une application pour attester une affirmation, le vérificateur apprend uniquement que le **programme guest s’est exécuté comme prévu**. Si le guest contient une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prouveur malveillant peut générer une preuve valide alors que les **métriques publiques ou l’invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée dans les guests de preuve

- Traitez les octets privés du witness/circuit comme des **entrées d’attaquant non fiables**, même s’ils sont masqués par la preuve.
- Évitez de les désérialiser à l’aide de fonctions non vérifiées telles que `rkyv::access_unchecked`, sauf si les octets ont déjà été validés par un autre moyen.
- Les discriminants d’enum, les pointeurs relatifs, les longueurs et les index chargés depuis des données sérialisées non fiables doivent être validés avant d’influencer le flux de contrôle ou l’accès mémoire.

Modèle d’audit pratique :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors limites**, chaque `match` en aval sur cette valeur devient suspect.

### Contournement des compteurs par jump-table / UB

Si Rust compile un grand `match` en **jump table**, un discriminant d’enum invalide peut entraîner un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` applique la **sémantique réelle de l’instruction**.
3. Un discriminant hors limites dépasse la première jump table et atterrit dans du code associé à la seconde.

Résultat : l’opération est tout de même exécutée, mais le chemin de comptabilisation est ignoré. Dans une zkVM, cela peut permettre de forger des preuves indiquant des métriques impossibles, par exemple un nombre réduit de portes, moins d’opérations coûteuses ou d’autres ressources bornées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par un attaquant et désérialisés depuis le témoin ou une entrée privée.
- Examinez les instructions `match` répétées qui utilisent le même champ d’opcode/de type.
- Considérez la combinaison `unsafe` + désérialisation sans vérification + dispatch d’opcodes volumineux comme étant à haut risque.
- Faites de la rétro-ingénierie du binaire produit si nécessaire ; la disposition des jump tables peut être plus importante que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vérifiez pas uniquement la sécurité mémoire ; vérifiez aussi les **règles sémantiques** que la preuve est censée faire respecter.

Pour les jeux d’instructions réversibles ou de type quantique, assurez-vous que les opérandes qui doivent être distincts sont effectivement contraints à l’être. Une opération de type Toffoli/CCX implémentée ainsi :<sup>[[7]](#references)[[8]](#references)</sup>

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

This crée une **primitive de réinitialisation déterministe**, qui brise les hypothèses de réversibilité et permet d’effectuer à moindre coût des calculs non prévus. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre à des attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit appliquer.

### Que tester dans les systèmes ZK

- Fuzz tous les analyseurs syntaxiques du guest avec des encodages malformés de witness/private-input.
- Vérifiez la plage des enums avant la distribution des opcodes.
- Ajoutez des vérifications sémantiques pour l’aliasing des opérandes et les autres formes d’instructions invalides.
- Comparez les compteurs rapportés/publics à ceux d’une implémentation de référence indépendante.
- N’oubliez pas qu’une preuve valide peut quand même prouver le **mauvais énoncé** si le programme guest est bogué.

## Autorisation dépendante de l’état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

Si vous étudiez l’exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus d’arrondis/de précision, swaps amplifiés par flash loan qui franchissent un seuil), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache des soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, étudiez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d’enjeu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Explication des clés publiques et privées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions à signatures multiples ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons battu la preuve à divulgation nulle de connaissance de Google sur la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécuriser les cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d’atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
