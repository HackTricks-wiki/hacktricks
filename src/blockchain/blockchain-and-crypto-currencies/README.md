# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- Les **smart contracts** sont des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies. Ils automatisent l’exécution d’accords sans intermédiaires.
- Les **applications décentralisées (dApps)** reposent sur des smart contracts et disposent d’une interface utilisateur conviviale et d’un back-end transparent et auditable.
- Les **tokens et les coins** se distinguent par leur fonction : les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
  - Les **utility tokens** donnent accès à des services, tandis que les **security tokens** représentent la propriété d’un actif.
- **DeFi** signifie finance décentralisée et désigne des services financiers sans autorité centrale.
- **DEX** et **DAO** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et concertée des transactions sur la blockchain :

- La **preuve de travail (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- La **preuve d’enjeu (PoS)** exige des validateurs qu’ils détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport à la PoW.<sup>[[1]](#references)</sup>

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre des adresses. Elles sont validées par des signatures numériques, ce qui garantit que seul le propriétaire de la clé privée peut effectuer des transferts.<sup>[[2]](#references)</sup>

#### Composants clés :

- Les **transactions multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions comprennent des **entrées** (source des fonds), des **sorties** (destination), des **frais** (versés aux mineurs) et des **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer l’évolutivité de Bitcoin en permettant plusieurs transactions au sein d’un canal, tout en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité liés à Bitcoin

Les attaques contre la confidentialité, comme la **propriété commune des entrées** et la **détection des adresses de renvoi UTXO**, exploitent les schémas des transactions. Des stratégies comme les **mixers** et **CoinJoin** améliorent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins de manière anonyme

Les méthodes comprennent les échanges en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer leur traçabilité, tandis que **PayJoin** dissimule les CoinJoins en les faisant passer pour des transactions ordinaires afin d’accroître la confidentialité.

# Résumé des attaques contre la confidentialité de Bitcoin

Dans l’univers du Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Hypothèse de propriété commune des entrées**

Il est généralement rare que les entrées de différents utilisateurs soient réunies dans une seule transaction, en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’entrée dans une même transaction appartiennent au même propriétaire**.

## **Détection des adresses de renvoi UTXO**

Un UTXO, ou **sortie de transaction non dépensée**, doit être dépensé entièrement dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de renvoi. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour limiter ce risque, les services de mixage ou l’utilisation de plusieurs adresses peuvent aider à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **de facilement relier une adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs à partir des flux de fonds.

## **Heuristique des entrées inutiles (heuristique de la monnaie optimale)**

Cette heuristique consiste à analyser les transactions comportant plusieurs entrées et sorties afin de deviner quelle sortie correspond à la monnaie rendue à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l’ajout d’entrées supplémentaires rend la sortie de change plus importante que n’importe quelle entrée, cela peut perturber l’heuristique.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine à d’autres entrées dans de futures transactions, reliant ainsi les adresses entre elles.

### Comportement adéquat du wallet

Les wallets devraient éviter d’utiliser des bitcoins reçus sur des adresses déjà utilisées et vides afin d’éviter ce leak de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants exacts des paiements :** Les transactions sans monnaie rendue sont probablement effectuées entre deux adresses appartenant au même utilisateur.
- **Nombres ronds :** Un montant rond dans une transaction suggère qu’il s’agit d’un paiement, la sortie dont le montant n’est pas rond étant probablement la monnaie rendue.
- **Fingerprinting du wallet :** Les différents wallets présentent des schémas de création de transactions qui leur sont propres, ce qui permet aux analystes d’identifier le logiciel utilisé et potentiellement l’adresse de monnaie rendue.
- **Corrélations entre montants et horaires :** La divulgation des horaires ou des montants des transactions peut les rendre traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement associer des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C’est particulièrement vrai lorsqu’une entité exploite de nombreux nœuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## Plus d’informations

Pour une liste complète des attaques visant la confidentialité et des moyens de défense, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d’obtenir des bitcoins anonymement

- **Transactions en espèces** : Acquérir des bitcoins en espèces.
- **Alternatives aux espèces** : Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining** : La méthode la plus confidentielle pour obtenir des bitcoins est le mining, en particulier lorsqu’il est effectué seul, car les mining pools peuvent connaître l’adresse IP du mineur. [Informations sur les mining pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol** : En théorie, voler des bitcoins pourrait être un autre moyen d’en acquérir anonymement, mais c’est illégal et déconseillé.

## Services de mixing

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **d’autres bitcoins en retour**, ce qui rend difficile la traçabilité du propriétaire initial. Cela exige toutefois de faire confiance au service, qui ne doit pas conserver de logs et doit effectivement restituer les bitcoins. Les casinos Bitcoin constituent une autre option de mixing.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant ainsi la tâche de quiconque essaie d’associer les entrées aux sorties. Malgré son efficacité, les transactions présentant des tailles d’entrées et de sorties uniques peuvent encore potentiellement être tracées.

Parmi les exemples de transactions ayant pu utiliser CoinJoin figurent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour en savoir plus, consultez [CoinJoin](https://coinjoin.io/en). Pour un mixer de smart contract Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans les sorties égales caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des entrées utilisée par les entités de surveillance des transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Des transactions comme celle ci-dessus pourraient être des PayJoin, renforçant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait considérablement perturber les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des portefeuilles**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les portefeuilles avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : en téléchargeant l’intégralité de la blockchain, un nœud complet assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui empêche les adversaires de déterminer les transactions ou les adresses qui intéressent l’utilisateur.
- **Filtrage des blocs côté client** : cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d’identifier les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu’ils trouvent une correspondance avec les adresses de l’utilisateur.

## **Utiliser Tor pour l’anonymat**

Étant donné que Bitcoin fonctionne sur un réseau pair-à-pair, il est recommandé d’utiliser Tor pour masquer votre adresse IP et améliorer la confidentialité lors de vos interactions avec le réseau.

## **Éviter la réutilisation des adresses**

Pour protéger votre confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant des transactions à la même entité. Les portefeuilles modernes découragent la réutilisation des adresses par leur conception.

## **Stratégies pour préserver la confidentialité des transactions**

- **Transactions multiples** : diviser un paiement en plusieurs transactions peut masquer le montant de la transaction et déjouer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : privilégier les transactions qui ne nécessitent pas de sortie de monnaie rendue améliore la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Plusieurs sorties de monnaie rendue** : s’il est impossible d’éviter la monnaie rendue, générer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un symbole de l’anonymat**

Monero est conçu pour donner la priorité à la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l’effort de calcul nécessaire à l’exécution d’opérations sur Ethereum et son prix est exprimé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (soit 0,00231 ETH) comporte une limite de gas et des frais de base, auxquels s’ajoutent des frais de priorité pour inciter un validateur à l’inclure. Les utilisateurs peuvent définir des frais maximums afin d’éviter de payer trop cher ; l’excédent leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d’utilisateurs ou de smart contracts. Elles nécessitent des frais et doivent être incluses dans un bloc. Une transaction contient notamment le destinataire, la signature de l’expéditeur, la valeur, des données facultatives, la limite de gas et les frais. Il est à noter que l’adresse de l’expéditeur est déduite de la signature ; elle n’a donc pas besoin de figurer dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont essentiels pour toute personne souhaitant utiliser des cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## Red Teaming Web3 centré sur la valeur

- Répertorier les composants qui détiennent de la valeur (signataires, oracles, bridges, automatisation) afin de comprendre qui peut déplacer les fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes afin de révéler les chemins d’escalade de privilèges.
- Répéter des chaînes d’attaque impliquant des flash loans, des oracles, des identifiants ou des interactions cross-chain afin de valider l’impact et de documenter les conditions préalables exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du flux de signature Web3

- La falsification de la chaîne d’approvisionnement des interfaces utilisateur de portefeuilles peut modifier les charges utiles EIP-712 juste avant la signature et récolter des signatures valides pour des prises de contrôle de proxy basées sur `delegatecall` (par exemple, l’écrasement du slot 0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Les modes de défaillance courants des smart accounts incluent le contournement du contrôle d’accès de `EntryPoint`, des champs de gas non signés, une validation avec état, le rejeu ERC-1271 et le drainage des frais par un revert après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Les tests de mutation permettent de détecter les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des guests zkVM

Lorsqu’un prouveur utilise une **zkVM** ou un circuit de preuve propre à une application pour attester une affirmation, le vérificateur apprend uniquement que le **programme guest s’est exécuté tel qu’il a été écrit**. Si le guest contient une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prouveur malveillant peut générer une preuve valide alors que les **métriques publiques ou l’invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée dans les guests de preuve

- Traiter les octets privés du witness/circuit comme des **entrées non fiables contrôlées par un attaquant**, même s’ils sont masqués par la preuve.
- Éviter de les désérialiser avec des fonctions auxiliaires sans vérification telles que `rkyv::access_unchecked`, sauf si les octets ont déjà été validés par un autre moyen.
- Les discriminants d’énumération, pointeurs relatifs, longueurs et index chargés à partir de données sérialisées non fiables doivent être validés avant d’influencer le flot de contrôle ou l’accès à la mémoire.

Modèle pratique d’audit :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors limites**, chaque `match` ultérieur sur cette valeur devient suspect.

### Contournement des compteurs via jump table / comportement indéfini

Si Rust compile un grand `match` en **jump table**, un discriminant d’enum invalide peut entraîner un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **sémantique réelle de l’instruction**.
3. Un discriminant hors limites dépasse la première jump table et arrive dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans un zkVM, cela peut permettre de forger des preuves indiquant des métriques impossibles, telles qu’un nombre réduit de gates, moins d’opérations coûteuses ou d’autres ressources bornées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par l’attaquant et désérialisés à partir du witness/de l’entrée privée.
- Examinez les `match` répétés sur le même champ opcode/kind.
- Considérez la combinaison `unsafe` + désérialisation sans vérification + dispatch d’opcodes volumineux comme présentant un risque élevé.
- Faites de la rétro-ingénierie du binaire généré si nécessaire ; la disposition des jump tables peut être plus importante que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vérifiez pas seulement la sûreté mémoire ; vérifiez aussi les **règles sémantiques** que la preuve est censée faire respecter.

Pour les jeux d’instructions réversibles/de type quantique, assurez-vous que les opérandes qui doivent être distincts sont effectivement contraints à l’être. Une opération de type Toffoli/CCX implémentée comme suit :<sup>[[7]](#references)[[8]](#references)</sup>

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

Cela crée une **primitive de réinitialisation déterministe**, qui brise les hypothèses de réversibilité et permet d’effectuer à moindre coût des calculs non prévus. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre aux attaquants de satisfaire aux contrôles fonctionnels tout en contournant le modèle de coût que le vérificateur croit imposer.

### Éléments à tester dans les systèmes ZK

- Fuzzer tous les analyseurs syntaxiques guest avec des encodages malformés de witness/entrées privées.
- Vérifier que les valeurs des enums sont validées avant le dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l’aliasing des opérandes et les autres formes d’instructions invalides.
- Comparer les compteurs rapportés/publics à ceux d’une implémentation de référence indépendante.
- Garder à l’esprit qu’une preuve valide peut tout de même prouver le **mauvais énoncé** si le programme guest est bogué.

## Autorisation dépendante de l’état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation de DeFi/AMM

Si vous étudiez l’exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus des arrondis/de la précision, swaps amplifiés par des flash loans qui franchissent des seuils), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache les soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, consultez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d’enjeu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Explication des clés publiques et privées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions multisignatures ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons vaincu la preuve à divulgation nulle de connaissance de Google sur la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécurisation des cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d’atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
