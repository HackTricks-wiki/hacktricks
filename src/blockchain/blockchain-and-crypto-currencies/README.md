# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- Les **contrats intelligents** sont des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies. Ils automatisent l’exécution d’accords sans intermédiaires.
- Les **applications décentralisées (dApps)** s’appuient sur des contrats intelligents et disposent d’une interface front-end conviviale et d’un back-end transparent et vérifiable.
- Les **tokens et les coins** se distinguent par leur fonction : les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans un contexte précis.
  - Les **utility tokens** donnent accès à des services, tandis que les **security tokens** représentent la propriété d’un actif.
- **DeFi** désigne la finance décentralisée, qui propose des services financiers sans autorité centrale.
- **DEX** et **DAO** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et concertée des transactions sur la blockchain :

- La **preuve de travail (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- La **preuve d’enjeu (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport à la PoW.<sup>[[1]](#references)</sup>

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin transfèrent des fonds entre des adresses. Elles sont validées par des signatures numériques, qui garantissent que seul le détenteur de la clé privée peut effectuer des transferts.<sup>[[2]](#references)</sup>

#### Éléments clés :

- Les **transactions multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions comprennent des **entrées** (source des fonds), des **sorties** (destination), des **frais** (versés aux mineurs) et des **scripts** (règles de transaction).

### Lightning Network

Ce réseau vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d’un canal et en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité liés à Bitcoin

Les attaques visant la confidentialité, comme la **propriété commune des entrées** et la **détection de l’adresse de change UTXO**, exploitent les modèles de transaction. Des stratégies comme les **mixers** et **CoinJoin** améliorent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins de manière anonyme

Les méthodes incluent les échanges en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour rendre leur traçage plus difficile, tandis que **PayJoin** dissimule les CoinJoin en les faisant passer pour des transactions ordinaires, afin d’améliorer la confidentialité.

# Résumé des attaques visant la confidentialité de Bitcoin

Dans l’univers de Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs sont souvent sources d’inquiétude. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Hypothèse de propriété commune des entrées**

Il est généralement rare que des entrées appartenant à différents utilisateurs soient réunies dans une même transaction, en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’entrée d’une même transaction appartiennent au même propriétaire**.

## **Détection de l’adresse de change UTXO**

Un UTXO, ou **sortie de transaction non dépensée**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour limiter ce risque, les services de mixage ou l’utilisation de plusieurs adresses peuvent contribuer à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **de relier facilement une adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs à partir des flux de fonds.

## **Heuristique des entrées inutiles (heuristique de change optimal)**

Cette heuristique consiste à analyser les transactions comportant plusieurs entrées et sorties afin de deviner quelle sortie correspond au change renvoyé à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l'ajout d'entrées supplémentaires rend la sortie de change supérieure à celle de n'importe quelle entrée, cela peut fausser l'heuristique.

## **Réutilisation forcée d'adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d'autres entrées dans de futures transactions, reliant ainsi les adresses entre elles.

### Comportement correct du wallet

Les wallets devraient éviter d'utiliser des bitcoins reçus sur des adresses déjà utilisées et vides afin d'empêcher cette fuite de confidentialité.

## **Autres techniques d'analyse de la blockchain**

- **Montants exacts des paiements :** Les transactions sans sortie de change sont probablement des transactions entre deux adresses appartenant au même utilisateur.
- **Montants ronds :** Un montant rond dans une transaction suggère qu'il s'agit d'un paiement ; la sortie au montant non rond est probablement le change.
- **Empreinte du wallet :** Les différents wallets ont des modèles de création de transactions uniques, ce qui permet aux analystes d'identifier le logiciel utilisé et éventuellement l'adresse de change.
- **Corrélations entre montants et horaires :** La divulgation des horaires ou des montants des transactions peut permettre de les tracer.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C'est particulièrement vrai lorsqu'une entité exploite de nombreux nœuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## Plus d'informations

Pour une liste complète des attaques contre la confidentialité et des défenses, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Façons d'obtenir des bitcoins de manière anonyme

- **Transactions en espèces :** Obtenir des bitcoins en les achetant avec de l'argent liquide.
- **Alternatives aux espèces :** Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining :** La méthode la plus privée pour gagner des bitcoins est le mining, surtout lorsqu'il est effectué seul, car les mining pools peuvent connaître l'adresse IP du mineur. [Informations sur les mining pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol :** En théorie, le vol de bitcoins pourrait être une autre façon de s'en procurer anonymement, mais c'est illégal et déconseillé.

## Services de mixing

En utilisant un service de mixing, un utilisateur peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui complique le traçage du propriétaire initial. Cela suppose toutefois de faire confiance au service : il ne doit pas conserver de logs et doit effectivement restituer les bitcoins. Les casinos Bitcoin constituent une autre option de mixing.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, ce qui complique la tâche de quiconque tente d'associer les entrées aux sorties. Malgré son efficacité, les transactions présentant des tailles d'entrée et de sortie uniques peuvent toujours être traçables.

Parmi les exemples de transactions ayant pu utiliser CoinJoin, on trouve `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour en savoir plus, consultez [CoinJoin](https://coinjoin.io/en). Pour un mixer basé sur un smart contract Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction classique, sans les sorties de montants égaux caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l'heuristique de propriété commune des entrées utilisée par les entités de surveillance des transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait fortement perturber les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des portefeuilles**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les portefeuilles avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : en téléchargeant l’intégralité de la blockchain, un nœud complet garantit une confidentialité maximale. Toutes les transactions effectuées sont stockées localement, ce qui empêche les adversaires de déterminer les transactions ou les adresses qui intéressent l’utilisateur.
- **Filtrage des blocs côté client** : cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, afin que les portefeuilles puissent repérer les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu’ils trouvent une correspondance avec les adresses de l’utilisateur.

## **Utiliser Tor pour préserver l’anonymat**

Bitcoin fonctionnant sur un réseau pair à pair, il est recommandé d’utiliser Tor pour masquer votre adresse IP et ainsi renforcer votre confidentialité lorsque vous interagissez avec le réseau.

## **Éviter la réutilisation des adresses**

Pour préserver la confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation d’adresses peut compromettre la confidentialité en reliant des transactions à une même entité. La conception des portefeuilles modernes décourage la réutilisation des adresses.

## **Stratégies pour préserver la confidentialité des transactions**

- **Transactions multiples** : diviser un paiement en plusieurs transactions peut masquer le montant de la transaction et contrer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : choisir des transactions qui ne nécessitent pas de sortie de monnaie rendue améliore la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Sorties multiples de monnaie rendue** : si éviter la monnaie rendue n’est pas possible, créer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un modèle d’anonymat**

Monero est conçu pour donner la priorité à la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l’effort de calcul nécessaire à l’exécution d’opérations sur Ethereum et est tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique une limite de gas et des frais de base, auxquels s’ajoutent des frais de priorité pour inciter un validateur à l’inclure. Les utilisateurs peuvent définir des frais maximums pour éviter de payer trop cher ; l’excédent leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d’utilisateur ou de smart contract. Elles nécessitent des frais et doivent être incluses dans un bloc. Les informations essentielles d’une transaction comprennent le destinataire, la signature de l’expéditeur, la valeur, des données facultatives, la limite de gas et les frais. À noter que l’adresse de l’expéditeur est déduite de la signature, ce qui évite de devoir l’inclure dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite utiliser des cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## Value-Centric Web3 Red Teaming

- Dresser l’inventaire des composants détenant de la valeur (signers, oracles, bridges, automatisation) afin de comprendre qui peut transférer des fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes pour révéler les chemins d’escalade de privilèges.
- Répéter des chaînes d’attaque impliquant des flash loans, des oracles, des identifiants ou des opérations inter-chaînes afin de valider l’impact et de documenter les conditions préalables exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- La falsification de la chaîne d’approvisionnement des interfaces de portefeuille peut modifier les charges utiles EIP-712 juste avant leur signature et ainsi récupérer des signatures valides pour des prises de contrôle de proxy reposant sur `delegatecall` (par exemple, l’écrasement du slot-0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Parmi les modes de défaillance courants des smart accounts figurent le contournement du contrôle d’accès d’`EntryPoint`, les champs de gas non signés, la validation avec état, le rejeu ERC-1271 et le drainage des frais par un revert après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Tests de mutation pour repérer les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des invités zkVM

Lorsqu’un prover utilise une **zkVM** ou un circuit de preuve spécifique à une application pour attester une affirmation, le vérificateur apprend uniquement que le **programme invité s’est exécuté tel qu’il a été écrit**. Si l’invité comporte une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prover malveillant peut générer une preuve valide alors que les **métriques publiques ou l’invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée dans les invités de preuve

- Traiter les octets de witness/circuit privé comme des **entrées non fiables contrôlées par un attaquant**, même s’ils sont masqués par la preuve.
- Éviter de les désérialiser avec des fonctions auxiliaires sans vérification, comme `rkyv::access_unchecked`, à moins que les octets aient déjà été validés en dehors du système.
- Les discriminants d’énumération, pointeurs relatifs, longueurs et index chargés à partir de données sérialisées non fiables doivent être validés avant d’influencer le flux de contrôle ou l’accès mémoire.

Méthode d’audit pratique :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors limites**, chaque `match` en aval sur cette valeur devient suspect.

### Contournement des compteurs via jump-table / UB

Si Rust compile un grand `match` en **jump table**, un discriminant d’enum invalide peut produire un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **sémantique réelle de l’instruction**.
3. Un discriminant hors limites indexe au-delà de la première jump table et aboutit dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans un zkVM, cela peut permettre de forger des preuves indiquant des métriques impossibles, comme un nombre inférieur de gates, d’opérations coûteuses ou d’autres ressources limitées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par l’attaquant et désérialisés à partir d’un witness/d’une entrée privée.
- Examinez les instructions `match` répétées portant sur le même champ d’opcode/de type.
- Considérez `unsafe` + désérialisation sans vérification + dispatch d’opcodes volumineux comme une combinaison à haut risque.
- Procédez à la rétro-ingénierie du binaire généré si nécessaire ; la disposition des jump tables peut être plus importante que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vérifiez pas uniquement la sécurité mémoire ; vérifiez aussi les **règles sémantiques** que la preuve est censée faire respecter.

Pour les jeux d’instructions réversibles/de type quantique, assurez-vous que les opérandes qui doivent être distincts sont effectivement contraints à l’être. Une opération de type Toffoli/CCX implémentée ainsi :<sup>[[7]](#references)[[8]](#references)</sup>

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

Cela crée une **primitive de réinitialisation déterministe**, qui brise les hypothèses de réversibilité et permet des calculs non prévus à moindre coût. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre à des attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit appliquer.

### Points à tester dans les systèmes ZK

- Fuzzer tous les parsers invités avec des encodages malformés de witness/entrée privée.
- Vérifier que les plages des enums sont validées avant le dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l’aliasing des opérandes et d’autres formes d’instructions invalides.
- Comparer les compteurs déclarés/publics avec une implémentation de référence indépendante.
- Garder à l’esprit qu’une preuve valide peut tout de même prouver la **mauvaise assertion** si le programme invité contient un bug.

## Autorisation dépendante de l’état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation DeFi/AMM

Pour étudier l’exploitation concrète des DEX et des AMM (hooks Uniswap v4, abus d’arrondi/de précision, swaps franchissant un seuil et amplifiés par des flash loans), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache des soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, consultez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d’enjeu - Wikipédia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Explication des clés publiques et privées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions multisignatures ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons vaincu la preuve à divulgation nulle de connaissance de Google sur la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécuriser les cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d’atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
