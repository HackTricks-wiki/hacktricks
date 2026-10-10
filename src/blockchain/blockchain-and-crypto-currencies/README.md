# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- **Smart Contracts** désigne des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l’exécution d’accords sans intermédiaires.
- Les **applications décentralisées (dApps)** s’appuient sur des smart contracts et disposent d’une interface front-end conviviale et d’un back-end transparent et auditable.
- **Tokens & Coins** se distinguent par le fait que les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes précis.
  - Les **Utility Tokens** donnent accès à des services, et les **Security Tokens** indiquent la propriété d’un actif.
- **DeFi** signifie Decentralized Finance et propose des services financiers sans autorités centrales.
- **DEX** et **DAOs** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et concertée des transactions sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- **Proof of Stake (PoS)** exige que les validateurs détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport au PoW.<sup>[[1]](#references)</sup>

## Les fondamentaux de Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre des adresses. Elles sont validées au moyen de signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.<sup>[[2]](#references)</sup>

#### Éléments clés :

- Les **transactions multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions se composent d’**inputs** (source des fonds), d’**outputs** (destination), de **frais** (versés aux mineurs) et de **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d’un canal, et en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité de Bitcoin

Les attaques contre la confidentialité, telles que la **propriété commune des inputs** et la **détection des adresses de change UTXO**, exploitent les schémas de transaction. Des stratégies comme les **Mixers** et **CoinJoin** améliorent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins de manière anonyme

Les méthodes incluent les transactions en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer leur traçabilité, tandis que **PayJoin** dissimule les CoinJoins sous l’apparence de transactions ordinaires afin d’améliorer la confidentialité.

# Résumé des attaques contre la confidentialité de Bitcoin

Dans le monde de Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs sont souvent sujets à préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes permettant aux attaquants de compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Hypothèse de propriété commune des inputs**

Il est généralement rare que des inputs appartenant à différents utilisateurs soient combinés dans une même transaction, en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’input dans une même transaction appartiennent au même propriétaire**.

## **Détection des adresses de change UTXO**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour limiter ce risque, les services de mixage ou l’utilisation de plusieurs adresses peuvent aider à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **de relier facilement l’adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs en fonction des flux de fonds.

## **Heuristique des inputs inutiles (heuristique du change optimal)**

Cette heuristique repose sur l’analyse des transactions comportant plusieurs inputs et outputs afin de deviner quel output correspond au change renvoyé à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l’ajout d’entrées supplémentaires rend la sortie de change plus importante que n’importe quelle entrée individuelle, cela peut induire l’heuristique en erreur.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine avec d’autres entrées dans de futures transactions, reliant ainsi les adresses entre elles.

### Comportement correct du portefeuille

Les portefeuilles devraient éviter d’utiliser des bitcoins reçus sur des adresses déjà utilisées et vides afin de prévenir cette fuite de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants de paiement exacts :** Les transactions sans monnaie rendue ont probablement lieu entre deux adresses appartenant au même utilisateur.
- **Nombres ronds :** Un nombre rond dans une transaction laisse penser qu’il s’agit d’un paiement, la sortie dont le montant n’est pas rond étant probablement la monnaie rendue.
- **Empreinte du portefeuille :** Les différents portefeuilles ont des modèles de création de transactions qui leur sont propres, ce qui permet aux analystes d’identifier le logiciel utilisé et éventuellement l’adresse de change.
- **Corrélations entre montant et horaire :** Divulguer les heures ou les montants des transactions peut permettre de les tracer.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement associer des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C’est particulièrement vrai lorsqu’une entité exploite de nombreux nœuds Bitcoin, ce qui accroît sa capacité à surveiller les transactions.

## Plus d’informations

Pour obtenir une liste complète des attaques visant la confidentialité et des moyens de s’en protéger, consultez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Comment obtenir des bitcoins de manière anonyme

- **Transactions en espèces** : Acquérir des bitcoins en espèces.
- **Alternatives aux espèces** : Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Minage** : La méthode la plus privée pour gagner des bitcoins est le minage, surtout lorsqu’il est effectué seul, car les pools de minage peuvent connaître l’adresse IP du mineur. [Informations sur les pools de minage](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol** : En théorie, voler des bitcoins pourrait être une autre façon de s’en procurer anonymement, mais c’est illégal et déconseillé.

## Services de mélange

En utilisant un service de mélange, un utilisateur peut **envoyer des bitcoins** et recevoir **d’autres bitcoins en retour**, ce qui complique le traçage jusqu’au propriétaire d’origine. Toutefois, cela exige de faire confiance au service : il ne doit pas conserver de journaux et doit effectivement restituer les bitcoins. Les casinos Bitcoin constituent une autre option de mélange.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant la tâche de quiconque cherche à faire correspondre les entrées et les sorties. Malgré son efficacité, les transactions dont les montants des entrées et des sorties sont uniques peuvent toujours être tracées.

Parmi les exemples de transactions ayant pu utiliser CoinJoin, on trouve `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d’informations, consultez [CoinJoin](https://coinjoin.io/en). Pour un mixer de smart contracts Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans les sorties égales caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des entrées utilisée par les entités qui surveillent les transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait perturber considérablement les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des portefeuilles**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les portefeuilles avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : en téléchargeant l’intégralité de la blockchain, un nœud complet assure une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui empêche les adversaires de déterminer les transactions ou les adresses qui intéressent l’utilisateur.
- **Filtrage des blocs côté client** : cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, afin que les portefeuilles puissent repérer les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu’une correspondance est trouvée avec les adresses de l’utilisateur.

## **Utiliser Tor pour l’anonymat**

Bitcoin fonctionnant sur un réseau pair-à-pair, il est recommandé d’utiliser Tor pour masquer votre adresse IP et ainsi renforcer la confidentialité lors des interactions avec le réseau.

## **Éviter la réutilisation des adresses**

Pour préserver la confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant des transactions à une même entité. La conception des portefeuilles modernes décourage la réutilisation des adresses.

## **Stratégies de confidentialité des transactions**

- **Transactions multiples** : diviser un paiement en plusieurs transactions peut masquer le montant de la transaction et déjouer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : privilégier les transactions qui ne nécessitent pas de sortie de monnaie rendue renforce la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Plusieurs sorties de monnaie rendue** : s’il est impossible d’éviter la monnaie rendue, générer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un modèle d’anonymat**

Monero est conçu pour donner la priorité à la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l’effort de calcul nécessaire à l’exécution d’opérations sur Ethereum ; son prix est exprimé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (soit 0.00231 ETH) implique une limite de gas et des frais de base, auxquels s’ajoutent des frais prioritaires pour inciter un validateur à l’inclure. Les utilisateurs peuvent définir des frais maximaux pour éviter de payer trop cher ; le surplus leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d’utilisateur ou de smart contract. Elles nécessitent des frais et doivent être incluses dans un bloc. Les informations essentielles d’une transaction comprennent le destinataire, la signature de l’expéditeur, la valeur, les données facultatives, la limite de gas et les frais. Il est à noter que l’adresse de l’expéditeur est déduite de la signature, ce qui évite de devoir l’inclure dans les données de transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont essentiels à toute personne souhaitant utiliser des cryptomonnaies tout en donnant la priorité à la confidentialité et à la sécurité.

## Red teaming Web3 axé sur la valeur

- Répertorier les composants détenant de la valeur (signers, oracles, bridges, automatisation) afin de comprendre qui peut déplacer des fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes pour révéler les voies d’escalade de privilèges.
- Répéter des chaînes d’attaque impliquant des flash loans, des oracles, des identifiants ou des interactions inter-chaînes afin de valider l’impact et de documenter les conditions préalables exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- Une altération de la chaîne d’approvisionnement des interfaces de portefeuille peut modifier les charges utiles EIP-712 juste avant leur signature et ainsi récupérer des signatures valides pour des prises de contrôle de proxy basées sur `delegatecall` (par exemple, l’écrasement du slot 0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Parmi les modes de défaillance courants des smart accounts figurent le contournement du contrôle d’accès de `EntryPoint`, les champs de gas non signés, la validation avec état, les attaques par rejeu ERC-1271 et le drainage des frais par revert après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Tests par mutation pour repérer les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des invités zkVM

Lorsqu’un prouveur utilise un **zkVM** ou un circuit de preuve propre à une application pour attester une affirmation, le vérificateur apprend uniquement que le **programme invité s’est exécuté conformément à sa définition**. Si l’invité contient une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prouveur malveillant peut générer une preuve valide alors que les **mesures publiques ou l’invariant affirmé sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée dans les invités de preuve

- Traiter les octets du témoin privé/circuit comme des **entrées non fiables contrôlées par un attaquant**, même s’ils sont masqués par la preuve.
- Éviter de les désérialiser avec des fonctions non vérifiées telles que `rkyv::access_unchecked`, sauf si les octets ont déjà été validés par un autre moyen.
- Les discriminants d’énumération, les pointeurs relatifs, les longueurs et les index chargés à partir de données sérialisées non fiables doivent être validés avant d’influencer le flux de contrôle ou l’accès mémoire.

Méthode d’audit pratique :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors limites**, chaque `match` en aval sur cette valeur devient suspect.

### Contournement des compteurs via jump table / UB

Si Rust compile un grand `match` en **jump table**, un discriminant d’enum invalide peut entraîner un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` applique la **sémantique réelle de l’instruction**.
3. Un discriminant hors limites indexe au-delà de la première jump table et aboutit dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans une zkVM, cela peut permettre de forger des preuves qui indiquent des métriques impossibles, telles qu’un nombre réduit de gates, moins d’opérations coûteuses ou d’autres ressources bornées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par l’attaquant et désérialisés à partir d’un témoin/d’une entrée privée.
- Examinez les instructions `match` répétées qui portent sur le même champ opcode/kind.
- Considérez `unsafe` + désérialisation sans vérification + dispatch de gros opcodes comme une combinaison à haut risque.
- Faites de la rétro-ingénierie du binaire généré si nécessaire ; la disposition des jump tables peut compter davantage que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vérifiez pas uniquement la sécurité mémoire ; vérifiez aussi les **règles sémantiques** que la preuve est censée faire respecter.

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

Cela crée une **primitive de réinitialisation déterministe**, qui brise les hypothèses de réversibilité et permet des calculs non prévus à moindre coût. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre aux attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit appliquer.

### Éléments à tester dans les systèmes ZK

- Fuzzer tous les parseurs guest avec des encodages de witness/private-input malformés.
- Vérifier la plage des enums avant le dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l’aliasing des opérandes et les autres formes d’instructions invalides.
- Comparer les compteurs déclarés/publics à une implémentation de référence indépendante.
- Garder à l’esprit qu’une preuve valide peut tout de même prouver la **mauvaise affirmation** si le programme guest est bogué.

## Autorisation dépendante de l’état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation DeFi/AMM

Pour étudier l’exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus des arrondis/de la précision, swaps amplifiés par flash loan qui franchissent un seuil), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache les soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, consultez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d’enjeu - Wikipédia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clé publique et clé privée expliquées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions multi-signatures ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons vaincu la preuve à divulgation nulle de connaissance de Google en matière de cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécuriser les cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d’atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
