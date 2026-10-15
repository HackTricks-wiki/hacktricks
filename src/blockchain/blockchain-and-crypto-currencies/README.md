# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

Ce chapitre présente les concepts de la blockchain et la sécurité on-chain. Pour un pair Bitcoin exposé, commencez par l’[énumération du service Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) ; pour un frontend de navigateur, une connexion de portefeuille ou un backend off-chain, consultez le [pentesting des DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Pour les opérations de confidentialité des cryptomonnaies et leurs limites, consultez le [chapitre sur la confidentialité des cryptomonnaies](../../privacy/cryptocurrency-privacy.md).

## Concepts de base

- Les **Smart Contracts** sont des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l’exécution d’accords sans intermédiaires.
- Les **applications décentralisées (dApps)** reposent sur des smart contracts et disposent d’un frontend convivial et d’un backend transparent et auditable.
- Les **tokens et coins** se distinguent par leur usage : les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
  - Les **Utility Tokens** donnent accès à des services, tandis que les **Security Tokens** représentent la propriété d’actifs.
- **DeFi** signifie finance décentralisée et propose des services financiers sans autorités centrales.
- **DEX** et **DAO** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

Pour la terminologie des ordres au comptant, des contrats à terme, de l’effet de levier et des options utilisée sur les marchés crypto, consultez les [termes d’investissement](investment-terms.md).

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et convenue des transactions sur la blockchain :

- La **Proof of Work (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- La **Proof of Stake (PoS)** exige des validateurs qu’ils détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport à la PoW.<sup>[[1]](#references)</sup>

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre des adresses. Elles sont validées par des signatures numériques, garantissant que seul le détenteur de la clé privée peut effectuer des transferts.<sup>[[2]](#references)</sup>

#### Éléments clés :

- Les **transactions multisignatures** exigent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions comprennent des **entrées** (source des fonds), des **sorties** (destination), des **frais** (versés aux mineurs) et des **scripts** (règles de transaction).

### Lightning Network

Ce réseau vise à améliorer l’évolutivité de Bitcoin en permettant plusieurs transactions au sein d’un canal, et en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité liés à Bitcoin

Les attaques contre la confidentialité, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les schémas de transaction. Des stratégies comme les **mixers** et **CoinJoin** renforcent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins anonymement

Les méthodes comprennent les échanges en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer leur traçabilité, tandis que **PayJoin** dissimule les CoinJoin sous l’apparence de transactions ordinaires afin d’améliorer la confidentialité.

# Résumé des attaques contre la confidentialité de Bitcoin

Dans l’univers de Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs suscitent souvent des inquiétudes. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Il est généralement rare que des entrées appartenant à différents utilisateurs soient combinées dans une seule transaction, en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’entrée d’une même transaction appartiennent au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de monnaie. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour atténuer ce risque, des services de mixage ou l’utilisation de plusieurs adresses peuvent aider à masquer la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **de relier facilement l’adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs selon les flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique consiste à analyser les transactions comportant plusieurs entrées et sorties afin de deviner quelle sortie correspond à la monnaie rendue à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l’ajout de plusieurs entrées rend la sortie de monnaie plus importante que n’importe quelle entrée, cela peut induire l’heuristique en erreur.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, dans l’espoir que le destinataire les combine avec d’autres entrées dans de futures transactions, reliant ainsi les adresses entre elles.

### Comportement correct du portefeuille

Les portefeuilles devraient éviter d’utiliser des bitcoins reçus sur des adresses déjà utilisées et vides afin d’empêcher cette fuite de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants exacts des paiements :** Les transactions sans monnaie rendue sont probablement des transactions entre deux adresses appartenant au même utilisateur.
- **Montants ronds :** Un montant rond dans une transaction suggère qu’il s’agit d’un paiement, tandis que la sortie dont le montant n’est pas rond est probablement la monnaie rendue.
- **Empreinte de portefeuille :** Les différents portefeuilles ont des modèles de création de transactions uniques, ce qui permet aux analystes d’identifier le logiciel utilisé et éventuellement l’adresse de monnaie rendue.
- **Corrélations des montants et des horaires :** La divulgation des horaires ou des montants des transactions peut permettre de les retracer.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C’est particulièrement vrai lorsqu’une entité exploite de nombreux nœuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## En savoir plus

Pour consulter une liste complète des attaques et des défenses relatives à la confidentialité, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d’obtenir des bitcoins anonymement

- **Transactions en espèces** : Acquérir des bitcoins en espèces.
- **Alternatives aux espèces** : Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Mining** : La méthode la plus confidentielle pour gagner des bitcoins est le mining, surtout lorsqu’il est effectué seul, car les pools de mining peuvent connaître l’adresse IP du mineur. [Informations sur les pools de mining](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol** : En théorie, voler des bitcoins pourrait être un autre moyen de les acquérir anonymement, même si c’est illégal et déconseillé.

## Services de mixage

En utilisant un service de mixage, un utilisateur peut **envoyer des bitcoins** et en recevoir **d’autres en retour**, ce qui rend difficile le traçage du propriétaire initial. Cela nécessite toutefois de faire confiance au service pour qu’il ne conserve pas de journaux et restitue effectivement les bitcoins. Les casinos Bitcoin constituent une autre option de mixage.

## CoinJoin

**CoinJoin** regroupe plusieurs transactions de différents utilisateurs en une seule, ce qui complique la tâche de quiconque tente d’associer les entrées aux sorties. Malgré son efficacité, les transactions dont les tailles d’entrée et de sortie sont uniques peuvent encore potentiellement être retracées.

Parmi les exemples de transactions susceptibles d’avoir utilisé CoinJoin figurent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour en savoir plus, visitez [CoinJoin](https://coinjoin.io/en). Pour un mixer de smart contracts Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans les sorties égales caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des entrées utilisée par les entités chargées de la surveillance des transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait considérablement perturber les méthodes de surveillance traditionnelles**, ce qui en fait une avancée prometteuse dans la quête de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des wallets**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les wallets avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : En téléchargeant l’intégralité de la blockchain, un nœud complet assure une confidentialité maximale. Toutes les transactions effectuées sont stockées localement, ce qui empêche les adversaires de déterminer les transactions ou les adresses qui intéressent l’utilisateur.
- **Filtrage des blocs côté client** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux wallets d’identifier les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu’une correspondance avec les adresses de l’utilisateur est détectée.

## **Utilisation de Tor pour l’anonymat**

Bitcoin fonctionnant sur un réseau peer-to-peer, il est recommandé d’utiliser Tor pour masquer son adresse IP et renforcer la confidentialité lors des interactions avec le réseau.

## **Éviter la réutilisation des adresses**

Pour protéger sa confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant des transactions à une même entité. Les wallets modernes découragent la réutilisation des adresses par leur conception.

## **Stratégies pour préserver la confidentialité des transactions**

- **Transactions multiples** : Fractionner un paiement en plusieurs transactions peut masquer le montant de la transaction et contrer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : Opter pour des transactions qui ne nécessitent pas de sortie de monnaie rendue améliore la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Plusieurs sorties de monnaie rendue** : S’il est impossible d’éviter la monnaie rendue, générer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un emblème de l’anonymat**

Monero est conçu pour accorder la priorité à la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l’effort de calcul nécessaire à l’exécution d’opérations sur Ethereum et est tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique une limite de gas et des frais de base, auxquels s’ajoutent des frais de priorité pour inciter les validateurs à l’inclure. Les utilisateurs peuvent définir des frais maximums afin de ne pas payer trop cher ; l’excédent leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d’utilisateur ou de smart contract. Elles nécessitent des frais et doivent être incluses dans un bloc. Les informations essentielles d’une transaction comprennent le destinataire, la signature de l’expéditeur, la valeur, les données facultatives, la limite de gas et les frais. À noter que l’adresse de l’expéditeur est déduite de sa signature, ce qui la rend inutile dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont fondamentaux pour toute personne souhaitant utiliser les cryptomonnaies tout en privilégiant la confidentialité et la sécurité.

## Red Teaming Web3 centré sur la valeur

- Dresser l’inventaire des composants détenant de la valeur (signers, oracles, bridges, automatisation) afin de comprendre qui peut déplacer des fonds et comment.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes pour révéler les chemins d’escalade de privilèges.
- Répéter des chaînes d’attaque flash-loan/oracle/identifiants/inter-chaînes afin de valider leur impact et de documenter les préconditions exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- La falsification de la chaîne d’approvisionnement des interfaces de wallet peut modifier les payloads EIP-712 juste avant la signature et récupérer des signatures valides permettant des prises de contrôle de proxy fondées sur `delegatecall` (par exemple, l’écrasement du slot 0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Parmi les modes de défaillance courants des smart accounts figurent le contournement du contrôle d’accès de `EntryPoint`, les champs de gas non signés, la validation avec état, les attaques par rejeu ERC-1271 et l’épuisement des frais via une réversion après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Les tests de mutation permettent de détecter les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des invités zkVM

Lorsqu’un prouveur utilise une **zkVM** ou un circuit de preuve spécifique à une application pour attester une affirmation, le vérificateur apprend uniquement que le **programme invité s’est exécuté comme prévu**. Si l’invité contient une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prouveur malveillant peut générer une preuve valide alors que les **métriques publiques ou l’invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée dans les invités de preuve

- Considérez les octets du witness privé/du circuit comme des **entrées non fiables contrôlées par un attaquant**, même s’ils sont masqués par la preuve.
- Évitez de les désérialiser avec des helpers sans vérification tels que `rkyv::access_unchecked`, à moins que les octets aient déjà été validés par un autre moyen.
- Les discriminants d’enum, les pointeurs relatifs, les longueurs et les index chargés à partir de données sérialisées non fiables doivent être validés avant d’influencer le flux de contrôle ou l’accès mémoire.

Méthode d’audit pratique :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors limites**, chaque `match` en aval devient suspect.

### Contournement des contrôles par jump table / UB

Si Rust compile un grand `match` en **jump table**, un discriminant d’enum invalide peut entraîner un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **sémantique réelle de l’instruction**.
3. Un discriminant hors limites dépasse la première jump table et atterrit dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans une zkVM, cela peut permettre de forger des preuves indiquant des métriques impossibles, comme un nombre inférieur de portes, d’opérations coûteuses ou d’autres ressources limitées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlés par l’attaquant et désérialisés à partir du témoin ou d’une entrée privée.
- Examinez les instructions `match` répétées sur le même champ opcode/kind.
- Considérez l’association de `unsafe`, d’une désérialisation sans vérification et d’un dispatch d’opcode volumineux comme une combinaison à haut risque.
- Procédez à la rétro-ingénierie du binaire généré si nécessaire ; la disposition des jump tables peut être plus importante que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vérifiez pas uniquement la sécurité mémoire ; vérifiez aussi les **règles sémantiques** que la preuve est censée faire respecter.

Pour les jeux d’instructions réversibles ou de type quantique, assurez-vous que les opérandes devant être distincts sont effectivement contraints à l’être. Une opération de type Toffoli/CCX implémentée comme :<sup>[[7]](#references)[[8]](#references)</sup>

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

This crée une **primitive de réinitialisation déterministe**, brisant les hypothèses de réversibilité et permettant des calculs non prévus à moindre coût. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre aux attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit appliquer.

### Conseils du prouveur sous-contraints et arithmétique modulaire

Les valeurs chargées depuis une **pile de conseils/témoins sont contrôlées par le prouveur**, même lorsqu’elles sont décrites comme des quotients, des restes, des inverses ou des indications pré-calculés. Une preuve établit uniquement que le témoin satisfait les contraintes implémentées ; elle n’établit pas que le calcul prévu a été effectué si ces contraintes omettent une vérification de type, de plage ou de forme canonique.<sup>[[13]](#references)</sup>

Pour un auxiliaire de réduction ou de division euclidienne, vérifiez la relation entière complète plutôt que la seule soustraction ou multiplication finale. Chaque limb de `q` et de `r` doit être contraint à la largeur déclarée, la reconstruction `x = q * m + r` doit être valide dans la représentation entière prévue, et la borne canonique `0 <= r < m` doit être imposée. Validez une valeur **avant** de la transmettre à une instruction `u32`/`u64` plus étroite ; une opération sur une valeur étroite ne prouve pas rétroactivement que l’élément initial du corps ou la valeur multi-limbe avait le type attendu.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

L'échec de `mod_12289` dans Miden illustre le schéma d'exploit : le quotient était vérifié comme une valeur de 64 bits sur deux limbs, mais le reste fourni par advice atteignait `u32overflowing_sub` sans validation équivalente. Un prouveur malveillant pouvait coordonner des valeurs de quotient et de reste invalides de sorte que les contraintes de soustraction implémentées restent satisfaites, alors que la procédure renvoyait un reste non mathématique. Comme ce résultat alimentait la vérification Falcon, le défaut de solidité pouvait être exploité pour produire des signatures d'autorisation falsifiées, et non simplement un résultat arithmétique erroné.<sup>[[13]](#references)</sup>

### Audit des VM cryptographiques à pile implicite

Les langages à pile masquent les opérandes. Il faut donc d'abord convertir les instructions en une IR où chaque valeur consommée ou produite sur la pile est une expression avec provenance. Un pipeline d'analyse prudent peut alors :<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construire le graphe d'appels et déduire les effets sur la pile des entrées et sorties des procédures.
2. Exécuter symboliquement les instructions prises en charge et convertir le flot de contrôle en expressions SSA/structurées.
3. Propager des faits abstraits tels que `Unknown`, `ProvenU32`, `Bool`, la provenance des valeurs et l'initialisation locale jusqu'à atteindre un point fixe.
4. Signaler les valeurs dérivées d'advice qui atteignent des opérations arithmétiques typées ou des points d'utilisation non nuls sans assainissement sur **chaque** chemin entrant.
5. Comparer les signatures déclarées et déduites, et vérifier que chaque sortie préserve les valeurs de pile appartenant à l'appelant.

Traitez une signature inconnue ou une construction non prise en charge comme une **lacune d'analyse**, et non comme un résultat sans problème. Les appels dynamiques, les boucles qui ne préservent pas la pile et les branches dont les effets sur la pile diffèrent peuvent rendre impossible le suivi fiable des emplacements de pile ; un décompilateur plus sûr rejette ou marque ces cas au lieu de produire un pseudo-code plausible, mais incorrect.<sup>[[10]](#references)[[13]](#references)</sup>

Aux points de jonction du flot de contrôle, ne conservez une propriété que si elle est vraie pour tous les prédécesseurs (par exemple, `ProvenU32 join Unknown = Unknown`). Distinguez également la convergence au point fixe de l'atteinte d'une limite d'itérations : seule une sur-approximation convergée et solide permet de considérer l'absence de diagnostic comme preuve que toutes les exécutions représentées satisfont la propriété.<sup>[[11]](#references)</sup>

### Utiliser les obligations de preuve pour révéler les préconditions cachées

Pour les petits jeux d'instructions, traduisez les procédures en un modèle de VM formel exécutable et prouvez à la fois le résultat et la transformation complète de la pile. Le théorème doit couvrir la terminaison, les entrées typées, le préfixe de sortie attendu et la préservation de la pile appelante intacte. Auditez l'énoncé du théorème aussi soigneusement que la preuve : le noyau peut valider une preuve d'une affirmation affaiblie par inadvertance.<sup>[[12]](#references)[[13]](#references)</sup>

Les hypothèses inattendues sont des découvertes utiles. Lors de l'audit de Miden, une preuve de la rotation droite sur 64 bits nécessitait `shift mod 32 != 0`, révélant un cas limite défaillant pour les grandes entrées lorsque le décalage était un multiple de 32 ; une autre preuve a révélé que `wrapping_mul` sur 256 bits supprimait des valeurs de pile appartenant à l'appelant. Ajoutez le cas limite découvert aux tests, puis corrigez l'implémentation ou renforcez délibérément la précondition publique, au lieu d'accepter silencieusement l'hypothèse supplémentaire.<sup>[[12]](#references)[[13]](#references)</sup>

### Que tester dans les systèmes ZK

- Fuzzer tous les analyseurs syntaxiques invités avec des encodages malformés de témoins/d'entrées privées.
- Vérifier la validation de la plage des enums avant la distribution des opcodes.
- Ajouter des vérifications sémantiques pour l'aliasing des opérandes et les autres formes d'instructions invalides.
- Suivre chaque source d'advice/témoin jusqu'à chaque point d'utilisation arithmétique typé et exiger une validation sur chaque chemin.<sup>[[11]](#references)[[13]](#references)</sup>
- Tester les fonctions arithmétiques avec des limbs non canoniques, des restes hors plage et des nombres de décalage limites.<sup>[[12]](#references)[[13]](#references)</sup>
- Vérifier la hauteur de pile et la préservation des valeurs situées sous les arguments déclarés de la procédure à chaque retour.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Comparer les compteurs signalés/publics à une implémentation de référence indépendante.
- N'oubliez pas qu'une preuve valide peut tout de même prouver la **mauvaise affirmation** si le programme invité est bogué.

## Autorisation dépendante de l'état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation DeFi/AMM

Si vous étudiez l'exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus des arrondis/de la précision, swaps amplifiés par flash loan qui franchissent des seuils), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-actifs qui mettent en cache des soldes virtuels et peuvent être empoisonnés lorsque `supply == 0`, consultez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Preuve d'enjeu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Explication des clés publiques et privées - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Que sont les transactions multisignatures ? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas et frais | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Confidentialité - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nous avons battu la preuve à divulgation nulle de connaissance de Google sur la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécuriser les cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d'atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architecture du décompilateur MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Moteur d'analyse statique MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modèle MASM vers Lean et preuves de correction](https://github.com/trailofbits/masm-lean)
- [13] [Auditer à l'ère de l'IA (suffisamment bonne)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
