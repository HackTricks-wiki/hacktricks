# Blockchain et crypto-monnaies

{{#include ../../banners/hacktricks-training.md}}

## Concepts de base

- Les **smart contracts** sont des programmes qui s’exécutent sur une blockchain lorsque certaines conditions sont remplies. Ils automatisent l’exécution d’accords sans intermédiaires.
- Les **applications décentralisées (dApps)** s’appuient sur des smart contracts et disposent d’une interface conviviale et d’un back-end transparent et vérifiable.
- Les **tokens et les coins** se distinguent par leur usage : les coins servent de monnaie numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes précis.
  - Les **utility tokens** donnent accès à des services, tandis que les **security tokens** représentent la propriété d’un actif.
- **DeFi** signifie finance décentralisée et désigne des services financiers sans autorité centrale.
- **DEX** et **DAO** désignent respectivement les plateformes d’échange décentralisées et les organisations autonomes décentralisées.

Pour connaître la terminologie des ordres au comptant, des contrats à terme, de l’effet de levier et des options sur les marchés des crypto-monnaies, consultez [les termes de l’investissement](investment-terms.md).

## Mécanismes de consensus

Les mécanismes de consensus garantissent la validation sécurisée et consensuelle des transactions sur la blockchain :

- La **Proof of Work (PoW)** repose sur la puissance de calcul pour vérifier les transactions.
- La **Proof of Stake (PoS)** exige des validateurs qu’ils détiennent une certaine quantité de tokens, ce qui réduit la consommation d’énergie par rapport à la PoW.<sup>[[1]](#references)</sup>

## Notions essentielles sur Bitcoin

### Transactions

Les transactions Bitcoin consistent à transférer des fonds entre des adresses. Elles sont validées à l’aide de signatures numériques, ce qui garantit que seul le détenteur de la clé privée peut initier des transferts.<sup>[[2]](#references)</sup>

#### Composants clés :

- Les **transactions multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.<sup>[[3]](#references)</sup>
- Les transactions comprennent des **entrées** (source des fonds), des **sorties** (destination), des **frais** (versés aux mineurs) et des **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer l’évolutivité de Bitcoin en permettant d’effectuer plusieurs transactions au sein d’un canal, tout en ne diffusant que l’état final sur la blockchain.

## Problèmes de confidentialité liés à Bitcoin

Les attaques visant la confidentialité, telles que la **propriété commune des entrées** et la **détection des adresses de rendu UTXO**, exploitent les schémas de transaction. Des méthodes comme les **mixers** et **CoinJoin** améliorent l’anonymat en masquant les liens entre les transactions des utilisateurs.

## Acquérir des bitcoins anonymement

Les méthodes comprennent les échanges en espèces, le minage et l’utilisation de mixers. **CoinJoin** mélange plusieurs transactions afin de compliquer leur traçabilité, tandis que **PayJoin** dissimule les CoinJoins en les faisant passer pour des transactions ordinaires, pour une meilleure confidentialité.

# Résumé des attaques visant la confidentialité de Bitcoin

Dans l’univers de Bitcoin, la confidentialité des transactions et l’anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes permettant aux attaquants de compromettre la confidentialité de Bitcoin.<sup>[[6]](#references)</sup>

## **Hypothèse de propriété commune des entrées**

Il est généralement rare que des entrées appartenant à différents utilisateurs soient regroupées dans une même transaction en raison de la complexité que cela implique. Ainsi, **on suppose souvent que deux adresses d’entrée d’une même transaction appartiennent au même propriétaire**.

## **Détection des adresses de rendu UTXO**

Un UTXO, ou **sortie de transaction non dépensée**, doit être entièrement dépensé dans une transaction. Si une partie seulement est envoyée à une autre adresse, le reste est envoyé à une nouvelle adresse de rendu. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l’expéditeur, ce qui compromet sa confidentialité.

### Exemple

Pour atténuer ce problème, des services de mélange ou l’utilisation de plusieurs adresses peuvent aider à dissimuler la propriété.

## **Exposition sur les réseaux sociaux et les forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui permet **de facilement associer une adresse à son propriétaire**.

## **Analyse du graphe des transactions**

Les transactions peuvent être représentées sous forme de graphes, révélant des liens potentiels entre les utilisateurs en fonction des flux de fonds.

## **Heuristique des entrées inutiles (heuristique du rendu optimal)**

Cette heuristique consiste à analyser les transactions comportant plusieurs entrées et sorties afin de deviner quelle sortie correspond au rendu renvoyé à l’expéditeur.

### Exemple

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si l’ajout d’entrées supplémentaires rend le montant de la monnaie supérieur à celui de n’importe quelle entrée, cela peut induire l’heuristique en erreur.

## **Réutilisation forcée d’adresses**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, en espérant que le destinataire les combine à d’autres entrées lors de transactions ultérieures, reliant ainsi les adresses entre elles.

### Comportement correct du portefeuille

Les portefeuilles devraient éviter d’utiliser des bitcoins reçus sur des adresses déjà utilisées et vides, afin d’empêcher ce leak de confidentialité.

## **Autres techniques d’analyse de la blockchain**

- **Montants exacts des paiements :** Les transactions sans monnaie sont probablement effectuées entre deux adresses appartenant au même utilisateur.
- **Montants arrondis :** Un montant arrondi dans une transaction suggère qu’il s’agit d’un paiement, et que la sortie non arrondie correspond probablement à la monnaie.
- **Empreinte du portefeuille :** Les portefeuilles ont des modèles de création de transactions distincts, ce qui permet aux analystes d’identifier le logiciel utilisé et éventuellement l’adresse de monnaie.
- **Corrélations entre montants et horaires :** La divulgation des heures ou des montants des transactions peut les rendre traçables.

## **Analyse du trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant ainsi la confidentialité des utilisateurs. C’est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, ce qui renforce sa capacité à surveiller les transactions.

## Plus d’informations

Pour une liste complète des attaques contre la confidentialité et des mesures de défense, consultez [Confidentialité Bitcoin sur Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions Bitcoin anonymes

## Moyens d’obtenir des bitcoins anonymement

- **Transactions en espèces** : Obtenir des bitcoins en payant en espèces.
- **Alternatives aux espèces** : Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Minage** : Le moyen le plus confidentiel de gagner des bitcoins est le minage, surtout lorsqu’il est effectué en solo, car les pools de minage peuvent connaître l’adresse IP du mineur. [Informations sur les pools de minage](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol** : En théorie, voler des bitcoins pourrait être un autre moyen d’en acquérir anonymement, bien que ce soit illégal et déconseillé.

## Services de mixage

En utilisant un service de mixage, un utilisateur peut **envoyer des bitcoins** et recevoir **d’autres bitcoins en retour**, ce qui rend difficile la traçabilité du propriétaire d’origine. Toutefois, cela nécessite de faire confiance au service pour qu’il ne conserve pas de journaux et restitue réellement les bitcoins. Les casinos Bitcoin constituent une autre option de mixage.

## CoinJoin

**CoinJoin** regroupe plusieurs transactions de différents utilisateurs en une seule, ce qui complique la tâche de quiconque tente d’associer les entrées aux sorties. Malgré son efficacité, les transactions présentant des tailles d’entrée et de sortie uniques peuvent toujours être potentiellement tracées.

Parmi les transactions qui pourraient avoir utilisé CoinJoin figurent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d’informations, consultez [CoinJoin](https://coinjoin.io/en). Pour un mixer de smart contracts Ethereum qui sépare les dépôts des retraits ultérieurs, consultez [Tornado Cash](https://tornado.cash).

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) dissimule une transaction entre deux parties (par exemple, un client et un commerçant) en la faisant passer pour une transaction ordinaire, sans les sorties égales caractéristiques de CoinJoin. Cela la rend extrêmement difficile à détecter et pourrait invalider l’heuristique de propriété commune des entrées utilisée par les entités chargées de la surveillance des transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L'utilisation de PayJoin pourrait perturber considérablement les méthodes de surveillance traditionnelles**, ce qui en fait une évolution prometteuse dans la recherche de la confidentialité des transactions.

# Bonnes pratiques pour préserver la confidentialité des cryptomonnaies

## **Techniques de synchronisation des portefeuilles**

Pour préserver la confidentialité et la sécurité, il est essentiel de synchroniser les portefeuilles avec la blockchain. Deux méthodes se distinguent :

- **Nœud complet** : En téléchargeant l'intégralité de la blockchain, un nœud complet garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui empêche les adversaires de déterminer quelles transactions ou adresses intéressent l'utilisateur.
- **Filtrage des blocs côté client** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans révéler leurs intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres et ne récupèrent les blocs complets que lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utilisation de Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau pair à pair, il est recommandé d'utiliser Tor pour masquer votre adresse IP et renforcer votre confidentialité lorsque vous interagissez avec le réseau.

## **Éviter la réutilisation des adresses**

Pour protéger votre confidentialité, il est essentiel d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant les transactions à une même entité. Les portefeuilles modernes sont conçus pour décourager la réutilisation des adresses.

## **Stratégies pour préserver la confidentialité des transactions**

- **Transactions multiples** : Diviser un paiement en plusieurs transactions peut masquer le montant de la transaction et déjouer les attaques visant la confidentialité.
- **Éviter la monnaie rendue** : Opter pour des transactions qui ne nécessitent pas de sorties de monnaie rendue renforce la confidentialité en perturbant les méthodes de détection de la monnaie rendue.
- **Sorties multiples de monnaie rendue** : S'il est impossible d'éviter la monnaie rendue, générer plusieurs sorties de monnaie rendue peut tout de même améliorer la confidentialité.

# **Monero : un modèle d'anonymat**

Monero est conçu pour privilégier la confidentialité des transactions.

# **Ethereum : gas et transactions**

## **Comprendre le gas**

Le gas mesure l'effort de calcul nécessaire à l'exécution d'opérations sur Ethereum et est tarifé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) comporte une limite de gas et des frais de base, auxquels s'ajoutent des frais de priorité pour inciter les validateurs à l'inclure. Les utilisateurs peuvent définir des frais maximums afin de ne pas payer trop cher ; l'excédent leur est remboursé.<sup>[[5]](#references)</sup>

## **Exécuter des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d'utilisateur ou de smart contract. Elles nécessitent des frais et doivent être incluses dans un bloc. Les informations essentielles d'une transaction comprennent le destinataire, la signature de l'expéditeur, la valeur, des données facultatives, la limite de gas et les frais. À noter que l'adresse de l'expéditeur est déduite de sa signature, ce qui évite de devoir l'inclure dans les données de la transaction.<sup>[[4]](#references)</sup>

Ces pratiques et mécanismes sont fondamentaux pour toute personne souhaitant utiliser des cryptomonnaies tout en privilégiant la confidentialité et la sécurité.

## Red Teaming Web3 centré sur la valeur

- Inventorier les composants qui détiennent des actifs (signataires, oracles, bridges, automatisation) afin de déterminer qui peut déplacer des fonds et de quelle manière.
- Associer chaque composant aux tactiques MITRE AADAPT pertinentes pour révéler les chemins d'escalade de privilèges.
- Répéter des chaînes d'attaque impliquant des flash loans, des oracles, des identifiants ou des opérations inter-chaînes afin de valider l'impact et de documenter les préconditions exploitables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromission du workflow de signature Web3

- La falsification de la chaîne d'approvisionnement des interfaces utilisateur de portefeuilles peut modifier les payloads EIP-712 juste avant la signature et ainsi récupérer des signatures valides permettant des prises de contrôle de proxy fondées sur delegatecall (par exemple, l'écrasement de slot-0 du masterCopy de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraction de compte (ERC-4337)

- Parmi les modes de défaillance courants des smart accounts figurent le contournement du contrôle d'accès d'`EntryPoint`, les champs de gas non signés, la validation avec état, les attaques par rejeu ERC-1271 et l'épuisement des frais par revert après validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sécurité des smart contracts

- Tests par mutation pour détecter les angles morts des suites de tests :

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Intégrité des preuves ZK / des invités zkVM

Lorsqu'un prouveur utilise une **zkVM** ou un circuit de preuve spécifique à l'application pour attester une affirmation, le vérificateur apprend uniquement que le **programme invité s'est exécuté conformément à sa définition**. Si l'invité contient une **désérialisation non sécurisée**, un **comportement indéfini** ou des **contraintes sémantiques manquantes**, un prouveur malveillant peut générer une preuve valide alors que les **mesures publiques ou l'invariant revendiqué sont faux**.<sup>[[7]](#references)</sup>

### Désérialisation non sécurisée au sein des invités de preuve

- Traiter les octets du témoin privé/circuit comme des **données non fiables fournies par un attaquant**, même s'ils sont masqués par la preuve.
- Éviter de les désérialiser à l'aide de fonctions non vérifiées comme `rkyv::access_unchecked`, sauf si les octets ont déjà été validés hors bande.
- Les discriminants d'énumération, les pointeurs relatifs, les longueurs et les index chargés à partir de données sérialisées non fiables doivent être validés avant d'influencer le flux de contrôle ou l'accès à la mémoire.

Méthode d'audit pratique :

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un champ tel que `op.kind` est une enum et qu’un attaquant peut injecter un **discriminant hors plage**, chaque `match` en aval sur cette valeur devient suspect.

### Contournement des compteurs via table de sauts / comportement indéfini

Si Rust compile un grand `match` en **table de sauts**, un discriminant d’enum invalide peut entraîner un **flux de contrôle indéfini**. Voici un schéma dangereux :<sup>[[7]](#references)[[9]](#references)</sup>

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **sémantique réelle de l’instruction**.
3. Un discriminant hors plage indexe au-delà de la première table de sauts et atterrit dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans une zkVM, cela peut permettre de forger des preuves qui indiquent des métriques impossibles, telles qu’un nombre réduit de portes, moins d’opérations coûteuses ou d’autres ressources bornées falsifiées.

Liste de vérification :

- Recherchez les enums contrôlées par l’attaquant et désérialisées à partir du witness ou d’une entrée privée.
- Examinez les `match` répétés sur le même champ d’opcode/de type.
- Considérez `unsafe` + désérialisation sans vérification + dispatch d’opcodes volumineux comme une combinaison à haut risque.
- Faites de la rétro-ingénierie du binaire généré si nécessaire ; la disposition des tables de sauts peut compter davantage que le code source.

### Contraintes sémantiques manquantes dans les interpréteurs réversibles/spécialisés

Ne vous contentez pas de valider la sûreté mémoire ; validez aussi les **règles sémantiques** que la preuve est censée appliquer.

Pour les jeux d’instructions réversibles/quantiques, assurez-vous que les opérandes qui doivent être distincts sont effectivement contraints à l’être. Une opération de type Toffoli/CCX implémentée ainsi :<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

devient dangereuse si l’invité ne rejette pas :

```text
op.q_control1 == op.q_control2 == op.q_target
```

Dans ce cas, la transition se réduit à :

```text
q = q ^ (q & q) = 0
```

Cela crée une **primitive de réinitialisation déterministe**, qui brise les hypothèses de réversibilité et permet des calculs non intentionnels moins coûteux. Dans les systèmes de preuve qui attestent de l’utilisation des ressources, cela peut permettre aux attaquants de satisfaire aux vérifications fonctionnelles tout en contournant le modèle de coût que le vérificateur croit appliquer.

### Conseils du prouveur sous-contraints et arithmétique modulaire

Les valeurs chargées depuis une **pile de conseils/témoins sont contrôlées par le prouveur**, même lorsqu’elles sont décrites comme des quotients, des restes, des inverses ou des indications précalculés. Une preuve établit uniquement que le témoin satisfait aux contraintes implémentées ; elle n’établit pas que le calcul prévu a été effectué si ces contraintes omettent une vérification de type, de plage ou de forme canonique.<sup>[[13]](#references)</sup>

Pour un helper de réduction ou de division euclidienne, vérifiez la relation entière complète plutôt que seulement la soustraction ou la multiplication finale. Chaque limb de `q` et de `r` doit être contraint à la largeur déclarée, la reconstruction `x = q * m + r` doit être valide dans la représentation entière prévue, et la borne canonique `0 <= r < m` doit être appliquée. Validez une valeur **avant** de la transmettre à une instruction `u32`/`u64` plus étroite ; une opération de largeur réduite ne prouve pas rétroactivement que l’élément de champ d’origine ou la valeur multi-limbe avait le type attendu.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

L’échec de `mod_12289` dans Miden illustre le schéma d’exploitation : le quotient était vérifié comme une valeur 64 bits sur deux limbs, mais le reste fourni par advice atteignait `u32overflowing_sub` sans validation équivalente. Un prover malveillant pouvait coordonner des valeurs de quotient et de reste invalides de sorte que les contraintes de soustraction implémentées restent satisfaites, tandis que la procédure renvoyait un reste non mathématique. Comme ce résultat alimentait la vérification Falcon, cette faille de soundness pouvait être exploitée pour forger des signatures d’autorisation, et pas seulement produire un résultat arithmétique erroné.<sup>[[13]](#references)</sup>

### Auditer les VM cryptographiques à pile implicite

Les langages à pile masquent les opérandes. Il faut donc d’abord convertir les instructions en IR, où chaque valeur consommée ou produite sur la pile est représentée par une expression dont la provenance est connue. Un pipeline d’analyse conservateur peut alors :<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construire le graphe d’appels et déduire les effets sur la pile des entrées et sorties de chaque procédure.
2. Exécuter symboliquement les instructions prises en charge et convertir le flot de contrôle en expressions SSA/structurées.
3. Propager des faits abstraits comme `Unknown`, `ProvenU32`, `Bool`, la provenance des valeurs et l’initialisation locale jusqu’à atteindre un point fixe.
4. Signaler les valeurs dérivées d’advice qui atteignent des opérations arithmétiques typées ou des sinks non nuls sans assainisseur sur **chaque** chemin entrant.
5. Comparer les signatures déclarées et déduites, et vérifier que chaque sortie préserve les valeurs de pile appartenant à l’appelant.

Traitez une signature inconnue ou une construction non prise en charge comme une **lacune d’analyse**, et non comme un résultat sans problème. Les appels dynamiques, les boucles qui ne préservent pas la pile et les branches ayant des effets différents sur la pile peuvent rendre impossible un suivi fiable des emplacements de pile ; un décompilateur plus sûr rejette ces cas ou les marque au lieu d’émettre du pseudocode plausible, mais incorrect.<sup>[[10]](#references)[[13]](#references)</sup>

Aux jonctions du flot de contrôle, ne conservez une propriété que si elle est vraie pour tous les prédécesseurs (par exemple, `ProvenU32 join Unknown = Unknown`). Distinguez aussi la convergence vers un point fixe de l’atteinte d’une limite d’itérations : seule une sur-approximation convergée et correcte permet de considérer l’absence de diagnostic comme une preuve que toutes les exécutions représentées satisfont la propriété.<sup>[[11]](#references)</sup>

### Utiliser des obligations de preuve pour révéler les préconditions cachées

Pour les petits jeux d’instructions, traduisez les procédures en un modèle de VM formel exécutable et prouvez à la fois le résultat et la transformation complète de la pile. Le théorème doit couvrir la terminaison, les entrées typées, le préfixe de sortie attendu et la préservation de la pile de l’appelant qui n’a pas été modifiée. Examinez l’énoncé du théorème aussi attentivement que la preuve : le kernel peut valider la preuve d’une affirmation affaiblie par inadvertance.<sup>[[12]](#references)[[13]](#references)</sup>

Les hypothèses inattendues sont des découvertes utiles. Lors de l’audit de Miden, une preuve de la rotation à droite sur 64 bits exigeait `shift mod 32 != 0`, révélant un cas limite qui échouait pour les grandes entrées lorsque le décalage était un multiple de 32 ; une autre preuve a montré que `wrapping_mul` sur 256 bits supprimait des valeurs de pile appartenant à l’appelant. Ajoutez le cas limite découvert aux tests, puis corrigez l’implémentation ou renforcez délibérément la précondition publique, plutôt que d’accepter silencieusement cette hypothèse supplémentaire.<sup>[[12]](#references)[[13]](#references)</sup>

### Que tester dans les systèmes ZK

- Fuzzer tous les parseurs guest avec des encodages malformés de witness/entrées privées.
- Vérifier la validation de la plage des enums avant le dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l’aliasing des opérandes et les autres formes d’instructions invalides.
- Suivre chaque source d’advice/witness jusqu’à chaque sink arithmétique typé et exiger une validation sur chaque chemin.<sup>[[11]](#references)[[13]](#references)</sup>
- Tester les helpers arithmétiques avec des limbs non canoniques, des restes hors plage et des valeurs limites de décalage.<sup>[[12]](#references)[[13]](#references)</sup>
- Vérifier la hauteur de la pile et la préservation des valeurs situées sous les arguments déclarés de la procédure à chaque retour.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Comparer les compteurs rapportés/publics à une implémentation de référence indépendante.
- N’oubliez pas qu’une preuve valide peut quand même prouver la **mauvaise affirmation** si le programme guest est bogué.

## Autorisation dépendante de l’état

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation DeFi/AMM

Si vous étudiez l’exploitation pratique des DEX et des AMM (hooks Uniswap v4, abus des arrondis/de la précision, swaps amplifiés par des flash loans qui franchissent des seuils), consultez :

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
- [7] [Trail of Bits - Nous avons vaincu la preuve à divulgation nulle de connaissance de Google pour la cryptanalyse quantique](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sécuriser les cryptomonnaies à courbe elliptique contre les vulnérabilités quantiques : estimations des ressources et mesures d’atténuation (version corrigée)](https://arxiv.org/abs/2603.28846v2)
- [9] [Dépôt de preuve de concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architecture du décompilateur MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Moteur d’analyse statique MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modèle MASM-vers-Lean et preuves de correction](https://github.com/trailofbits/masm-lean)
- [13] [L’audit à l’ère de l’IA (suffisamment bonne)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
