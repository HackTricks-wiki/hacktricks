# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- **Decentralized Applications (dApps)** s'appuient sur des smart contracts, avec un front-end convivial et un back-end transparent et vérifiable.
- **Tokens & Coins** distinguent le fait que les coins servent d'argent numérique, tandis que les tokens représentent une valeur ou une propriété dans des contextes spécifiques.
- **Utility Tokens** donnent accès à des services, et les **Security Tokens** signifient la propriété d'un actif.
- **DeFi** signifie Decentralized Finance, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** désignent respectivement des Decentralized Exchange Platforms et des Decentralized Autonomous Organizations.

## Consensus Mechanisms

Les mécanismes de consensus garantissent des validations de transactions sécurisées et approuvées sur la blockchain :

- **Proof of Work (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Proof of Stake (PoS)** exige des validateurs qu'ils détiennent une certaine quantité de tokens, réduisant la consommation d'énergie par rapport à PoW.

## Bitcoin Essentials

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre des adresses. Les transactions sont validées au moyen de signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Key Components:

- Les transactions **Multisignature Transactions** nécessitent plusieurs signatures pour autoriser une transaction.
- Les transactions sont composées de **inputs** (source des fonds), **outputs** (destination), **fees** (payées aux mineurs) et de **scripts** (règles de transaction).

### Lightning Network

Vise à améliorer la scalabilité de Bitcoin en permettant plusieurs transactions au sein d'un canal, en ne diffusant à la blockchain que l'état final.

## Bitcoin Privacy Concerns

Les attaques sur la vie privée, telles que **Common Input Ownership** et **UTXO Change Address Detection**, exploitent les schémas de transaction. Des stratégies comme **Mixers** et **CoinJoin** améliorent l'anonymat en masquant les liens de transaction entre utilisateurs.

## Acquiring Bitcoins Anonymously

Les méthodes incluent les échanges en espèces, le minage et l'utilisation de mixers. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguise les CoinJoins en transactions ordinaires pour une confidentialité accrue.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Dans le monde de Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles des attaquants peuvent compromettre la vie privée de Bitcoin.

## **Common Input Ownership Assumption**

Il est généralement rare que des inputs provenant de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité que cela implique. Ainsi, **deux adresses input dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **UTXO Change Address Detection**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste va vers une nouvelle adresse de change. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Example

Pour atténuer cela, des services de mixage ou l'utilisation de plusieurs adresses peuvent aider à masquer la propriété.

## **Social Networks & Forums Exposure**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, ce qui rend **facile de relier l'adresse à son propriétaire**.

## **Transaction Graph Analysis**

Les transactions peuvent être visualisées sous forme de graphes, révélant des connexions potentielles entre utilisateurs en fonction du flux de fonds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Cette heuristique est basée sur l'analyse de transactions avec plusieurs inputs et outputs pour deviner quel output est le change renvoyé à l'expéditeur.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si ajouter plus d'inputs rend la sortie de change plus grande que n'importe quel input unique, cela peut confondre l'heuristic.

## **Forced Address Reuse**

Les attaquants peuvent envoyer de petites sommes à des addresses déjà utilisées, en espérant que le destinataire les combine avec d'autres inputs dans de futures transactions, reliant ainsi les addresses entre elles.

### Correct Wallet Behavior

Les wallets devraient éviter d'utiliser des coins reçus sur des addresses vides déjà utilisées afin d'empêcher ce leak de confidentialité.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Les transactions sans change sont probablement entre deux addresses appartenant au même user.
- **Round Numbers:** Un montant rond dans une transaction suggère qu'il s'agit d'un paiement, la sortie non ronde étant probablement le change.
- **Wallet Fingerprinting:** Différents wallets ont des patterns uniques de création de transactions, permettant aux analystes d'identifier le software utilisé et potentiellement l'address de change.
- **Amount & Timing Correlations:** Divulguer les heures ou les montants des transactions peut rendre les transactions traçables.

## **Traffic Analysis**

En surveillant le traffic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocks à des IP addresses, compromettant la confidentialité des users. C'est particulièrement vrai si une entité opère de nombreux nœuds Bitcoin, ce qui améliore sa capacité à surveiller les transactions.

## More

Pour une liste complète des attaques et défenses de confidentialité, visitez [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquérir des bitcoin via du cash.
- **Cash Alternatives**: Acheter des gift cards et les échanger en ligne contre des bitcoin.
- **Mining**: La méthode la plus privée pour gagner des bitcoins est le mining, surtout lorsqu'il est effectué seul, car les mining pools peuvent connaître l'IP address du miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Théoriquement, voler des bitcoin pourrait être une autre méthode pour les obtenir anonymement, bien que ce soit illégal et non recommandé.

## Mixing Services

En utilisant un mixing service, un user peut **envoyer des bitcoins** et recevoir **d'autres bitcoins en retour**, ce qui rend difficile le tracing du propriétaire original. Cependant, cela exige de faire confiance au service pour qu'il ne conserve pas de logs et qu'il renvoie réellement les bitcoins. Parmi les options de mixing alternatives figurent les casinos Bitcoin.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents users en une seule, compliquant le processus pour quiconque essaie de faire correspondre inputs et outputs. Malgré son efficacité, les transactions avec des tailles d'input et d'output uniques peuvent toujours potentiellement être tracées.

Des transactions d'exemple ayant pu utiliser CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant de miners.

## PayJoin

Variante de CoinJoin, **PayJoin** (ou P2EP) déguise la transaction entre deux parties (par exemple, un client et un merchant) comme une transaction normale, sans les outputs égaux distinctifs caractéristiques de CoinJoin. Cela le rend extrêmement difficile à détecter et pourrait invalider l'heuristic d'ownership commun des inputs utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Des transactions comme celles ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions bitcoin standard.

**L’utilisation de PayJoin pourrait perturber de manière significative les méthodes de surveillance traditionnelles**, ce qui en fait une évolution prometteuse dans la quête de confidentialité transactionnelle.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Pour maintenir la confidentialité et la sécurité, synchroniser les wallets avec la blockchain est crucial. Deux méthodes se distinguent :

- **Full node** : En téléchargeant l’intégralité de la blockchain, un full node garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, ce qui rend impossible pour des adversaires d’identifier quelles transactions ou adresses intéressent l’utilisateur.
- **Client-side block filtering** : Cette méthode consiste à créer des filtres pour chaque bloc de la blockchain, permettant aux wallets d’identifier les transactions pertinentes sans exposer d’intérêts spécifiques aux observateurs du réseau. Les wallets légers téléchargent ces filtres, ne récupérant les blocs complets que lorsqu’une correspondance avec les adresses de l’utilisateur est trouvée.

## **Utilizing Tor for Anonymity**

Étant donné que Bitcoin fonctionne sur un réseau peer-to-peer, l’utilisation de Tor est recommandée pour masquer votre adresse IP, renforçant la confidentialité lors des interactions avec le réseau.

## **Preventing Address Reuse**

Pour protéger la confidentialité, il est essentiel d’utiliser une nouvelle adresse pour chaque transaction. La réutilisation des adresses peut compromettre la confidentialité en reliant les transactions à la même entité. Les wallets modernes découragent la réutilisation des adresses par leur conception.

## **Strategies for Transaction Privacy**

- **Multiple transactions** : Fractionner un paiement en plusieurs transactions peut masquer le montant de la transaction, contrecarrant les attaques sur la confidentialité.
- **Change avoidance** : Opter pour des transactions qui ne nécessitent pas de sorties de change améliore la confidentialité en perturbant les méthodes de détection du change.
- **Multiple change outputs** : Si éviter le change n’est pas faisable, générer plusieurs sorties de change peut tout de même améliorer la confidentialité.

# **Monero: A Beacon of Anonymity**

Monero répond au besoin d’anonymat absolu dans les transactions numériques, en fixant un niveau élevé de confidentialité.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas mesure l’effort de calcul nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2,310,000 gwei (ou 0.00231 ETH) implique un gas limit et une base fee, avec un tip pour inciter les miners. Les utilisateurs peuvent définir un max fee pour s’assurer de ne pas trop payer, l’excédent étant remboursé.

## **Executing Transactions**

Les transactions dans Ethereum impliquent un sender et un recipient, qui peuvent être des adresses d’utilisateur ou de smart contract. Elles nécessitent des frais et doivent être minées. Les informations essentielles d’une transaction incluent le recipient, la signature du sender, la valeur, des données optionnelles, le gas limit et les frais. Notamment, l’adresse du sender est déduite de la signature, ce qui élimine le besoin de l’inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour toute personne souhaitant utiliser les cryptocurrencies tout en privilégiant la confidentialité et la sécurité.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Lorsqu’un prover utilise une **zkVM** ou un circuit de preuve spécifique à une application pour attester une revendication, le vérificateur apprend seulement que le **programme guest a été exécuté tel qu’écrit**. Si le guest contient une **unsafe deserialization**, un **undefined behavior** ou des **missing semantic constraints**, un prover malveillant peut générer une preuve qui se vérifie alors que les **métriques publiques ou l’invariant revendiqué sont faux**.

### Unsafe deserialization inside proof guests

- Traitez les octets privés du witness/circuit comme des **untrusted attacker input** même s’ils sont cachés par la preuve.
- Évitez de les désérialiser avec des helpers non vérifiés tels que `rkyv::access_unchecked` sauf si les octets ont déjà été validés hors bande.
- Les discriminants d’enum, les pointeurs relatifs, les longueurs et les index chargés depuis des données sérialisées non fiables doivent être validés avant d’influencer le contrôle du flux ou l’accès mémoire.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Si un champ tel que `op.kind` est un enum et qu’un attaquant peut injecter un **discriminant hors plage**, chaque `match` en aval sur cette valeur devient suspect.

### Contournement par jump-table / UB

Si Rust abaisse un grand `match` en **jump table**, un discriminant d’enum invalide peut produire un **flux de contrôle indéfini**. Un schéma dangereux est le suivant :

1. Un premier `match` met à jour des **compteurs/contraintes critiques pour la sécurité**.
2. Un second `match` exécute la **vraie sémantique de l’instruction**.
3. Un discriminant hors plage indexe au-delà de la première jump table et arrive dans du code associé à la seconde.

Résultat : l’opération s’exécute quand même, mais le chemin de comptabilisation est ignoré. Dans un zkVM, cela peut forger des preuves qui rapportent des métriques impossibles, comme moins de gates, moins d’opérations coûteuses, ou d’autres ressources bornées falsifiées.

Checklist de revue :

- Chercher des enums contrôlés par l’attaquant et désérialisés depuis witness/private input.
- Inspecter les `match` répétés sur le même opcode/kind field.
- Considérer `unsafe` + désérialisation non vérifiée + grand dispatch d’opcodes comme une combinaison à haut risque.
- Faire de la rétro-ingénierie du binaire généré si nécessaire ; la disposition de la jump-table peut compter plus que le source.

### Contraintes sémantiques manquantes dans les interpreters réversibles/spécialisés

Ne validez pas seulement la sécurité mémoire ; validez aussi les **règles sémantiques** que la preuve est censée imposer.

Pour les instruction sets réversibles/de type quantique, assurez-vous que les opérandes qui doivent être distincts sont bien contraints à l’être. Une opération de type Toffoli/CCX implémentée comme :
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
devient dangereuse si l'invité ne refuse pas :
```text
op.q_control1 == op.q_control2 == op.q_target
```
Dans ce cas, la transition se réduit à :
```text
q = q ^ (q & q) = 0
```
This crée un **primitif de reset déterministe**, casse les hypothèses de réversibilité et permet des calculs non intentionnels moins coûteux. Dans les proof systems qui attestent l’utilisation des ressources, cela peut permettre à des attaquants de satisfaire les vérifications fonctionnelles tout en contournant le modèle de coût que le verifier pense appliquer.

### What to test in ZK systems

- Fuzzer tous les parsers du guest avec des encodages de witness/private-input malformés.
- Assert la validation de l’intervalle des enums avant le dispatch des opcodes.
- Ajouter des vérifications sémantiques pour l’aliasing des opérandes et d’autres formes d’instructions invalides.
- Comparer les compteurs reported/public avec une implémentation de référence indépendante.
- Rappelle-toi qu’une proof valide peut quand même prouver la **mauvaise assertion** si le programme guest est buggy.

## DeFi/AMM Exploitation

Si vous recherchez l’exploitation pratique de DEXes et AMMs (Uniswap v4 hooks, abus de rounding/precision, flash-loan amplified threshold-crossing swaps), consultez :

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Pour les pools pondérés multi-assets qui mettent en cache des soldes virtuels et peuvent être empoisonnés quand `supply == 0`, étudiez :

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
