# Pièges de sécurité des Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

L’account abstraction d’ERC-4337 transforme les wallets en systèmes programmables. Le flux central est **validate-then-execute** pour l’ensemble d’un bundle : l’`EntryPoint` valide chaque `UserOperation` avant d’en exécuter une seule.<sup>[[5]](#references)</sup> Cet ordre crée une attack surface non évidente lorsque la validation est permissive, stateful ou incohérente avec les règles de simulation des bundlers.

## 1) Contournement des fonctions privilégiées par appel direct
Toute fonction `execute` (ou fonction déplaçant des fonds) accessible de manière externe et qui n’est pas limitée à l’`EntryPoint` (ou à un module d’exécution vérifié) peut être appelée directement pour drainer le compte.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sûr : restreindre à `EntryPoint` et utiliser `msg.sender == address(this)` pour les flux d’administration et d’auto-gestion (installation de modules, modifications des validateurs, mises à niveau).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Champs de gas non signés ou non vérifiés -> drain de frais
Si la validation de la signature ne couvre que l’intention (`callData`), mais pas les champs liés au gas, un bundler ou un frontrunner peut gonfler les frais et drainer l’ETH. Le payload signé doit au minimum lier les éléments suivants :<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern défensif : utiliser le `userOpHash` fourni par l’`EntryPoint` (qui inclut les champs de gas) et/ou plafonner strictement chaque champ.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Écrasement de la validation stateful (sémantique du bundle)
Comme toutes les validations s’exécutent avant toute exécution, stocker les résultats de validation dans l’état du contrat est dangereux. Une autre op dans le même bundle peut les écraser, ce qui peut faire utiliser à votre exécution un état contrôlé par l’attaquant.<sup>[[2]](#references)</sup>

Évitez d’écrire dans le storage dans `validateUserOp`. Si cela est inévitable, indexez les données temporaires par `userOpHash` et supprimez-les de manière déterministe après utilisation (préférez une validation stateless).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 entre comptes et chains (absence de séparation de domaine)
`isValidSignature(bytes32 hash, bytes sig)` doit lier les signatures à **ce contrat** et à **cette chain**. Effectuer la récupération sur un hash brut permet de rejouer les signatures entre différents comptes ou chains.<sup>[[1]](#references)[[4]](#references)</sup>

Utilisez des données typées EIP-712 (le domaine inclut `verifyingContract` et `chainId`) et retournez la valeur magique ERC-1271 exacte `0x1626ba7e` en cas de succès.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Les reverts ne remboursent pas après la validation
Une fois que `validateUserOp` a réussi, les frais sont engagés même si l’exécution échoue ensuite avec un revert. Les attaquants peuvent soumettre de manière répétée des ops qui échoueront et percevoir malgré tout des frais sur le compte.<sup>[[2]](#references)</sup>

Pour les paymasters, payer depuis un pool partagé dans `validateUserOp` et facturer les utilisateurs dans `postOp` est fragile, car `postOp` peut revert sans annuler le paiement. Sécurisez les fonds pendant la validation (escrow/dépôt par utilisateur), gardez `postOp` minimal et sans revert, et prévoyez un `paymasterPostOpGasLimit` suffisant pour le chemin de remboursement dans le pire des cas.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Déploiement contrefactuel / hypothèses sur la factory
La première `UserOperation` contient souvent un `initCode`, ce qui entraîne le déploiement du compte par une **factory** pendant la validation. Ce chemin est facile à sous-auditer, car il ne s’exécute que lors de la première utilisation.<sup>[[5]](#references)</sup>

Les échecs courants incluent :<sup>[[5]](#references)</sup>

- La factory/l’initializer fait confiance à `msg.sender == entryPoint`, mais le chemin de déploiement ERC-4337 n’appelle **pas** `initCode` directement depuis `EntryPoint`.
- Le salt, l’owner, le validator ou la configuration des modules ne sont pas entièrement liés à l’intention signée ; un frontrunner peut donc devancer le premier déploiement et utiliser l’adresse contrefactuelle avec des paramètres contrôlés par l’attaquant.
- La factory n’est pas idempotente ; une répétition du flux de première utilisation bloque le wallet au lieu de retourner l’adresse déjà créée.

Pattern sûr : recalculez le sender attendu à partir des paramètres de déploiement signés, rendez le déploiement déterministe (généralement avec `CREATE2`) et rendez l’initialisation exécutable une seule fois.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logique de validation rejetée par les bundlers
Le code de validation peut être correct dans les tests locaux tout en étant inutilisable dans les bundlers réels. Les bundlers exécutent la validation plusieurs fois et doivent effectuer une validation complète du bundle avec traçage avant la soumission.<sup>[[6]](#references)</sup>

Selon ces règles de portée de validation, les patterns suivants sont dangereux :<sup>[[6]](#references)</sup>

- Opcodes dépendants du bloc tels que `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
- Accès au stockage en dehors de la portée autorisée du compte/de l'entité, ou itération non bornée sur le stockage
- Appels externes ou lectures d'oracle qui dépendent d'un état mutable en dehors de la portée de validation autorisée

Mauvais exemple :
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Traitez la validation comme une fonction de preflight déterministe et limitée. Si un état partagé ou des recherches externes sont nécessaires, suivez les règles relatives aux entités stakées et testez le même chemin de simulation multi-passes du bundler, et pas uniquement les tests unitaires.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 attribue à un EOA une délégation persistante vers du code de smart-account ; la délégation n’exécute pas l’initialisation de manière atomique. Si l’initialisation est appelable de l’extérieur, un observateur peut la front-run et se définir comme propriétaire.<sup>[[7]](#references)</sup>

Mitigation : exigez que les calldata d’initialisation soient autorisées par l’EOA et n’autorisez l’initialisation qu’une seule fois. Dans un flux ERC-4337 EIP-7702, limitez également l’appelant à `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Vérifications rapides avant la fusion
- Valider les signatures à l'aide du `userOpHash` de `EntryPoint` (qui lie les champs de gas).
- Restreindre les fonctions privilégiées à `EntryPoint` et/ou à `address(this)`, selon le cas.
- Garder `validateUserOp` stateless, déterministe et compatible avec les règles de simulation du bundler.
- Appliquer la séparation de domaine EIP-712 pour ERC-1271 et retourner `0x1626ba7e` en cas de succès.
- Garder `postOp` minimal, limité et sans revert ; sécuriser les fees pendant la validation.
- Tester séparément le premier chemin `initCode` : déploiement déterministe, comportement idempotent de la factory et initialisation à usage unique.
- Exécuter la validation multi-pass du bundler ainsi qu'une vérification tracée du bundle complet avant la mise en production.
- Pour ERC-7702, lier l'initialisation à l'autorisation de l'EOA et ne l'autoriser qu'une seule fois ; dans les flows ERC-4337, restreindre l'appelant à `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - Plus de 15 équipes affectées (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Six erreurs dans les smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271 : méthode standard de validation des signatures pour les contrats](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712 : hachage et signature de données structurées typées](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337 : Account Abstraction utilisant l'Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562 : règles de portée de validation de l'Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702 : définir le code des EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
