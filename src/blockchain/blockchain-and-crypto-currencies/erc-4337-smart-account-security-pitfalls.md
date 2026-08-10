# ERC-4337 Smart Account Security Pitfalls

L’account abstraction ERC-4337 transforme les wallets en systèmes programmables. Le flux principal est **validate-then-execute** sur l’ensemble d’un bundle : l’`EntryPoint` valide chaque `UserOperation` avant d’en exécuter une seule.<sup>[[5]](#references)</sup> Cet ordre crée une attack surface non évidente lorsque la validation est permissive, stateful ou incohérente avec les règles de simulation du bundler.

## 1) Direct-call bypass of privileged functions
Toute fonction `execute` (ou fonction déplaçant des fonds) appelable depuis l’extérieur qui n’est pas limitée à l’`EntryPoint` (ou à un module d’exécution vérifié) peut être appelée directement pour vider le compte.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sûr : restreindre à `EntryPoint` et utiliser `msg.sender == address(this)` pour les flux d’administration et de gestion interne (installation de modules, modifications des validateurs, mises à niveau).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Champs de gas non signés ou non vérifiés -> épuisement des frais
Si la validation de la signature ne couvre que l'intention (`callData`), mais pas les champs liés au gas, un bundler ou un frontrunner peut gonfler les frais et vider les ETH. Le payload signé doit au minimum lier&nbsp;:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern défensif&nbsp;: utiliser le `userOpHash` fourni par l'`EntryPoint` (qui inclut les champs de gas) et/ou plafonner strictement chaque champ.<sup>[[2]](#references)[[5]](#references)</sup>
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
Comme toutes les validations s’exécutent avant toute exécution, stocker les résultats de validation dans l’état du contrat est dangereux. Une autre op dans le même bundle peut les écraser, ce qui fait que votre exécution utilise un état contrôlé par l’attaquant.<sup>[[2]](#references)</sup>

Évitez d’écrire dans le storage depuis `validateUserOp`. Si cela est inévitable, indexez les données temporaires par `userOpHash` et supprimez-les de manière déterministe après utilisation (préférez une validation stateless).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 entre comptes et chains (absence de domain separation)
`isValidSignature(bytes32 hash, bytes sig)` doit lier les signatures à **ce contrat** et à **cette chain**. Effectuer une récupération sur un hash brut permet de rejouer les signatures entre différents comptes ou chains.<sup>[[1]](#references)[[4]](#references)</sup>

Utilisez des données typées EIP-712 (le domain inclut `verifyingContract` et `chainId`) et retournez la valeur magic ERC-1271 exacte `0x1626ba7e` en cas de succès.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Les reverts ne remboursent pas après la validation
Une fois que `validateUserOp` a réussi, les fees sont engagées même si l’exécution revert ensuite. Les attaquants peuvent soumettre à plusieurs reprises des ops vouées à échouer tout en prélevant des fees sur le compte.<sup>[[2]](#references)</sup>

Pour les paymasters, payer depuis un pool partagé dans `validateUserOp` et facturer les utilisateurs dans `postOp` est fragile, car `postOp` peut revert sans annuler le paiement. Sécurisez les fonds pendant la validation (escrow/deposit par utilisateur), gardez `postOp` minimal et non-reverting, et prévoyez un `paymasterPostOpGasLimit` suffisant pour le chemin de remboursement dans le pire des cas.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Déploiement contrefactuel / hypothèses concernant la factory
La première `UserOperation` contient souvent `initCode`, ce qui entraîne le déploiement du compte par l’intermédiaire d’une **factory** pendant la validation. Ce chemin est facile à sous-auditer, car il ne s’exécute que lors de la première utilisation.<sup>[[5]](#references)</sup>

Les erreurs courantes incluent :<sup>[[5]](#references)</sup>

- La factory/initializer fait confiance à `msg.sender == entryPoint`, mais le chemin de déploiement ERC-4337 n’appelle **pas** `initCode` directement depuis `EntryPoint`.
- Le salt, l’owner, le validator ou la configuration des modules ne sont pas entièrement liés à l’intention signée ; un frontrunner peut donc s’emparer du déploiement initial et griller l’adresse contrefactuelle avec des paramètres contrôlés par l’attaquant.
- La factory n’est pas idempotente ; un flux répété lors de la première utilisation bloque le wallet au lieu de retourner l’adresse déjà créée.

Pattern sûr : recalculez le sender attendu à partir des paramètres de déploiement signés, rendez le déploiement déterministe (généralement avec `CREATE2`) et faites en sorte que l’initialisation ne puisse être effectuée qu’une seule fois.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logique de validation que les bundlers rejettent
Le code de validation peut être correct dans les tests locaux tout en étant inutilisable dans de vrais bundlers. Les bundlers exécutent la validation plusieurs fois et devraient effectuer une validation complète du bundle avec traçage avant la soumission.<sup>[[6]](#references)</sup>

Selon ces règles de portée de validation, les modèles suivants sont dangereux :<sup>[[6]](#references)</sup>

- Opcodes dépendant du bloc, tels que `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
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
Traitez la validation comme une fonction de preflight déterministe et bornée. Si un état partagé ou des recherches externes sont nécessaires, suivez les règles applicables aux entités stakées et testez le même chemin de simulation multi-pass du bundler, et pas uniquement les tests unitaires.<sup>[[6]](#references)</sup>

## 8) Frontrun de l'initialisation ERC-7702
ERC-7702 attribue à une EOA une délégation persistante vers du code de smart account ; la délégation n'exécute pas l'initialisation de manière atomique. Si l'initialisation peut être appelée de manière externe, un observateur peut la frontrun et se définir comme propriétaire.<sup>[[7]](#references)</sup>

Mitigation : exigez que le calldata d'initialisation soit autorisé par l'EOA et n'autorisez l'initialisation qu'une seule fois. Dans un flux ERC-4337 EIP-7702, limitez également l'appelant à `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Vérifications rapides avant le merge
- Valider les signatures à l’aide de `EntryPoint`'s `userOpHash` (lie les champs de gas).
- Restreindre les fonctions privilégiées à `EntryPoint` et/ou à `address(this)` selon le cas.
- Garder `validateUserOp` stateless, déterministe et compatible avec les règles de simulation du bundler.
- Appliquer la séparation de domaine EIP-712 pour ERC-1271 et retourner `0x1626ba7e` en cas de succès.
- Garder `postOp` minimal, limité et sans revert ; sécuriser les fees pendant la validation.
- Tester séparément le premier chemin `initCode` : déploiement déterministe, comportement idempotent de la factory et initialisation à usage unique.
- Exécuter la validation multi-pass du bundler et une vérification tracée du bundle complet avant la mise en production.
- Pour ERC-7702, lier l'init à l'autorisation de l'EOA et ne l'autoriser qu'une seule fois ; dans les flows ERC-4337, restreindre l'appelant à `EntryPoint.senderCreator()`.

## References

- [1] [Replay d'ERC1271 - Plus de 15 équipes affectées (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Six erreurs dans les smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271 : méthode standard de validation des signatures pour les contrats](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712 : hachage et signature de données structurées typées](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337 : abstraction de compte utilisant l'Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562 : règles de portée de validation de l'abstraction de compte](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702 : définir le code des EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
