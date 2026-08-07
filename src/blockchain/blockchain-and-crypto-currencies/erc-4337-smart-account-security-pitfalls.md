# Pièges de sécurité des Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

L'account abstraction d'ERC-4337 transforme les wallets en systèmes programmables. Le flux central est **validate-then-execute** sur l'ensemble d'un bundle : l'`EntryPoint` valide chaque `UserOperation` avant d'en exécuter une seule. Cet ordre crée une surface d'attaque non évidente lorsque la validation est permissive, stateful ou incohérente avec les règles de simulation du bundler.

## 1) Contournement des fonctions privilégiées par appel direct
Toute fonction `execute` (ou fonction de transfert de fonds) appelable de manière externe qui n'est pas limitée à l'`EntryPoint` (ou à un module d'exécution approuvé) peut être appelée directement pour vider le compte.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sûr : restreindre à `EntryPoint`, et utiliser `msg.sender == address(this)` pour les flux d’administration et d’auto-gestion (installation de modules, modifications de validators, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Champs de gas non signés ou non vérifiés -> drain de fees
Si la validation de la signature ne couvre que l'intention (`callData`), mais pas les champs liés au gas, un bundler ou un frontrunner peut gonfler les fees et drainer l'ETH. Le payload signé doit au minimum inclure :<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern défensif : utiliser le `userOpHash` fourni par l'`EntryPoint` (qui inclut les champs de gas) et/ou plafonner strictement chaque champ.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Écrasement de la validation avec état (sémantique du bundle)
Comme toutes les validations s’exécutent avant toute exécution, stocker les résultats de validation dans l’état du contrat est dangereux. Une autre op dans le même bundle peut les écraser et amener votre exécution à utiliser un état contrôlé par l’attaquant.<sup>[[1]](#references)</sup>

Évitez d’écrire dans le storage dans `validateUserOp`. Si cela est inévitable, indexez les données temporaires par `userOpHash` et supprimez-les de manière déterministe après leur utilisation (préférez une validation stateless).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 entre comptes et chaînes (absence de séparation de domaine)
`isValidSignature(bytes32 hash, bytes sig)` doit lier les signatures à **ce contrat** et à **cette chaîne**. Effectuer une récupération sur un hash brut permet de rejouer les signatures entre plusieurs comptes ou chaînes.<sup>[[1]](#references)</sup>

Utilisez des données typées EIP-712 (le domaine inclut `verifyingContract` et `chainId`) et retournez la valeur magic ERC-1271 exacte `0x1626ba7e` en cas de succès.<sup>[[1]](#references)</sup>

## 5) Les reverts ne remboursent pas après la validation
Une fois que `validateUserOp` a réussi, les frais sont engagés même si l’exécution échoue ensuite avec un revert. Les attaquants peuvent soumettre de manière répétée des ops vouées à l’échec tout en prélevant des frais sur le compte.<sup>[[1]](#references)</sup>

Pour les paymasters, payer depuis un pool partagé dans `validateUserOp` et facturer les utilisateurs dans `postOp` est fragile, car `postOp` peut revert sans annuler le paiement. Sécurisez les fonds pendant la validation (escrow/deposit par utilisateur), gardez `postOp` minimal et sans revert, et prévoyez un `paymasterPostOpGasLimit` suffisant pour le chemin de remboursement dans le pire des cas.<sup>[[1]](#references)</sup>

## 6) Déploiement contrefactuel / hypothèses concernant la factory
La première `UserOperation` contient souvent `initCode`, ce qui entraîne le déploiement du compte via une **factory** pendant la validation. Ce chemin est facile à sous-auditer, car il n’est exécuté qu’à la première utilisation.<sup>[[2]](#references)</sup>

Échecs courants :

- La factory/l’initializer fait confiance à `msg.sender == entryPoint`, mais le chemin de déploiement ERC-4337 n’appelle **pas** `initCode` directement depuis `EntryPoint`.
- Le salt, l’owner, le validator ou la configuration du module ne sont pas entièrement liés à l’intention signée ; un frontrunner peut donc devancer le premier déploiement et réserver l’adresse contrefactuelle avec des paramètres contrôlés par l’attaquant.
- La factory n’est pas idempotente : un flux répété lors de la première utilisation bloque le wallet au lieu de retourner l’adresse déjà créée.

Pattern sûr : recalculez le sender attendu à partir des paramètres de déploiement signés, rendez le déploiement déterministe (généralement avec `CREATE2`) et rendez l’initialisation à usage unique.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logique de validation que les bundlers rejettent
Le code de validation peut être correct dans les tests locaux tout en étant inutilisable avec de vrais bundlers. Les bundlers publics simulent `validateUserOp()` / `validatePaymasterUserOp()` off-chain et exécutent généralement un `debug_traceCall(handleOps)` complet avant l'inclusion.<sup>[[3]](#references)</sup>

Ces patterns sont donc dangereux dans la validation :

- Opcodes dépendant du block, tels que `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
- Écritures d'état telles que `SSTORE`
- Itération non bornée sur le storage
- Appels externes arbitraires ou lectures d'oracle pouvant changer entre la simulation et l'inclusion

Mauvais exemple :
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Traitez la validation comme une fonction de preflight déterministe et bornée. Si vous avez réellement besoin d’un état partagé ou de recherches externes, déplacez cette complexité dans des entités staked/reputation-tracked et testez le chemin exact de simulation du bundler, et pas uniquement les tests unitaires.

## 8) ERC-7702 initialization frontrun
ERC-7702 permet à un EOA d’exécuter du code de smart account pendant une seule tx. Si l’initialization est callable depuis l’extérieur, un frontrunner peut se définir comme owner.<sup>[[1]](#references)</sup>

Mitigation : autoriser l’initialization uniquement via un **self-call** et une seule fois.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vérifications rapides avant la fusion
- Valider les signatures à l’aide de `userOpHash` d’`EntryPoint` (lie les champs de gas).
- Restreindre les fonctions privilégiées à `EntryPoint` et/ou à `address(this)` selon le cas.
- Garder `validateUserOp` sans état, déterministe et compatible avec les règles de simulation des bundlers.
- Appliquer la séparation de domaine EIP-712 pour ERC-1271 et retourner `0x1626ba7e` en cas de succès.
- Garder `postOp` minimal, limité et sans revert ; sécuriser les frais pendant la validation.
- Tester séparément le premier chemin `initCode` : déploiement déterministe, comportement idempotent de la factory et initialisation unique.
- Exécuter une simulation complète du bundler (`simulateValidation` ainsi qu’un `handleOps` tracé) avant le déploiement.
- Pour ERC-7702, n’autoriser l’initialisation que lors d’un self-call et une seule fois.

## Références

- [1] [Six erreurs dans les smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337 : abstraction des comptes utilisant une Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562 : règles de portée de validation pour l’abstraction des comptes](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
