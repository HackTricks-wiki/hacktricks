# Pièges de sécurité des Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

L’abstraction de compte ERC-4337 transforme les wallets en systèmes programmables. Le flux central est **valider-puis-exécuter** sur l’ensemble d’un bundle : le `EntryPoint` valide chaque `UserOperation` avant d’en exécuter une seule. Cet ordre crée une surface d’attaque non évidente lorsque la validation est permissive, stateful, ou incohérente avec les règles de simulation du bundler.

## 1) Contournement par appel direct des fonctions privilégiées
Toute fonction `execute` (ou de transfert de fonds) appelable depuis l’extérieur et qui n’est pas restreinte à `EntryPoint` (ou à un module d’exécution vérifié) peut être appelée directement pour vider le compte.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Motif sûr : limiter à `EntryPoint` et utiliser `msg.sender == address(this)` pour les flux d'administration / d'auto-gestion (installation de module, changements de validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Champs de gas non signés ou non vérifiés -> drain de frais
Si la validation de signature ne couvre que l’intention (`callData`) mais pas les champs liés au gas, un bundler ou un frontrunner peut gonfler les frais et drainer de l’ETH. Le payload signé doit lier au minimum :

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern défensif : utiliser le `userOpHash` fourni par `EntryPoint` (qui inclut les champs de gas) et/ou plafonner strictement chaque champ.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Écrasement de la validation stateful (bundle semantics)
Comme toutes les validations s’exécutent avant toute exécution, stocker les résultats de validation dans l’état du contract est unsafe. Une autre op dans le même bundle peut les écraser, ce qui amène votre exécution à utiliser un état influencé par l’attaquant.

Évitez d’écrire dans le storage dans `validateUserOp`. Si c’est unavoidable, indexez les données temporaires par `userOpHash` et supprimez-les de façon déterministe après usage (préférez une validation stateless).

## 4) Rejeu ERC-1271 entre accounts/chains (absence de domain separation)
`isValidSignature(bytes32 hash, bytes sig)` doit lier les signatures à **ce contract** et à **cette chain**. Faire un recover sur un hash brut permet de rejouer les signatures entre accounts ou chains.

Utilisez des typed data EIP-712 (le domain inclut `verifyingContract` et `chainId`) et renvoyez la valeur magique ERC-1271 exacte `0x1626ba7e` en cas de succès.

## 5) Les reverts ne remboursent pas après validation
Une fois que `validateUserOp` réussit, les fees sont engagés même si l’exécution revert plus tard. Les attaquants peuvent soumettre à répétition des ops qui vont échouer et quand même faire payer des fees à partir du account.

Pour les paymasters, payer depuis un pool partagé dans `validateUserOp` et facturer les users dans `postOp` est fragile parce que `postOp` peut revert sans annuler le paiement. Sécurisez les fonds pendant la validation (escrow/deposit par user), gardez `postOp` minimal et non-reverting, et budgétez `paymasterPostOpGasLimit` pour le pire chemin de remboursement.

## 6) Déploiement contre-factuel / hypothèses de factory
La première `UserOperation` transporte souvent `initCode`, ce qui provoque le déploiement du account via une **factory** pendant la validation. Ce chemin est facile à sous-auditer parce qu’il ne s’exécute qu’au premier usage.

Échecs courants :

- La factory/l’initializer fait confiance à `msg.sender == entryPoint`, mais le chemin de déploiement ERC-4337 n’appelle pas `initCode` directement depuis `EntryPoint`.
- Le salt, owner, validator, ou la configuration du module ne sont pas entièrement liés à l’intention signée, donc un frontrunner peut gagner la course du premier déploiement et brûler l’adresse contre-factuelle avec des settings contrôlés par l’attaquant.
- La factory n’est pas idempotent, donc un flux de first-use répété brick le wallet au lieu de renvoyer l’adresse déjà créée.

Safe pattern: recalculez le sender attendu à partir des paramètres de déploiement signés, rendez le déploiement déterministe (généralement `CREATE2`), et rendez l’initialisation one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic that bundlers reject
Le code de validation peut être correct dans des tests locaux et rester pourtant inutilisable dans de vrais bundlers. Les bundlers publics simulent `validateUserOp()` / `validatePaymasterUserOp()` hors chaîne et exécutent souvent un `debug_traceCall(handleOps)` complet avant inclusion.

Cela rend ces patterns dangereux dans la validation :

- Des opcodes dépendants du bloc tels que `TIMESTAMP`, `NUMBER`, ou `BLOCKHASH`
- Des écritures d’état telles que `SSTORE`
- Une itération non bornée sur le storage
- Des appels externes arbitraires ou des lectures d’oracle qui peuvent changer entre la simulation et l’inclusion

Bad example:
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
Traitez la validation comme une fonction de prévol déterministe et bornée. Si vous avez vraiment besoin d’un état partagé ou de recherches externes, poussez cette complexité vers des entités avec stake/suivi de réputation et testez le chemin exact de simulation du bundler, pas seulement les unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 permet à un EOA d’exécuter du code smart-account pour une seule tx. Si l’initialization est appelable de l’extérieur, un frontrunner peut se définir comme owner.

Mitigation: autorisez l’initialization uniquement sur **self-call** et une seule fois.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vérifications rapides avant la fusion
- Valider les signatures en utilisant le `userOpHash` d'`EntryPoint` (lie les champs de gas).
- Restreindre les fonctions privilégiées à `EntryPoint` et/ou `address(this)` selon le cas.
- Garder `validateUserOp` stateless, deterministic, et compatible avec les règles de simulation du bundler.
- Imposer la séparation de domaine EIP-712 pour ERC-1271 et renvoyer `0x1626ba7e` en cas de succès.
- Garder `postOp` minimal, borné, et non-reverting ; sécuriser les frais pendant la validation.
- Tester séparément le premier chemin `initCode` : déploiement deterministic, comportement idempotent de la factory, et initialisation one-shot.
- Exécuter la simulation complète du bundler (`simulateValidation` plus un `handleOps` tracé) avant le déploiement.
- Pour ERC-7702, autoriser init seulement sur self-call et seulement une fois.



## Références

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
