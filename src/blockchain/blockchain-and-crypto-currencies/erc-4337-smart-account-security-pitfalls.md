# ERC-4337 Pièges de sécurité des comptes intelligents

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction turns wallets into programmable systems. The core flow is **validate-then-execute** across a whole bundle: the `EntryPoint` validates every `UserOperation` before executing any of them. This ordering creates non-obvious attack surface when validation is permissive or stateful.

## 1) Contournement par appel direct des fonctions privilégiées
Toute fonction `execute` (ou de déplacement de fonds) appelable depuis l'extérieur qui n'est pas restreinte à `EntryPoint` (ou à un module exécuteur approuvé) peut être appelée directement pour vider le compte.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Modèle sûr : restreindre à `EntryPoint` et utiliser `msg.sender == address(this)` pour les flux d'admin/self-management (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Champs gas non signés ou non vérifiés -> vidage d'ETH via frais
Si la validation de la signature ne couvre que l'intention (`callData`) mais pas les champs liés au gas, un bundler ou frontrunner peut gonfler les frais et vider l'ETH. Le payload signé doit au minimum lier :

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern défensif : utiliser le `userOpHash` fourni par `EntryPoint` (qui inclut les champs gas) et/ou imposer un plafond strict à chaque champ.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
Parce que toutes les validations s'exécutent avant toute exécution, stocker les résultats de validation dans l'état du contrat est dangereux. Une autre op dans le même bundle peut l'écraser, faisant que votre exécution utilise un état influencé par un attaquant.

Évitez d'écrire dans le storage depuis `validateUserOp`. Si impossible, indexez les données temporaires par `userOpHash` et supprimez-les de manière déterministe après utilisation (préférez la validation sans état).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` doit lier les signatures à **ce contrat** et à **cette chaîne**. Faire le recovery sur un hash brut permet aux signatures d'être rejouées entre comptes ou chaînes.

Utilisez EIP-712 typed data (le domaine inclut `verifyingContract` et `chainId`) et renvoyez la valeur magique ERC-1271 exacte `0x1626ba7e` en cas de succès.

## 5) Reverts do not refund after validation
Une fois que `validateUserOp` réussit, les frais sont engagés même si l'exécution revert ensuite. Des attaquants peuvent soumettre à répétition des ops qui échoueront et tout de même prélever des frais sur le compte.

Pour les paymasters, payer depuis un pool partagé dans `validateUserOp` et facturer les utilisateurs dans `postOp` est fragile car `postOp` peut revert sans annuler le paiement. Sécurisez les fonds pendant la validation (escrow/dépôt par utilisateur), et gardez `postOp` minimal et non susceptible de revert.

## 6) ERC-7702 initialisation frontrun
ERC-7702 permet à une EOA d'exécuter du code smart-account pour une seule tx. Si l'initialisation est appelable depuis l'extérieur, un frontrunner peut se définir comme owner.

Atténuation : autoriser l'initialisation uniquement lors d'un **self-call** et une seule fois.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vérifications rapides avant la fusion
- Valider les signatures en utilisant le `userOpHash` de `EntryPoint` (associe les champs de gas).
- Restreindre les fonctions privilégiées à `EntryPoint` et/ou `address(this)` selon le cas.
- Garder `validateUserOp` sans état.
- Appliquer la séparation de domaine EIP-712 pour ERC-1271 et renvoyer `0x1626ba7e` en cas de succès.
- Maintenir `postOp` minimal, borné et qui ne revert pas ; sécuriser les frais pendant la validation.
- Pour ERC-7702, autoriser init uniquement lors d'un self-call et une seule fois.

## Références

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
