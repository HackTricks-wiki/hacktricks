# ERC-4337 Armadilhas de segurança de Smart Accounts

{{#include ../../banners/hacktricks-training.md}}

A abstração de conta do ERC-4337 transforma wallets em sistemas programáveis. O fluxo principal é **validate-then-execute** em todo o pacote: o `EntryPoint` valida cada `UserOperation` antes de executar qualquer uma delas. Essa ordenação cria uma superfície de ataque não óbvia quando a validação é permissiva ou com estado.

## 1) Bypass por chamada direta de funções privilegiadas
Qualquer função `execute` (ou que mova fundos) chamável externamente que não esteja restrita ao `EntryPoint` (ou a um módulo executor verificado) pode ser chamada diretamente para drenar a conta.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Padrão seguro: restrinja a `EntryPoint` e use `msg.sender == address(this)` para fluxos de administração/auto-gerenciamento (instalação de módulos, mudanças de validador, atualizações).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas não assinados ou não verificados -> drenagem de taxas
Se a validação de assinatura cobrir apenas a intenção (`callData`) mas não os campos relacionados ao gas, um bundler ou frontrunner pode inflar as taxas e drenar ETH. O payload assinado deve vincular pelo menos:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Padrão defensivo: use o `userOpHash` fornecido pelo `EntryPoint` (que inclui os campos de gas) e/ou limite estritamente cada campo.
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
Because all validations run before any execution, storing validation results in contract state is unsafe. Another op in the same bundle can overwrite it, causing your execution to use attacker-influenced state.

Avoid writing storage in `validateUserOp`. If unavoidable, key temporary data by `userOpHash` and delete it deterministically after use (prefer stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` must bind signatures to **this contract** and **this chain**. Recovering over a raw hash lets signatures replay across accounts or chains.

Use EIP-712 typed data (domain includes `verifyingContract` and `chainId`) and return the exact ERC-1271 magic value `0x1626ba7e` on success.

## 5) Reverts do not refund after validation
Once `validateUserOp` succeeds, fees are committed even if execution later reverts. Attackers can repeatedly submit ops that will fail and still collect fees from the account.

For paymasters, paying from a shared pool in `validateUserOp` and charging users in `postOp` is fragile because `postOp` can revert without undoing the payment. Secure funds during validation (per-user escrow/deposit), and keep `postOp` minimal and non-reverting.

## 6) ERC-7702 initialization frontrun
ERC-7702 lets an EOA run smart-account code for a single tx. If initialization is externally callable, a frontrunner can set themselves as owner.

Mitigation: allow initialization only on **self-call** and only once.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Verificações rápidas pré-merge
- Valide assinaturas usando o `userOpHash` do `EntryPoint` (vincula campos de gas).
- Restrinja funções privilegiadas a `EntryPoint` e/ou `address(this)`, conforme apropriado.
- Mantenha `validateUserOp` sem estado.
- Implemente separação de domínio EIP-712 para ERC-1271 e retorne `0x1626ba7e` em caso de sucesso.
- Mantenha `postOp` mínimo, limitado e sem reverter; assegure as taxas durante a validação.
- Para ERC-7702, permita `init` apenas em self-call e apenas uma vez.

## Referências

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
