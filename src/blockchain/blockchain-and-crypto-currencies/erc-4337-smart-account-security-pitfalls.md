# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

A abstração de conta ERC-4337 transforma wallets em sistemas programáveis. O fluxo central é **validate-then-execute** em um bundle inteiro: o `EntryPoint` valida cada `UserOperation` antes de executar qualquer uma delas. Essa ordem cria uma superfície de ataque não óbvia quando a validação é permissiva, stateful, ou inconsistente com as regras de simulação do bundler.

## 1) Direct-call bypass de funções privilegiadas
Qualquer função `execute` chamável externamente (ou de movimentação de fundos) que não seja restrita ao `EntryPoint` (ou a um módulo executor validado) pode ser chamada diretamente para drenar a conta.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Padrão seguro: restrinja a `EntryPoint`, e use `msg.sender == address(this)` para fluxos de administração/autogerenciamento (instalação de módulo, mudanças de validador, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas não assinados ou não verificados -> fee drain
Se a validação da assinatura cobre apenas a intenção (`callData`), mas não os campos relacionados a gas, um bundler ou frontrunner pode inflar as taxas e drenar ETH. O payload assinado deve vincular no mínimo:

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
Como todas as validações rodam antes de qualquer execução, armazenar resultados de validação no estado do contrato é inseguro. Outra op no mesmo bundle pode sobrescrevê-los, fazendo sua execução usar estado influenciado pelo atacante.

Evite escrever storage em `validateUserOp`. Se for inevitável, use a chave dos dados temporários por `userOpHash` e apague-os deterministically após o uso (prefira validação stateless).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` deve vincular signatures a **este contract** e **esta chain**. Fazer recovery sobre um hash bruto permite replay de signatures entre accounts ou chains.

Use EIP-712 typed data (o domain inclui `verifyingContract` e `chainId`) e retorne o valor mágico exato de ERC-1271 `0x1626ba7e` em caso de sucesso.

## 5) Reverts do not refund after validation
Uma vez que `validateUserOp` tem sucesso, as fees ficam comprometidas mesmo que a execução depois reverta. Attackers podem submeter repetidamente ops que vão falhar e ainda assim coletar fees da account.

Para paymasters, pagar de um shared pool em `validateUserOp` e cobrar usuários em `postOp` é frágil porque `postOp` pode reverter sem desfazer o pagamento. Trave os fundos durante a validação (per-user escrow/deposit), mantenha `postOp` mínimo e non-reverting, e reserve `paymasterPostOpGasLimit` para o pior caminho de reimbursement.

## 6) Counterfactual deployment / factory assumptions
A primeira `UserOperation` frequentemente carrega `initCode`, o que faz com que a account seja deployed por uma **factory** durante a validação. Esse path é fácil de sub-auditar porque só roda no primeiro uso.

Falhas comuns:

- A factory/initializer confia em `msg.sender == entryPoint`, mas o path de deployment do ERC-4337 não chama `initCode` diretamente de `EntryPoint`.
- O salt, owner, validator, ou configuração de module não está totalmente vinculada à intenção assinada, então um frontrunner pode disputar o primeiro deployment e queimar o endereço counterfactual com settings controlados pelo attacker.
- A factory não é idempotent, então um fluxo repetido de primeiro uso bricka a wallet em vez de retornar o endereço já criado.

Padrão safe: recalcule o sender esperado a partir dos parâmetros de deployment assinados, torne o deployment deterministic (normalmente `CREATE2`), e faça a initialization ser one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validação que bundlers rejeitam
O código de validação pode estar correto em testes locais e ainda assim ser inutilizável em bundlers reais. Bundlers públicos simulam `validateUserOp()` / `validatePaymasterUserOp()` off-chain e, comumente, executam um `debug_traceCall(handleOps)` completo antes da inclusão.

Isso torna estes padrões perigosos dentro da validação:

- Opcodes dependentes de bloco, como `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
- Escritas de estado, como `SSTORE`
- Iteração sem limite sobre storage
- Chamadas externas arbitrárias ou leituras de oracle que podem mudar entre a simulação e a inclusão

Exemplo ruim:
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
Trate a validação como uma função preflight determinística e limitada. Se você realmente precisar de estado compartilhado ou consultas externas, empurre essa complexidade para entidades com stake/reputation tracked e teste o caminho exato da simulação do bundler, não apenas unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 permite que uma EOA execute código de smart-account para uma única tx. Se a inicialização for chamável externamente, um frontrunner pode se definir como owner.

Mitigação: permita a inicialização apenas em **self-call** e apenas uma vez.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Verificações rápidas antes do merge
- Valide assinaturas usando `EntryPoint`'s `userOpHash` (vincula campos de gas).
- Restrinja funções privilegiadas a `EntryPoint` e/ou `address(this)` conforme apropriado.
- Mantenha `validateUserOp` stateless, deterministic, and compatible with bundler simulation rules.
- Aplique EIP-712 domain separation para ERC-1271 e retorne `0x1626ba7e` em caso de sucesso.
- Mantenha `postOp` minimal, bounded, and non-reverting; proteja fees during validation.
- Teste separadamente o primeiro caminho `initCode`: deployment determinístico, comportamento idempotente da factory e inicialização one-shot.
- Execute a simulação completa do bundler (`simulateValidation` mais um `handleOps` com trace) antes de publicar.
- Para ERC-7702, permita init apenas em self-call e apenas uma vez.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
