# Armadilhas de segurança de Smart Accounts ERC-4337

{{#include ../../banners/hacktricks-training.md}}

A abstração de contas do ERC-4337 transforma wallets em sistemas programáveis. O fluxo central é **validate-then-execute** em todo o bundle: o `EntryPoint` valida cada `UserOperation` antes de executar qualquer uma delas. Essa ordem cria uma superfície de ataque não óbvia quando a validação é permissiva, stateful ou inconsistente com as regras de simulação do bundler.

## 1) Bypass por chamada direta de funções privilegiadas
Qualquer função `execute` (ou de movimentação de fundos) que possa ser chamada externamente e não esteja restrita ao `EntryPoint` (ou a um módulo executor validado) pode ser chamada diretamente para esvaziar a conta.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Padrão seguro: restrinja a `EntryPoint` e use `msg.sender == address(this)` para fluxos de administração/autogerenciamento (instalação de módulos, alterações de validadores e upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas não assinados ou não verificados -> drenagem de taxas
Se a validação da assinatura cobrir apenas a intenção (`callData`), mas não os campos relacionados a gas, um bundler ou frontrunner poderá inflar as taxas e drenar ETH. O payload assinado deve vincular pelo menos:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Padrão defensivo: use o `userOpHash` fornecido pelo `EntryPoint` (que inclui os campos de gas) e/ou estabeleça limites rígidos para cada campo.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering da validação stateful (semântica do bundle)
Como todas as validações são executadas antes de qualquer execução, armazenar resultados de validação no estado do contrato é inseguro. Outra op no mesmo bundle pode sobrescrevê-los, fazendo com que sua execução use um estado influenciado pelo atacante.<sup>[[1]](#references)</sup>

Evite gravar no storage em `validateUserOp`. Se for inevitável, identifique os dados temporários por `userOpHash` e exclua-os deterministicamente após o uso (prefira a validação stateless).<sup>[[1]](#references)</sup>

## 4) Replay de ERC-1271 entre contas/chains (ausência de domain separation)
`isValidSignature(bytes32 hash, bytes sig)` deve vincular as assinaturas a **este contrato** e a **esta chain**. Fazer a recuperação usando um hash bruto permite que as assinaturas sejam reutilizadas em outras contas ou chains.<sup>[[1]](#references)</sup>

Use dados tipados EIP-712 (o domínio inclui `verifyingContract` e `chainId`) e retorne o valor mágico exato do ERC-1271, `0x1626ba7e`, em caso de sucesso.<sup>[[1]](#references)</sup>

## 5) Reverts não reembolsam após a validação
Após `validateUserOp` ser concluído com sucesso, as taxas ficam comprometidas mesmo que a execução sofra revert posteriormente. Atacantes podem enviar repetidamente ops que falharão e ainda assim cobrar taxas da conta.<sup>[[1]](#references)</sup>

Para paymasters, pagar a partir de um pool compartilhado em `validateUserOp` e cobrar os usuários em `postOp` é frágil, pois `postOp` pode sofrer revert sem desfazer o pagamento. Proteja os fundos durante a validação (escrow/deposit por usuário), mantenha `postOp` mínimo e sem possibilidade de revert, e reserve `paymasterPostOpGasLimit` para o caminho de reembolso no pior caso.<sup>[[1]](#references)</sup>

## 6) Deploy contrafactual / suposições da factory
A primeira `UserOperation` geralmente carrega `initCode`, o que faz com que a conta seja deployed por meio de uma **factory** durante a validação. Esse caminho é fácil de auditar de forma insuficiente porque só é executado no primeiro uso.<sup>[[2]](#references)</sup>

Falhas comuns:

- A factory/initializer confia em `msg.sender == entryPoint`, mas o caminho de deploy do ERC-4337 **não** chama `initCode` diretamente a partir do `EntryPoint`.
- O salt, owner, validator ou a configuração do módulo não estão totalmente vinculados à intenção assinada, permitindo que um frontrunner dispute o primeiro deploy e ocupe o endereço contrafactual com configurações controladas pelo atacante.
- A factory não é idempotente, portanto um fluxo repetido de primeiro uso inutiliza a wallet em vez de retornar o endereço já criado.

Padrão seguro: recalcule o sender esperado a partir dos parâmetros de deploy assinados, torne o deploy determinístico (normalmente usando `CREATE2`) e faça com que a inicialização ocorra apenas uma vez.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validação que os bundlers rejeitam
O código de validação pode estar correto nos testes locais e ainda assim ser inutilizável em bundlers reais. Os bundlers públicos simulam `validateUserOp()` / `validatePaymasterUserOp()` off-chain e normalmente executam um `debug_traceCall(handleOps)` completo antes da inclusão.<sup>[[3]](#references)</sup>

Isso torna estes padrões perigosos dentro da validação:

- Opcodes dependentes do bloco, como `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
- Escritas de estado, como `SSTORE`
- Iteração sem limite sobre o storage
- Chamadas externas arbitrárias ou leituras de oracles que podem mudar entre a simulação e a inclusão

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
Trate a validação como uma função determinística e limitada de preflight. Se você realmente precisar de estado compartilhado ou de consultas externas, transfira essa complexidade para entidades com stake/rastreio de reputação e teste o caminho exato de simulação do bundler, não apenas testes unitários.

## 8) ERC-7702 initialization frontrun
O ERC-7702 permite que uma EOA execute código de smart account durante uma única tx. Se a inicialização puder ser chamada externamente, um frontrunner poderá definir a si mesmo como owner.<sup>[[1]](#references)</sup>

Mitigação: permita a inicialização somente em **self-call** e apenas uma vez.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Verificações rápidas pré-merge
- Valide assinaturas usando o `userOpHash` do `EntryPoint` (vincula os campos de gas).
- Restrinja funções privilegiadas ao `EntryPoint` e/ou a `address(this)`, conforme apropriado.
- Mantenha `validateUserOp` sem estado, determinístico e compatível com as regras de simulação do bundler.
- Imponha a separação de domínio EIP-712 para ERC-1271 e retorne `0x1626ba7e` em caso de sucesso.
- Mantenha `postOp` mínimo, limitado e sem possibilidade de reverter; proteja as taxas durante a validação.
- Teste separadamente o primeiro fluxo de `initCode`: deployment determinístico, comportamento idempotente da factory e inicialização de uso único.
- Execute a simulação completa do bundler (`simulateValidation` mais um `handleOps` rastreado) antes do lançamento.
- Para ERC-7702, permita a inicialização apenas em self-call e somente uma vez.

## Referências

- [1] [Seis erros em smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Abstração de Contas Usando Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Regras de Escopo de Validação de Abstração de Contas](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
