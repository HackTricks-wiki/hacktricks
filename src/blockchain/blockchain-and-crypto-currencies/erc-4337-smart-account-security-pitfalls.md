# Armadilhas de Segurança de Smart Accounts ERC-4337

{{#include ../../banners/hacktricks-training.md}}

A account abstraction do ERC-4337 transforma wallets em sistemas programáveis. O fluxo principal é **validate-then-execute** em todo o bundle: o `EntryPoint` valida cada `UserOperation` antes de executar qualquer uma delas.<sup>[[5]](#references)</sup> Essa ordem cria uma attack surface não óbvia quando a validação é permissiva, stateful ou inconsistente com as regras de simulação do bundler.

## 1) Bypass por chamada direta de funções privilegiadas
Qualquer função `execute` (ou função que mova fundos) acessível externamente e que não seja restrita ao `EntryPoint` (ou a um módulo executor validado) pode ser chamada diretamente para drenar a conta.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Padrão seguro: restrinja a `EntryPoint` e use `msg.sender == address(this)` para fluxos de administração/autogerenciamento (instalação de módulos, alterações de validadores e upgrades).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas não assinados ou não verificados -> drain de taxas
Se a validação da assinatura cobrir apenas a intenção (`callData`), mas não os campos relacionados a gas, um bundler ou frontrunner poderá inflar as taxas e drenar ETH. O payload assinado deve vincular pelo menos:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Padrão defensivo: use o `userOpHash` fornecido pelo `EntryPoint` (que inclui os campos de gas) e/ou limite estritamente cada campo.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering de validação com estado (semântica do bundle)
Como todas as validações são executadas antes de qualquer execução, armazenar resultados de validação no estado do contrato é inseguro. Outra op no mesmo bundle pode sobrescrevê-los, fazendo com que sua execução use um estado influenciado pelo atacante.<sup>[[2]](#references)</sup>

Evite escrever no storage em `validateUserOp`. Se for inevitável, associe os dados temporários a `userOpHash` e exclua-os deterministicamente após o uso (prefira validação stateless).<sup>[[2]](#references)</sup>

## 4) Replay de ERC-1271 entre contas/chains (ausência de separação de domínio)
`isValidSignature(bytes32 hash, bytes sig)` deve vincular as assinaturas a **este contrato** e a **esta chain**. Fazer a recuperação usando um hash bruto permite que as assinaturas sofram replay entre contas ou chains.<sup>[[1]](#references)[[4]](#references)</sup>

Use typed data de EIP-712 (o domínio inclui `verifyingContract` e `chainId`) e retorne o valor mágico exato do ERC-1271, `0x1626ba7e`, em caso de sucesso.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts não reembolsam após a validação
Depois que `validateUserOp` é concluído com sucesso, as taxas são comprometidas mesmo que a execução sofra um revert posteriormente. Atacantes podem enviar repetidamente ops que falharão e ainda assim cobrar taxas da conta.<sup>[[2]](#references)</sup>

Para paymasters, pagar a partir de um pool compartilhado em `validateUserOp` e cobrar os usuários em `postOp` é frágil, pois `postOp` pode sofrer um revert sem desfazer o pagamento. Proteja os fundos durante a validação (escrow/deposit por usuário), mantenha `postOp` minimalista e sem possibilidade de revert, e reserve `paymasterPostOpGasLimit` para o caminho de reembolso no pior caso.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Deploy contrafactual / suposições sobre a factory
A primeira `UserOperation` geralmente contém `initCode`, o que faz com que a conta seja deployada por meio de uma **factory** durante a validação. Esse caminho é fácil de auditar de forma insuficiente porque só é executado no primeiro uso.<sup>[[5]](#references)</sup>

Falhas comuns incluem:<sup>[[5]](#references)</sup>

- A factory/initializer confia em `msg.sender == entryPoint`, mas o caminho de deploy do ERC-4337 **não** chama `initCode` diretamente a partir do `EntryPoint`.
- O salt, owner, validator ou a configuração do module não está totalmente vinculado à intenção assinada, permitindo que um frontrunner dispute o primeiro deploy e ocupe o endereço contrafactual com configurações controladas pelo atacante.
- A factory não é idempotente, então um fluxo repetido de primeiro uso inutiliza a wallet em vez de retornar o endereço já criado.

Padrão seguro: recalcule o sender esperado a partir dos parâmetros de deploy assinados, torne o deploy determinístico (normalmente usando `CREATE2`) e faça com que a inicialização ocorra uma única vez.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validação que os bundlers rejeitam
O código de validação pode estar correto em testes locais e ainda ser inutilizável em bundlers reais. Os bundlers executam a validação várias vezes e devem realizar uma validação rastreada do pacote completo antes do envio.<sup>[[6]](#references)</sup>

De acordo com essas regras de escopo de validação, estes padrões são perigosos:<sup>[[6]](#references)</sup>

- Opcodes dependentes do bloco, como `TIMESTAMP`, `NUMBER` ou `BLOCKHASH`
- Acesso ao armazenamento fora do escopo permitido da conta/entidade ou iteração sem limites sobre o armazenamento
- Chamadas externas ou leituras de oráculos que dependem de estado mutável fora do escopo de validação permitido

Exemplo ruim:
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
Trate a validação como uma função determinística e limitada de preflight. Se forem necessários estado compartilhado ou consultas externas, siga as regras para entidades com stake e teste o mesmo caminho de simulação multi-pass do bundler, não apenas testes unitários.<sup>[[6]](#references)</sup>

## 8) Frontrun de inicialização do ERC-7702
O ERC-7702 fornece a uma EOA uma delegação persistente para código de smart-account; a delegação não executa a inicialização atomicamente. Se a inicialização puder ser chamada externamente, um observador poderá fazer frontrun e definir a si mesmo como proprietário.<sup>[[7]](#references)</sup>

Mitigação: exija que os dados de inicialização sejam autorizados pela EOA e permita a inicialização apenas uma vez. Em um fluxo ERC-4337 EIP-7702, também restrinja o chamador a `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Verificações rápidas pré-merge
- Valide as assinaturas usando o `userOpHash` do `EntryPoint` (vincula os campos de gas).
- Restrinja as funções privilegiadas a `EntryPoint` e/ou `address(this)`, conforme apropriado.
- Mantenha `validateUserOp` stateless, determinístico e compatível com as regras de simulação do bundler.
- Imponha a separação de domínio do EIP-712 para ERC-1271 e retorne `0x1626ba7e` em caso de sucesso.
- Mantenha `postOp` mínimo, limitado e sem possibilidade de revert; proteja as fees durante a validação.
- Teste separadamente o primeiro caminho de `initCode`: deployment determinístico, comportamento idempotente da factory e inicialização de uso único.
- Execute a validação em múltiplas passagens do bundler e uma verificação rastreada do bundle completo antes do lançamento.
- Para ERC-7702, vincule a inicialização à autorização da EOA e permita-a apenas uma vez; nos fluxos ERC-4337, restrinja o caller a `EntryPoint.senderCreator()`.

## References

- [1] [Replay de ERC1271 - Mais de 15 equipes afetadas (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Seis erros em smart accounts ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Método padrão de validação de assinaturas para contratos](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing e assinatura de dados estruturados tipados](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Abstração de contas usando Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Regras de escopo de validação da abstração de contas](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Definição de código para EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
