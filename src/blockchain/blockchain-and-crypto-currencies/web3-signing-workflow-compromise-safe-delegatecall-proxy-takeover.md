# Comprometimento do Fluxo de Assinatura Web3 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

Uma cadeia de roubo de cold-wallet combinou um **comprometimento da supply-chain da UI web do Safe{Wallet}** com um **primitive on-chain delegatecall que sobrescreveu o ponteiro de implementação do proxy (slot 0)**. As principais conclusões são:

- Se uma dApp pode injetar código no caminho de assinatura, ela pode fazer com que um signer produza uma **EIP-712 signature válida sobre campos escolhidos pelo atacante** enquanto restaura os dados originais da UI para que outros signers permaneçam alheios.
- Safe proxies armazenam `masterCopy` (implementation) em **storage slot 0**. Uma delegatecall para um contrato que escreve no slot 0 efetivamente “atualiza” o Safe para a lógica do atacante, concedendo controle total da wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Um bundle Safe adulterado (`_app-*.js`) atacou seletivamente endereços específicos de Safe + signer. A lógica injetada era executada imediatamente antes da chamada de assinatura:
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Propriedades do ataque
- **Context-gated**: allowlists hard-coded para victim Safes/signers reduziram o ruído e diminuíram a detecção.
- **Last-moment mutation**: campos (`to`, `data`, `operation`, gas) foram sobrescritos imediatamente antes de `signTransaction`, então revertidos, de modo que os payloads de proposta na UI pareciam benignos enquanto as assinaturas correspondiam ao payload do atacante.
- **EIP-712 opacity**: wallets exibiam dados estruturados mas não decodificavam nested calldata nem destacavam `operation = delegatecall`, fazendo com que a mensagem mutada fosse assinada às cegas.

### Relevância da validação do Gateway
Propostas do Safe são submetidas ao **Safe Client Gateway**. Antes das checagens reforçadas, o gateway podia aceitar uma proposta onde `safeTxHash`/assinatura correspondiam a campos diferentes do corpo JSON se a UI os reescrevesse após a assinatura. Após o incidente, o gateway agora rejeita propostas cujo hash/assinatura não correspondam à transação submetida. Verificação de hash similar no servidor deve ser aplicada em qualquer API de signing-orchestration.

## On-chain: Tomada de proxy por delegatecall via colisão de slot

Os proxies Safe mantêm `masterCopy` em **storage slot 0** e delegam toda a lógica a ele. Como o Safe suporta **`operation = 1` (delegatecall)**, qualquer transação assinada pode apontar para um contrato arbitrário e executar seu código no contexto de storage do proxy.

Um contrato atacante imitou um ERC-20 `transfer(address,uint256)` mas em vez disso escreveu `_to` no slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **tomada total da carteira e drenagem dos fundos**.

## Detecção & checklist de hardening

- **Integridade da UI**: fixar JS assets / SRI; monitorar bundle diffs; tratar a UI de assinatura como parte do limite de confiança.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; renderizar explicitamente `operation` e decodificar calldata aninhado. Rejeitar a assinatura quando `operation = 1` a menos que a política permita.
- **Verificações de hash no servidor**: gateways/services que retransmitem propostas devem recomputar `safeTxHash` e validar que as assinaturas correspondem aos campos submetidos.
- **Política/allowlists**: regras de preflight para `to`, selectors, tipos de asset, e proibir delegatecall exceto para fluxos verificados. Exigir um serviço de política interno antes de broadcast de transações totalmente assinadas.
- **Design de contrato**: evitar expor delegatecall arbitrário em carteiras multisig/treasury a menos que estritamente necessário. Colocar pointers de upgrade longe do slot 0 ou proteger com lógica explícita de upgrade e controle de acesso.
- **Monitoramento**: alertar sobre execuções de delegatecall de carteiras que detêm fundos da tesouraria, e sobre propostas que mudam `operation` de padrões típicos `call`.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
