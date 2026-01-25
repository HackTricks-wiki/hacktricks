# Comprometimento do Fluxo de Assinatura Web3 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Uma cold-wallet theft chain combinou a **supply-chain compromise of the Safe{Wallet} web UI** com uma **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Os pontos principais são:

- Se uma dApp puder injetar código no caminho de assinatura, ela pode fazer com que um signer produza uma **EIP-712 signature over attacker-chosen fields** enquanto restaura os dados originais da UI para que outros signers permaneçam desavisados.
- Safe proxies store `masterCopy` (implementation) at **storage slot 0**. A delegatecall para um contrato que escreve no slot 0 efetivamente “upgrades” o Safe para a lógica do attacker, dando controle total da wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

A tampered Safe bundle (`_app-*.js`) atacou seletivamente endereços específicos de Safe + signer. A lógica injetada foi executada logo antes da chamada de assinatura:
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
### Attack properties
- **Context-gated**: hard-coded allowlists para os Safes/signers das vítimas impediram ruído e reduziram a detecção.
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) foram sobrescritos imediatamente antes de `signTransaction`, então revertidos, de modo que os payloads de proposta na UI pareciam benignos enquanto as signatures correspondiam ao payload do atacante.
- **EIP-712 opacity**: wallets exibiam structured data mas não decodificavam nested calldata nem ressaltavam `operation = delegatecall`, fazendo com que a mensagem mutada fosse efetivamente assinada às cegas.

### Gateway validation relevance
Propostas Safe são submetidas ao **Safe Client Gateway**. Antes das verificações reforçadas, o gateway podia aceitar uma proposta onde `safeTxHash`/signature correspondiam a campos diferentes do corpo JSON se a UI os regravasse pós-signing. Após o incidente, o gateway agora rejeita propostas cujo hash/signature não correspondem à transação submetida. Verificação similar de hash no lado servidor deve ser aplicada em qualquer signing-orchestration API.

### 2025 Bybit/Safe incident highlights
- O drain da cold-wallet da Bybit em 21 de fevereiro de 2025 (~401k ETH) reutilizou o mesmo padrão: um bundle Safe S3 comprometido disparava apenas para os signers da Bybit e trocava `operation=0` → `1`, apontando `to` para um contrato atacante pré-deployado que escreve o slot 0.
- `_app-52c9031bfa03da47.js` cacheado no Wayback mostra a lógica condicionada ao Safe da Bybit (`0x1db9…cf4`) e aos endereços dos signers, então foi imediatamente revertido para um bundle limpo dois minutos após a execução, espelhando o truque “mutate → sign → restore”.
- O contrato malicioso (ex.: `0x9622…c7242`) continha funções simples `sweepETH/sweepERC20` além de um `transfer(address,uint256)` que escreve o implementation slot. A execução de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` mudou a implementação do proxy e concedeu controle total.

## On-chain: Delegatecall proxy takeover via slot collision

Os proxies Safe mantêm `masterCopy` no **storage slot 0** e delegam toda a lógica a ele. Como o Safe suporta **`operation = 1` (delegatecall)**, qualquer transação assinada pode apontar para um contrato arbitrário e executar seu código no contexto de storage do proxy.

Um contrato atacante imitava um `transfer(address,uint256)` de ERC-20 mas, em vez disso, escreveu `_to` no slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Caminho de execução:
1. As vítimas assinam `execTransaction` com `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. O Safe `masterCopy` valida as assinaturas sobre esses parâmetros.
3. O proxy realiza `delegatecall` para `attackerContract`; o corpo de `transfer` escreve no slot 0.
4. O slot 0 (`masterCopy`) agora aponta para lógica controlada pelo atacante → **tomada completa da carteira e drenagem dos fundos**.

### Notas sobre Guard & versão (endurecimento pós-incidente)
- Safes >= v1.3.0 podem instalar um **Guard** para vetar `delegatecall` ou aplicar ACLs em `to`/selectors; Bybit rodava v1.1.1, então não existia hook de Guard. Atualizar contratos (e readicionar owners) é necessário para obter esse plano de controle.

## Checklist de detecção e endurecimento

- **Integridade da UI**: fixar JS assets / SRI; monitorar diffs do bundle; tratar a UI de assinatura como parte do limite de confiança.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; renderizar explicitamente `operation` e decodificar calldata aninhada. Rejeitar assinatura quando `operation = 1` a menos que a política permita.
- **Verificações de hash no servidor**: gateways/serviços que retransmitem propostas devem recomputar `safeTxHash` e validar que as assinaturas correspondem aos campos submetidos.
- **Política/listas permitidas**: regras preflight para `to`, selectors, tipos de ativos, e bloquear `delegatecall` exceto para fluxos validados. Exigir um serviço de política interno antes de broadcastar transações totalmente assinadas.
- **Design de contratos**: evitar expor `delegatecall` arbitrário em multisig/treasury wallets a menos que estritamente necessário. Colocar ponteiros de upgrade longe do slot 0 ou proteger com lógica de upgrade explícita e controle de acesso.
- **Monitoramento**: alertar sobre execuções de `delegatecall` de wallets que detêm fundos da tesouraria, e sobre propostas que alteram `operation` de padrões típicos de `call`.

## Referências

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
