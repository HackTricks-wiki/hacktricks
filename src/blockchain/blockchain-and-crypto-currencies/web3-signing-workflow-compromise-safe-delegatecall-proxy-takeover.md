# Comprometimento do fluxo de assinatura Web3 e takeover de proxy Safe Delegatecall

## Visão geral

Uma cadeia de roubo de cold-wallet combinou um **comprometimento da cadeia de suprimentos da interface web do Safe{Wallet}** com uma **primitive on-chain de delegatecall que sobrescreveu o ponteiro de implementação de um proxy (slot 0)**. As principais conclusões são:

- Se uma dApp puder injetar código no caminho de assinatura, ela poderá fazer com que um signer produza uma **assinatura EIP-712 válida sobre campos escolhidos pelo atacante**, restaurando os dados originais da UI para que os outros signers permaneçam sem conhecimento do ataque.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Proxies do Safe armazenam `masterCopy` (implementação) no **storage slot 0**. Um delegatecall para um contrato que grava no slot 0 efetivamente faz um “upgrade” do Safe para a lógica do atacante, proporcionando controle total da wallet.<sup>[[3]](#references)</sup>

## Off-chain: mutação direcionada de assinatura no Safe{Wallet}

Um bundle adulterado do Safe (`_app-*.js`) atacou seletivamente endereços específicos de Safe + signer. A lógica injetada foi executada imediatamente antes da chamada de assinatura:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: allowlists codificadas para as Safes/signers das vítimas evitaram ruído e reduziram a detecção.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: os campos (`to`, `data`, `operation`, gas) eram sobrescritos imediatamente antes de `signTransaction` e depois revertidos, fazendo com que os payloads das propostas na UI parecessem benignos, enquanto as assinaturas correspondiam ao payload do atacante.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: as wallets exibiam dados estruturados, mas não decodificavam calldata aninhada nem destacavam `operation = delegatecall`, tornando a mensagem alterada efetivamente uma blind-signature.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevância da validação do Gateway
As propostas de Safe são enviadas ao **Safe Client Gateway**.<sup>[[5]](#references)</sup> Antes das verificações reforçadas, o gateway podia aceitar uma proposta em que `safeTxHash`/assinatura correspondessem a campos diferentes dos presentes no corpo JSON, caso a UI os reescrevesse após a assinatura. Depois do incidente, o gateway passou a rejeitar propostas cujo hash/assinatura não corresponda à transação enviada.<sup>[[3]](#references)</sup> Uma verificação de hash semelhante no lado do servidor deve ser aplicada a qualquer API de signing-orchestration.

### Destaques do incidente Bybit/Safe de 2025
- O esvaziamento da cold wallet da Bybit em 21 de fevereiro de 2025 (~401k ETH) reutilizou o mesmo padrão: um bundle S3 comprometido da Safe só era ativado para os signers da Bybit e trocava `operation=0` → `1`, apontando `to` para um contrato do atacante previamente implantado que gravava no slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- O `_app-52c9031bfa03da47.js` armazenado em cache pelo Wayback mostra a lógica baseada na Safe da Bybit (`0x1db9…cf4`) e nos endereços dos signers, revertendo imediatamente para um bundle limpo dois minutos após a execução, reproduzindo o truque “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- O contrato malicioso (por exemplo, `0x9622…c7242`) continha funções simples `sweepETH/sweepERC20` e uma `transfer(address,uint256)` que grava no implementation slot. A execução de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` alterou a implementação do proxy e concedeu controle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: takeover de proxy via delegatecall por colisão de slots

Os proxies da Safe mantêm `masterCopy` no **storage slot 0** e delegam toda a lógica a ele. Como a Safe oferece suporte a **`operation = 1` (delegatecall)**, qualquer transação assinada pode apontar para um contrato arbitrário e executar seu código no contexto de storage do proxy.<sup>[[3]](#references)</sup>

Um contrato do atacante imitava um `transfer(address,uint256)` de ERC-20, mas, em vez disso, gravava `_to` no slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Caminho de execução:<sup>[[1]](#references)[[3]](#references)</sup>
1. As vítimas assinam `execTransaction` com `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. O masterCopy do Safe valida as assinaturas sobre esses parâmetros.
3. O proxy faz delegatecall para `attackerContract`; o corpo de `transfer` grava no slot 0.
4. O slot 0 (`masterCopy`) agora aponta para uma lógica controlada pelo atacante → **tomada completa da carteira e drenagem dos fundos**.

### Observações sobre guard e versão (hardening pós-incidente)
- Os transaction guards foram introduzidos no Safe v1.3.0 e podem inspecionar todos os parâmetros de `execTransaction` antes da execução; um guard pode rejeitar `delegatecall` ou aplicar uma política ao destino e aos dados da calldata. O Bybit usava a v1.1.1, anterior a esse hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Checklist de detecção e hardening

- **Integridade da UI**: fixar assets JS / SRI; monitorar diferenças entre bundles; tratar a signing UI como parte do limite de confiança.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; renderizar explicitamente `operation` e decodificar a calldata aninhada. Rejeitar a assinatura quando `operation = 1`, a menos que a política permita isso.<sup>[[3]](#references)</sup>
- **Verificações de hash no lado do servidor**: gateways/serviços que retransmitem propostas devem recalcular `safeTxHash` e validar se as assinaturas correspondem aos campos enviados.<sup>[[3]](#references)</sup>
- **Políticas/allowlists**: regras de preflight para `to`, selectors, tipos de ativos e proibição de delegatecall, exceto em flows avaliados. Exigir um serviço interno de políticas antes de transmitir transações totalmente assinadas.
- **Design de contratos**: evitar expor delegatecall arbitrário em carteiras multisig/treasury, a menos que seja estritamente necessário. Tratar qualquer ponteiro de implementação como um upgrade primitive: protegê-lo com controle de acesso explícito e aplicar guard aos alvos/selectors de delegatecall; mover o ponteiro para outro slot, por si só, não é uma defesa completa.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoramento**: alertar sobre execuções de delegatecall a partir de carteiras que mantêm fundos de treasury e sobre propostas que alteram `operation` em relação aos padrões usuais de `call`.

## References

- [1] [Análise forense da AnChain.AI sobre o exploit do Bybit Safe](https://www.anchain.ai/blog/bybit)
- [2] [Análise da Zero Hour Technology sobre o comprometimento do bundle do Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Análise técnica aprofundada do hack do Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog da smart account v1.3.0 do Safe (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
