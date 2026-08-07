# Comprometimento do fluxo de assinatura do Web3 e takeover de proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Uma cadeia de roubo de cold wallet combinou um **comprometimento de supply chain da web UI do Safe{Wallet}** com uma **primitive de delegatecall on-chain que sobrescreveu o ponteiro de implementação de um proxy (slot 0)**. Os principais pontos são:

- Se uma dApp puder injetar código no signing path, ela poderá fazer com que um signer produza uma **assinatura EIP-712 válida sobre campos escolhidos pelo atacante**<sup>[[4]](#references)</sup>, enquanto restaura os dados originais da UI para que os outros signers não percebam.
- Os proxies do Safe armazenam `masterCopy` (implementation) no **storage slot 0**. Um delegatecall para um contract que escreve no slot 0 efetivamente faz “upgrade” do Safe para a lógica do atacante, concedendo controle total da wallet.

## Off-chain: mutação direcionada de signing no Safe{Wallet}

Um bundle do Safe adulterado (`_app-*.js`) atacava seletivamente endereços específicos de Safe + signer. A lógica injetada era executada imediatamente antes da chamada de assinatura:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: allowlists codificadas para as Safes/signers vítimas impediram ruído e reduziram a detecção.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: os campos (`to`, `data`, `operation`, gas) foram sobrescritos imediatamente antes de `signTransaction` e depois revertidos, fazendo com que os payloads das propostas na UI parecessem benignos, enquanto as assinaturas correspondiam ao payload do atacante.
- **EIP-712 opacity**: as wallets exibiam dados estruturados, mas não decodificavam calldata aninhada nem destacavam `operation = delegatecall`, fazendo com que a mensagem mutada fosse efetivamente assinada às cegas.

### Relevância da validação do Gateway
As propostas de Safe são enviadas ao **Safe Client Gateway**.<sup>[[5]](#references)</sup> Antes da implementação de checks reforçados, o gateway podia aceitar uma proposta na qual `safeTxHash`/assinatura correspondessem a campos diferentes dos presentes no corpo JSON, caso a UI os reescrevesse após a assinatura. Após o incidente, o gateway passou a rejeitar propostas cujo hash/assinatura não correspondessem à transação enviada. Uma verificação de hash semelhante no lado do servidor deve ser aplicada a qualquer API de orquestração de signing.

### Destaques do incidente Bybit/Safe de 2025
- O drain da cold-wallet da Bybit em 21 de fevereiro de 2025 (~401k ETH) reutilizou o mesmo padrão: um bundle S3 comprometido da Safe era acionado apenas para signers da Bybit e trocava `operation=0` → `1`, apontando `to` para um contrato do atacante pré-deployed que escrevia no slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- O `_app-52c9031bfa03da47.js` armazenado em cache pelo Wayback mostra a lógica vinculada à Safe da Bybit (`0x1db9…cf4`) e aos endereços dos signers, sendo imediatamente revertida para um bundle limpo dois minutos após a execução, reproduzindo o truque “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- O contrato malicioso (por exemplo, `0x9622…c7242`) continha funções simples `sweepETH/sweepERC20` e uma `transfer(address,uint256)` que escrevia no implementation slot. A execução de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` alterava a implementação do proxy e concedia controle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: takeover de proxy via delegatecall por colisão de slots

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
2. O Safe masterCopy valida as assinaturas sobre esses parâmetros.
3. O proxy executa um delegatecall em `attackerContract`; o corpo de `transfer` grava no slot 0.
4. O slot 0 (`masterCopy`) agora aponta para uma lógica controlada pelo atacante → **tomada total da wallet e drenagem dos fundos**.

### Observações sobre Guard e versões (hardening pós-incidente)
- Safes >= v1.3.0 podem instalar um **Guard** para vetar `delegatecall` ou aplicar ACLs a `to`/selectors; a Bybit usava a v1.1.1, portanto não existia nenhum hook de Guard. É necessário fazer upgrade dos contratos (e adicionar novamente os owners) para obter esse control plane.

## Checklist de detecção e hardening

- **Integridade da UI**: fixar assets JS / SRI; monitorar diferenças no bundle; tratar a signing UI como parte da trust boundary.
- **Validação no momento da assinatura**: hardware wallets com **EIP-712 clear-signing**; renderizar explicitamente `operation` e decodificar a calldata aninhada. Rejeitar a assinatura quando `operation = 1`, a menos que a policy permita.
- **Verificações de hash no servidor**: gateways/services que retransmitem propostas devem recalcular `safeTxHash` e validar se as assinaturas correspondem aos campos enviados.
- **Policy/allowlists**: regras de preflight para `to`, selectors e tipos de assets, além de bloquear delegatecall, exceto em flows avaliados. Exigir um policy service interno antes de fazer o broadcast de transações totalmente assinadas.
- **Design de contratos**: evitar expor delegatecall arbitrário em wallets multisig/treasury, a menos que seja estritamente necessário. Colocar os ponteiros de upgrade longe do slot 0 ou protegê-los com lógica explícita de upgrade e controle de acesso.
- **Monitoramento**: gerar alertas para execuções de delegatecall provenientes de wallets que mantêm fundos de treasury e para propostas que alterem `operation` em relação aos padrões usuais de `call`.

## Referências

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
